use crate::node::{
    Endpoint, InvalidNodeReason, NodeProtocol, NodeRejection, ProxyNodeDraft,
    UnsupportedCapability, percent,
    uri::{QueryPair, parse_authority_uri, parse_endpoint, scan_query},
    vless::{
        ClientFingerprint, GrpcMode, RealityOptions, RealityPublicKey, RealityShortId,
        VlessSecurityKind, VlessTransport, VlessTransportKind,
        share::{
            build_tls_options, nonempty_owned, parameter_value, parse_alpn, parse_fingerprint,
            parse_grpc_mode, parse_public_key, parse_short_id, parse_transport_kind,
            require_compatible, require_nonempty,
        },
    },
};

use super::{TrojanNode, TrojanPassword, TrojanSecurity};

pub(crate) fn parse(input: &str) -> Result<ProxyNodeDraft, NodeRejection> {
    let uri = parse_authority_uri(input)?;
    let password = parse_password(uri.userinfo)?;
    let endpoint = parse_endpoint(uri.authority)?;
    let parameters = parse_parameters(uri.query)?;
    let (transport, security) = build_components(parameters, &endpoint)?;

    Ok(ProxyNodeDraft {
        endpoint,
        name_input: uri.name_input,
        protocol: NodeProtocol::Trojan(TrojanNode::new(password, transport, security).ok_or(
            NodeRejection::Invalid(InvalidNodeReason::IncompatibleParameter),
        )?),
    })
}

fn parse_password(userinfo: &str) -> Result<TrojanPassword, NodeRejection> {
    let decoded = percent::decode(userinfo)
        .map_err(|()| NodeRejection::Invalid(InvalidNodeReason::PercentEncoding))?;
    TrojanPassword::new(decoded.into_owned())
        .ok_or(NodeRejection::Invalid(InvalidNodeReason::Credential))
}

enum ShortIdParameter {
    Empty,
    Value(RealityShortId),
}

struct Parameters {
    transport: VlessTransportKind,
    security: VlessSecurityKind,
    path: Option<String>,
    host: Option<String>,
    service_name: Option<String>,
    mode: Option<GrpcMode>,
    server_name: Option<String>,
    peer: Option<String>,
    alpn: Option<Vec<String>>,
    fingerprint: Option<ClientFingerprint>,
    public_key: Option<RealityPublicKey>,
    short_id: Option<ShortIdParameter>,
}

impl Default for Parameters {
    fn default() -> Self {
        Self {
            transport: VlessTransportKind::Tcp,
            security: VlessSecurityKind::Tls,
            path: None,
            host: None,
            service_name: None,
            mode: None,
            server_name: None,
            peer: None,
            alpn: None,
            fingerprint: None,
            public_key: None,
            short_id: None,
        }
    }
}

struct ParameterContext {
    transport: Result<VlessTransportKind, NodeRejection>,
    security: Result<VlessSecurityKind, NodeRejection>,
}

impl ParameterContext {
    fn from_pairs(pairs: &[QueryPair<'_>]) -> Self {
        let transport = parameter_value(pairs, "type")
            .map_or(Ok(VlessTransportKind::Tcp), parse_transport_kind);
        let security = parameter_value(pairs, "security")
            .map_or(Ok(VlessSecurityKind::Tls), parse_security_kind);
        Self {
            transport,
            security,
        }
    }

    fn transport_is(&self, expected: VlessTransportKind) -> bool {
        self.transport
            .as_ref()
            .is_ok_and(|actual| *actual == expected)
    }

    fn security_is(&self, expected: VlessSecurityKind) -> bool {
        self.security
            .as_ref()
            .is_ok_and(|actual| *actual == expected)
    }

    fn security_uses_tls(&self) -> bool {
        self.security
            .as_ref()
            .is_ok_and(|security| security.uses_tls())
    }
}

fn parse_parameters(query: Option<&str>) -> Result<Parameters, NodeRejection> {
    let mut parameters = Parameters::default();
    let Some(query) = query else {
        return Ok(parameters);
    };
    let pairs = scan_query(query)?;
    let context = ParameterContext::from_pairs(&pairs);

    for pair in pairs {
        let key = pair.key;
        let value = pair.value;
        match key {
            "type" => parameters.transport = context.transport.clone()?,
            "security" => parameters.security = context.security.clone()?,
            "path" => {
                let value = nonempty_owned(value)?;
                require_compatible(context.transport_is(VlessTransportKind::WebSocket))?;
                parameters.path = Some(value);
            }
            "host" => {
                let value = nonempty_owned(value)?;
                require_compatible(context.transport_is(VlessTransportKind::WebSocket))?;
                parameters.host = Some(value);
            }
            "serviceName" => {
                let value = nonempty_owned(value)?;
                require_compatible(context.transport_is(VlessTransportKind::Grpc))?;
                parameters.service_name = Some(value);
            }
            "mode" => {
                require_nonempty(&value)?;
                let mode = parse_grpc_mode(&value)?;
                require_compatible(context.transport_is(VlessTransportKind::Grpc))?;
                parameters.mode = Some(mode);
            }
            "sni" => {
                let value = nonempty_owned(value)?;
                require_compatible(context.security_uses_tls())?;
                parameters.server_name = Some(value);
            }
            "peer" => {
                let value = nonempty_owned(value)?;
                require_compatible(context.security_uses_tls())?;
                parameters.peer = Some(value);
            }
            "alpn" => {
                require_nonempty(&value)?;
                let alpn = parse_alpn(&value)?;
                require_compatible(context.security_uses_tls())?;
                parameters.alpn = Some(alpn);
            }
            "fp" => {
                require_nonempty(&value)?;
                let fingerprint = parse_fingerprint(&value)?;
                require_compatible(context.security_uses_tls())?;
                parameters.fingerprint = Some(fingerprint);
            }
            "pbk" => {
                require_nonempty(&value)?;
                let public_key = parse_public_key(&value)?;
                require_compatible(context.security_is(VlessSecurityKind::Reality))?;
                parameters.public_key = Some(public_key);
            }
            "sid" => {
                let short_id = if value.is_empty() {
                    ShortIdParameter::Empty
                } else {
                    ShortIdParameter::Value(parse_short_id(&value)?)
                };
                require_compatible(context.security_is(VlessSecurityKind::Reality))?;
                parameters.short_id = Some(short_id);
            }
            "allowInsecure" | "insecure" => parse_insecure_flag(&value)?,
            _ => return Err(unsupported_parameter(key)),
        }
    }

    Ok(parameters)
}

fn parse_insecure_flag(value: &str) -> Result<(), NodeRejection> {
    match value {
        "0" | "false" => Ok(()),
        "1" | "true" => Err(NodeRejection::Unsupported(
            UnsupportedCapability::ProtocolOption,
        )),
        _ => Err(NodeRejection::Invalid(InvalidNodeReason::ParameterValue)),
    }
}

fn parse_security_kind(value: &str) -> Result<VlessSecurityKind, NodeRejection> {
    require_nonempty(value)?;
    match value {
        "tls" => Ok(VlessSecurityKind::Tls),
        "reality" => Ok(VlessSecurityKind::Reality),
        _ => Err(NodeRejection::Unsupported(UnsupportedCapability::Security)),
    }
}

fn unsupported_parameter(key: &str) -> NodeRejection {
    let capability = match key {
        "authority" | "service-name" | "headerType" | "seed" => {
            UnsupportedCapability::TransportOption
        }
        "flow" | "encryption" | "mux" | "ss" | "plugin" | "udp" | "packetEncoding"
        | "packet-encoding" | "ech" | "spx" | "pqv" | "request" | "response" | "ed" | "eh"
        | "echConfig" | "echForceQuery" => UnsupportedCapability::ProtocolOption,
        _ => UnsupportedCapability::UnknownParameter,
    };
    NodeRejection::Unsupported(capability)
}

fn build_components(
    parameters: Parameters,
    endpoint: &Endpoint,
) -> Result<(VlessTransport, TrojanSecurity), NodeRejection> {
    let Parameters {
        transport: transport_kind,
        security: security_kind,
        path,
        host,
        service_name,
        mode,
        server_name,
        peer,
        alpn,
        fingerprint,
        public_key,
        short_id,
    } = parameters;

    let transport = match transport_kind {
        VlessTransportKind::Tcp => VlessTransport::Tcp,
        VlessTransportKind::WebSocket => VlessTransport::WebSocket {
            path: path.unwrap_or_else(|| "/".into()),
            host,
        },
        VlessTransportKind::Grpc => VlessTransport::Grpc {
            service_name,
            mode: mode.unwrap_or(GrpcMode::Gun),
        },
    };

    let server_name = match (server_name, peer) {
        (Some(sni), Some(peer)) if sni != peer => {
            return Err(NodeRejection::Invalid(
                InvalidNodeReason::IncompatibleParameter,
            ));
        }
        (Some(sni), _) => Some(sni),
        (None, peer) => peer,
    };

    let security = match security_kind {
        VlessSecurityKind::None => {
            return Err(NodeRejection::Unsupported(UnsupportedCapability::Security));
        }
        VlessSecurityKind::Tls => {
            if public_key.is_some() || short_id.is_some() {
                return Err(NodeRejection::Invalid(
                    InvalidNodeReason::IncompatibleParameter,
                ));
            }
            TrojanSecurity::Tls(build_tls_options(
                server_name,
                alpn,
                endpoint,
                fingerprint.unwrap_or(ClientFingerprint::Chrome),
            )?)
        }
        VlessSecurityKind::Reality => {
            let public_key =
                public_key.ok_or(NodeRejection::Invalid(InvalidNodeReason::Credential))?;
            let short_id = match short_id {
                None | Some(ShortIdParameter::Empty) => None,
                Some(ShortIdParameter::Value(short_id)) => Some(short_id),
            };
            TrojanSecurity::Reality(RealityOptions::new(
                build_tls_options(
                    server_name,
                    alpn,
                    endpoint,
                    fingerprint.unwrap_or(ClientFingerprint::Chrome),
                )?,
                public_key,
                short_id,
            ))
        }
    };

    Ok((transport, security))
}
