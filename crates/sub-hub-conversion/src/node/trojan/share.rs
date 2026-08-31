use crate::node::{
    Endpoint, InvalidNodeReason, NodeProtocol, NodeRejection, ProxyNodeDraft,
    UnsupportedCapability, percent,
    uri::{parse_authority_uri, parse_endpoint, scan_query},
    vless::{
        ClientFingerprint, GrpcMode, RealityOptions, VlessSecurityKind, VlessTransport,
        VlessTransportKind,
        share::{
            ParameterContext, ShortIdParameter, StreamQueryBase, apply_shared_stream_query_pair,
            build_tls_options, nonempty_owned, require_compatible, require_nonempty,
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

struct Parameters {
    base: StreamQueryBase,
    peer: Option<String>,
}

fn parse_parameters(query: Option<&str>) -> Result<Parameters, NodeRejection> {
    let mut base = StreamQueryBase::new(VlessSecurityKind::Tls);
    let mut peer = None;
    let Some(query) = query else {
        return Ok(Parameters { base, peer });
    };
    let pairs = scan_query(query)?;
    let context = ParameterContext::from_pairs(&pairs, VlessSecurityKind::Tls, parse_security_kind);

    for pair in pairs {
        let key = pair.key;
        let value = pair.value;
        match key {
            "peer" => {
                let value = nonempty_owned(value)?;
                require_compatible(context.security_uses_tls())?;
                peer = Some(value);
            }
            _ if apply_shared_stream_query_pair(&mut base, &context, key, value)? => {}
            _ => return Err(unsupported_parameter(key)),
        }
    }

    Ok(Parameters { base, peer })
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
        "authority" | "service-name" | "seed" => UnsupportedCapability::TransportOption,
        "flow" | "encryption" | "ss" | "plugin" | "packetEncoding" | "packet-encoding" | "ech"
        | "pqv" | "request" | "response" | "ed" | "eh" | "echConfig" | "echForceQuery" => {
            UnsupportedCapability::ProtocolOption
        }
        _ => UnsupportedCapability::UnknownParameter,
    };
    NodeRejection::Unsupported(capability)
}

fn build_components(
    parameters: Parameters,
    endpoint: &Endpoint,
) -> Result<(VlessTransport, TrojanSecurity), NodeRejection> {
    let Parameters {
        base:
            StreamQueryBase {
                transport: transport_kind,
                security: security_kind,
                path,
                host,
                service_name,
                mode,
                server_name,
                alpn,
                fingerprint,
                public_key,
                short_id,
            },
        peer,
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
