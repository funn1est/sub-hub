use std::borrow::Cow;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use uuid::Uuid;

use crate::node::{
    Endpoint, Host, InvalidNodeReason, NodeProtocol, NodeRejection, ProxyNodeDraft,
    UnsupportedCapability,
    uri::{QueryPair, parse_authority_uri, parse_endpoint, scan_query},
};

use super::{
    ClientFingerprint, GrpcMode, RealityOptions, RealityPublicKey, RealityShortId, TlsOptions,
    VlessFlow, VlessId, VlessNode, VlessSecurity, VlessSecurityKind, VlessTransport,
    VlessTransportKind,
};

pub(crate) fn parse(input: &str) -> Result<ProxyNodeDraft, NodeRejection> {
    let uri = parse_authority_uri(input)?;
    let id = uri.userinfo;
    if id.contains(':') {
        return Err(NodeRejection::Invalid(InvalidNodeReason::Uri));
    }
    if !is_canonical_uuid(id) {
        return Err(NodeRejection::Invalid(InvalidNodeReason::Credential));
    }
    let id = Uuid::parse_str(id)
        .map(VlessId::new)
        .map_err(|_| NodeRejection::Invalid(InvalidNodeReason::Credential))?;
    let endpoint = parse_endpoint(uri.authority)?;
    let parameters = parse_parameters(uri.query)?;
    let (transport, security, flow) = build_components(parameters, &endpoint)?;

    Ok(ProxyNodeDraft {
        endpoint,
        name_input: uri.name_input,
        protocol: NodeProtocol::Vless(VlessNode::new(id, transport, security, flow).ok_or(
            NodeRejection::Invalid(InvalidNodeReason::IncompatibleParameter),
        )?),
    })
}

pub(crate) enum ShortIdParameter {
    Empty,
    Value(RealityShortId),
}

/// Shared stream-query fields for VLESS and Trojan share-URIs.
pub(crate) struct StreamQueryBase {
    pub transport: VlessTransportKind,
    pub security: VlessSecurityKind,
    pub path: Option<String>,
    pub host: Option<String>,
    pub service_name: Option<String>,
    pub mode: Option<GrpcMode>,
    pub server_name: Option<String>,
    pub alpn: Option<Vec<String>>,
    pub fingerprint: Option<ClientFingerprint>,
    pub public_key: Option<RealityPublicKey>,
    pub short_id: Option<ShortIdParameter>,
}

impl StreamQueryBase {
    pub(crate) fn new(security: VlessSecurityKind) -> Self {
        Self {
            transport: VlessTransportKind::Tcp,
            security,
            path: None,
            host: None,
            service_name: None,
            mode: None,
            server_name: None,
            alpn: None,
            fingerprint: None,
            public_key: None,
            short_id: None,
        }
    }
}

pub(crate) struct ParameterContext {
    transport: Result<VlessTransportKind, NodeRejection>,
    security: Result<VlessSecurityKind, NodeRejection>,
}

impl ParameterContext {
    pub(crate) fn from_pairs(
        pairs: &[QueryPair<'_>],
        default_security: VlessSecurityKind,
        parse_security: fn(&str) -> Result<VlessSecurityKind, NodeRejection>,
    ) -> Self {
        let transport = parameter_value(pairs, "type")
            .map_or(Ok(VlessTransportKind::Tcp), parse_transport_kind);
        let security =
            parameter_value(pairs, "security").map_or(Ok(default_security), parse_security);
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

    pub(crate) fn security_uses_tls(&self) -> bool {
        self.security
            .as_ref()
            .is_ok_and(|security| security.uses_tls())
    }

    pub(crate) fn flow_is_compatible(&self, flow: VlessFlow) -> bool {
        match (self.transport.as_ref(), self.security.as_ref()) {
            (Ok(transport), Ok(security)) => flow.is_compatible_with(*transport, *security),
            _ => false,
        }
    }
}

/// Applies a shared stream-query key. Returns `false` when `key` is protocol-local.
pub(crate) fn apply_shared_stream_query_pair(
    parameters: &mut StreamQueryBase,
    context: &ParameterContext,
    key: &str,
    value: Cow<'_, str>,
) -> Result<bool, NodeRejection> {
    match key {
        "type" => parameters.transport = context.transport.clone()?,
        "security" => parameters.security = context.security.clone()?,
        "headerType" => {
            require_nonempty(&value)?;
            if value.as_ref() != "none" {
                return Err(NodeRejection::Unsupported(
                    UnsupportedCapability::ProtocolOption,
                ));
            }
        }
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
        "spx" | "spiderx" | "spiderX" => {}
        "allowInsecure" | "insecure" => parse_insecure_off_flag(&value)?,
        "udp" => parse_udp_enable_flag(&value)?,
        "mux" => parse_mux_off_flag(&value)?,
        _ => return Ok(false),
    }
    Ok(true)
}

struct Parameters {
    base: StreamQueryBase,
    flow: Option<VlessFlow>,
}

fn parse_parameters(query: Option<&str>) -> Result<Parameters, NodeRejection> {
    let mut base = StreamQueryBase::new(VlessSecurityKind::None);
    let mut flow = None;
    let Some(query) = query else {
        return Ok(Parameters { base, flow });
    };
    let pairs = scan_query(query)?;
    let context =
        ParameterContext::from_pairs(&pairs, VlessSecurityKind::None, parse_security_kind);

    for pair in pairs {
        let key = pair.key;
        let value = pair.value;
        match key {
            "encryption" => {
                require_nonempty(&value)?;
                if value.as_ref() != "none" {
                    return Err(NodeRejection::Unsupported(
                        UnsupportedCapability::Encryption,
                    ));
                }
            }
            "flow" => {
                if value.is_empty() {
                    continue;
                }
                let parsed = parse_flow(&value)?;
                require_compatible(context.flow_is_compatible(parsed))?;
                flow = Some(parsed);
            }
            _ if apply_shared_stream_query_pair(&mut base, &context, key, value)? => {}
            _ => return Err(unsupported_parameter(key)),
        }
    }

    Ok(Parameters { base, flow })
}

fn unsupported_parameter(key: &str) -> NodeRejection {
    let capability = match key {
        "authority" | "service-name" => UnsupportedCapability::TransportOption,
        "packetEncoding" | "packet-encoding" | "seed" | "request" | "response" | "ed" | "eh"
        | "pqv" | "ech" | "echConfig" | "echForceQuery" => UnsupportedCapability::ProtocolOption,
        _ => UnsupportedCapability::UnknownParameter,
    };
    NodeRejection::Unsupported(capability)
}

pub(crate) fn parse_transport_kind(value: &str) -> Result<VlessTransportKind, NodeRejection> {
    require_nonempty(value)?;
    match value {
        "tcp" => Ok(VlessTransportKind::Tcp),
        "ws" => Ok(VlessTransportKind::WebSocket),
        "grpc" => Ok(VlessTransportKind::Grpc),
        _ => Err(NodeRejection::Unsupported(UnsupportedCapability::Transport)),
    }
}

fn parse_security_kind(value: &str) -> Result<VlessSecurityKind, NodeRejection> {
    require_nonempty(value)?;
    match value {
        "none" => Ok(VlessSecurityKind::None),
        "tls" => Ok(VlessSecurityKind::Tls),
        "reality" => Ok(VlessSecurityKind::Reality),
        _ => Err(NodeRejection::Unsupported(UnsupportedCapability::Security)),
    }
}

pub(crate) fn parse_grpc_mode(value: &str) -> Result<GrpcMode, NodeRejection> {
    match value {
        "gun" => Ok(GrpcMode::Gun),
        _ => Err(NodeRejection::Unsupported(
            UnsupportedCapability::TransportOption,
        )),
    }
}

fn parse_flow(value: &str) -> Result<VlessFlow, NodeRejection> {
    match value {
        "xtls-rprx-vision" => Ok(VlessFlow::Vision),
        _ => Err(NodeRejection::Unsupported(UnsupportedCapability::Flow)),
    }
}

pub(crate) fn parameter_value<'a>(pairs: &'a [QueryPair<'_>], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|pair| pair.key == key)
        .map(|pair| pair.value.as_ref())
}

pub(crate) fn require_nonempty(value: &str) -> Result<(), NodeRejection> {
    if value.is_empty() {
        Err(NodeRejection::Invalid(InvalidNodeReason::ParameterValue))
    } else {
        Ok(())
    }
}

pub(crate) fn parse_insecure_off_flag(value: &str) -> Result<(), NodeRejection> {
    match value {
        "0" | "false" => Ok(()),
        "1" | "true" => Err(NodeRejection::Unsupported(
            UnsupportedCapability::ProtocolOption,
        )),
        _ => Err(NodeRejection::Invalid(InvalidNodeReason::ParameterValue)),
    }
}

pub(crate) fn parse_udp_enable_flag(value: &str) -> Result<(), NodeRejection> {
    match value {
        "1" | "true" => Ok(()),
        "0" | "false" => Err(NodeRejection::Unsupported(
            UnsupportedCapability::ProtocolOption,
        )),
        _ => Err(NodeRejection::Invalid(InvalidNodeReason::ParameterValue)),
    }
}

fn parse_mux_off_flag(value: &str) -> Result<(), NodeRejection> {
    parse_insecure_off_flag(value)
}

pub(crate) fn require_compatible(is_compatible: bool) -> Result<(), NodeRejection> {
    if is_compatible {
        Ok(())
    } else {
        Err(NodeRejection::Invalid(
            InvalidNodeReason::IncompatibleParameter,
        ))
    }
}

pub(crate) fn nonempty_owned(value: Cow<'_, str>) -> Result<String, NodeRejection> {
    if value.is_empty() {
        Err(NodeRejection::Invalid(InvalidNodeReason::ParameterValue))
    } else {
        Ok(value.into_owned())
    }
}

fn build_components(
    parameters: Parameters,
    endpoint: &Endpoint,
) -> Result<(VlessTransport, VlessSecurity, Option<VlessFlow>), NodeRejection> {
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
        flow,
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

    let security = match security_kind {
        VlessSecurityKind::None => {
            if server_name.is_some()
                || alpn.is_some()
                || fingerprint.is_some()
                || public_key.is_some()
                || short_id.is_some()
            {
                return Err(NodeRejection::Invalid(
                    InvalidNodeReason::IncompatibleParameter,
                ));
            }
            VlessSecurity::None
        }
        VlessSecurityKind::Tls => {
            if public_key.is_some() || short_id.is_some() {
                return Err(NodeRejection::Invalid(
                    InvalidNodeReason::IncompatibleParameter,
                ));
            }
            VlessSecurity::Tls(build_tls_options(
                server_name,
                alpn,
                endpoint,
                fingerprint.unwrap_or(ClientFingerprint::Chrome),
            )?)
        }
        VlessSecurityKind::Reality => {
            if !transport
                .kind()
                .is_compatible_with_security(VlessSecurityKind::Reality)
            {
                return Err(NodeRejection::Invalid(
                    InvalidNodeReason::IncompatibleParameter,
                ));
            }
            let fingerprint =
                fingerprint.ok_or(NodeRejection::Invalid(InvalidNodeReason::ParameterValue))?;
            let public_key =
                public_key.ok_or(NodeRejection::Invalid(InvalidNodeReason::Credential))?;
            let short_id = match short_id {
                None | Some(ShortIdParameter::Empty) => None,
                Some(ShortIdParameter::Value(short_id)) => Some(short_id),
            };
            VlessSecurity::Reality(RealityOptions::new(
                build_tls_options(server_name, alpn, endpoint, fingerprint)?,
                public_key,
                short_id,
            ))
        }
    };

    Ok((transport, security, flow))
}

pub(crate) fn build_tls_options(
    server_name: Option<String>,
    alpn: Option<Vec<String>>,
    endpoint: &Endpoint,
    fingerprint: ClientFingerprint,
) -> Result<TlsOptions, NodeRejection> {
    TlsOptions::new(
        server_name.unwrap_or_else(|| canonical_host(endpoint.host())),
        alpn,
        fingerprint,
    )
    .ok_or(NodeRejection::Invalid(InvalidNodeReason::ParameterValue))
}

pub(crate) fn parse_public_key(input: &str) -> Result<RealityPublicKey, NodeRejection> {
    if input.len() != 43
        || !input
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(NodeRejection::Invalid(InvalidNodeReason::Credential));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|_| NodeRejection::Invalid(InvalidNodeReason::Credential))?;
    let bytes = decoded
        .try_into()
        .map_err(|_| NodeRejection::Invalid(InvalidNodeReason::Credential))?;
    Ok(RealityPublicKey::new(bytes))
}

pub(crate) fn parse_short_id(input: &str) -> Result<RealityShortId, NodeRejection> {
    if !(2..=16).contains(&input.len())
        || !input.len().is_multiple_of(2)
        || !input
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(NodeRejection::Invalid(InvalidNodeReason::Credential));
    }
    let bytes = input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| Some((hex_value(pair[0])? << 4) | hex_value(pair[1])?))
        .collect::<Option<Vec<_>>>()
        .ok_or(NodeRejection::Invalid(InvalidNodeReason::Credential))?;
    RealityShortId::new(bytes).ok_or(NodeRejection::Invalid(InvalidNodeReason::Credential))
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

pub(crate) fn parse_alpn(input: &str) -> Result<Vec<String>, NodeRejection> {
    let values = input.split(',').map(str::to_owned).collect::<Vec<_>>();
    if values
        .iter()
        .any(|value| value.is_empty() || value.chars().any(char::is_whitespace))
    {
        return Err(NodeRejection::Invalid(InvalidNodeReason::ParameterValue));
    }
    Ok(values)
}

pub(crate) fn parse_fingerprint(input: &str) -> Result<ClientFingerprint, NodeRejection> {
    match input {
        "chrome" => Ok(ClientFingerprint::Chrome),
        "firefox" => Ok(ClientFingerprint::Firefox),
        "safari" => Ok(ClientFingerprint::Safari),
        "ios" => Ok(ClientFingerprint::Ios),
        "android" => Ok(ClientFingerprint::Android),
        "edge" => Ok(ClientFingerprint::Edge),
        "360" => Ok(ClientFingerprint::ThreeSixty),
        "qq" => Ok(ClientFingerprint::Qq),
        "random" => Ok(ClientFingerprint::Random),
        _ => Err(NodeRejection::Invalid(InvalidNodeReason::ParameterValue)),
    }
}

pub(crate) fn canonical_host(host: &Host) -> String {
    match host {
        Host::Domain(domain) => domain.clone(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => address.to_string(),
    }
}

pub(crate) fn is_canonical_uuid(input: &str) -> bool {
    input.len() == 36
        && input.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}
