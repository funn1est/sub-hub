use std::{
    borrow::Cow,
    fmt,
    io::{self, Write},
};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::Serialize;

use crate::{
    node::shadowsocks::{ShadowsocksCipher, ShadowsocksCredential},
    node::vless::{ClientFingerprint, VlessFlow, VlessSecurity, VlessTransport},
    node::{Host, NodeProtocol, ProxyNode},
    node_name::{NamedNodeOccurrence, NodeNameDiagnostics, NodeNameError, resolve_node_names},
    policy::{
        CompiledPolicyV1, CompiledRuleV1, GroupStrategyV1, IpVersion, RuleMatcherV1,
        compile_builtin_policy_v1,
    },
    quanx::{QuanxRenderError, render_quanx_from_policy_v1},
    share_uri::NodeRejection,
    singbox::{SingboxRenderError, render_singbox_from_policy_v1},
    subscription_source::{NodeOrigin, ParsedSubscriptionSources},
};

const LOSSY_COMMENT: &str =
    "# subconverter: lossy conversion; unsupported URL-REGEX rules omitted\n";
const EMPTY_GROUP_COMMENT_PREFIX: &str =
    "# subconverter: warning; empty proxy groups downgraded to select + REJECT; count=";

#[derive(PartialEq, Eq)]
pub(crate) struct BuiltinMihomoOutput {
    config: Vec<u8>,
    diagnostics: BuiltinMihomoDiagnostics,
}

impl BuiltinMihomoOutput {
    pub(crate) fn config(&self) -> &[u8] {
        &self.config
    }

    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "diagnostics stay behind the application facade")
    )]
    pub(crate) const fn diagnostics(&self) -> &BuiltinMihomoDiagnostics {
        &self.diagnostics
    }
}

impl fmt::Debug for BuiltinMihomoOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BuiltinMihomoOutput")
            .field("config", &"[REDACTED]")
            .field("config_len", &self.config.len())
            .field("diagnostics", &self.diagnostics)
            .finish()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct BuiltinMihomoDiagnostics {
    rejections: Vec<BuiltinMihomoRejection>,
    node_names: NodeNameDiagnostics,
}

impl BuiltinMihomoDiagnostics {
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "diagnostics stay behind the application facade")
    )]
    pub(crate) fn rejections(&self) -> &[BuiltinMihomoRejection] {
        &self.rejections
    }

    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "diagnostics stay behind the application facade")
    )]
    pub(crate) const fn node_names(&self) -> &NodeNameDiagnostics {
        &self.node_names
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct BuiltinMihomoRejection {
    origin: NodeOrigin,
    rejection: NodeRejection,
}

impl BuiltinMihomoRejection {
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "diagnostics stay behind the application facade")
    )]
    pub(crate) const fn origin(&self) -> NodeOrigin {
        self.origin
    }

    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "diagnostics stay behind the application facade")
    )]
    pub(crate) const fn rejection(&self) -> &NodeRejection {
        &self.rejection
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BuiltinMihomoError {
    NodeNaming(NodeNameError),
    NoValidNodes {
        diagnostics: BuiltinMihomoDiagnostics,
    },
    OutputTooLarge {
        limit_bytes: usize,
    },
    Serialization,
}

pub(crate) const MAX_MIHOMO_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

pub(crate) fn render_builtin_mihomo_v1(
    parsed: ParsedSubscriptionSources,
) -> Result<BuiltinMihomoOutput, BuiltinMihomoError> {
    render_builtin_mihomo_v1_with_limit(parsed, MAX_MIHOMO_OUTPUT_BYTES)
}

fn render_builtin_mihomo_v1_with_limit(
    parsed: ParsedSubscriptionSources,
    limit_bytes: usize,
) -> Result<BuiltinMihomoOutput, BuiltinMihomoError> {
    let named =
        resolve_node_names(parsed, &["PROXY", "AUTO"]).map_err(BuiltinMihomoError::NodeNaming)?;
    let diagnostics = BuiltinMihomoDiagnostics {
        rejections: named
            .occurrences()
            .iter()
            .filter_map(|occurrence| match occurrence {
                NamedNodeOccurrence::Accepted { .. } => None,
                NamedNodeOccurrence::Rejected { origin, rejection } => {
                    Some(BuiltinMihomoRejection {
                        origin: *origin,
                        rejection: rejection.clone(),
                    })
                }
            })
            .collect(),
        node_names: named.diagnostics().clone(),
    };
    let nodes = named
        .occurrences()
        .iter()
        .filter_map(|occurrence| match occurrence {
            NamedNodeOccurrence::Accepted { node, .. } => Some(node.as_ref()),
            NamedNodeOccurrence::Rejected { .. } => None,
        })
        .collect::<Vec<_>>();
    if nodes.is_empty() {
        return Err(BuiltinMihomoError::NoValidNodes { diagnostics });
    }

    let policy = compile_builtin_policy_v1(&nodes);
    let config = render_mihomo_from_policy_v1(&nodes, &policy, limit_bytes)?;
    Ok(BuiltinMihomoOutput {
        config,
        diagnostics,
    })
}

pub(crate) fn render_builtin_quanx_v1(
    parsed: ParsedSubscriptionSources,
) -> Result<BuiltinMihomoOutput, BuiltinMihomoError> {
    render_builtin_quanx_v1_with_limit(parsed, MAX_MIHOMO_OUTPUT_BYTES)
}

fn render_builtin_quanx_v1_with_limit(
    parsed: ParsedSubscriptionSources,
    limit_bytes: usize,
) -> Result<BuiltinMihomoOutput, BuiltinMihomoError> {
    let named =
        resolve_node_names(parsed, &["PROXY", "AUTO"]).map_err(BuiltinMihomoError::NodeNaming)?;
    let diagnostics = BuiltinMihomoDiagnostics {
        rejections: named
            .occurrences()
            .iter()
            .filter_map(|occurrence| match occurrence {
                NamedNodeOccurrence::Accepted { .. } => None,
                NamedNodeOccurrence::Rejected { origin, rejection } => {
                    Some(BuiltinMihomoRejection {
                        origin: *origin,
                        rejection: rejection.clone(),
                    })
                }
            })
            .collect(),
        node_names: named.diagnostics().clone(),
    };
    let nodes = named
        .occurrences()
        .iter()
        .filter_map(|occurrence| match occurrence {
            NamedNodeOccurrence::Accepted { node, .. } => Some(node.as_ref()),
            NamedNodeOccurrence::Rejected { .. } => None,
        })
        .collect::<Vec<_>>();
    if nodes.is_empty() {
        return Err(BuiltinMihomoError::NoValidNodes { diagnostics });
    }
    let policy = compile_builtin_policy_v1(&nodes);
    let config = match render_quanx_from_policy_v1(&nodes, &policy, limit_bytes) {
        Ok(config) => config,
        Err(QuanxRenderError::NoValidNodes) => {
            return Err(BuiltinMihomoError::NoValidNodes { diagnostics });
        }
        Err(QuanxRenderError::OutputTooLarge { limit_bytes }) => {
            return Err(BuiltinMihomoError::OutputTooLarge { limit_bytes });
        }
        Err(QuanxRenderError::Internal) => return Err(BuiltinMihomoError::Serialization),
    };
    Ok(BuiltinMihomoOutput {
        config,
        diagnostics,
    })
}

pub(crate) fn render_builtin_singbox_v1(
    parsed: ParsedSubscriptionSources,
) -> Result<BuiltinMihomoOutput, BuiltinMihomoError> {
    render_builtin_singbox_v1_with_limit(parsed, MAX_MIHOMO_OUTPUT_BYTES)
}

fn render_builtin_singbox_v1_with_limit(
    parsed: ParsedSubscriptionSources,
    limit_bytes: usize,
) -> Result<BuiltinMihomoOutput, BuiltinMihomoError> {
    let named =
        resolve_node_names(parsed, &["PROXY", "AUTO"]).map_err(BuiltinMihomoError::NodeNaming)?;
    let diagnostics = BuiltinMihomoDiagnostics {
        rejections: named
            .occurrences()
            .iter()
            .filter_map(|occurrence| match occurrence {
                NamedNodeOccurrence::Accepted { .. } => None,
                NamedNodeOccurrence::Rejected { origin, rejection } => {
                    Some(BuiltinMihomoRejection {
                        origin: *origin,
                        rejection: rejection.clone(),
                    })
                }
            })
            .collect(),
        node_names: named.diagnostics().clone(),
    };
    let nodes = named
        .occurrences()
        .iter()
        .filter_map(|occurrence| match occurrence {
            NamedNodeOccurrence::Accepted { node, .. } => Some(node.as_ref()),
            NamedNodeOccurrence::Rejected { .. } => None,
        })
        .collect::<Vec<_>>();
    if nodes.is_empty() {
        return Err(BuiltinMihomoError::NoValidNodes { diagnostics });
    }
    let policy = compile_builtin_policy_v1(&nodes);
    let config = match render_singbox_from_policy_v1(&nodes, &policy, limit_bytes) {
        Ok(config) => config,
        Err(SingboxRenderError::NoValidNodes) => {
            return Err(BuiltinMihomoError::NoValidNodes { diagnostics });
        }
        Err(SingboxRenderError::OutputTooLarge { limit_bytes }) => {
            return Err(BuiltinMihomoError::OutputTooLarge { limit_bytes });
        }
        Err(SingboxRenderError::Internal) => return Err(BuiltinMihomoError::Serialization),
    };
    Ok(BuiltinMihomoOutput {
        config,
        diagnostics,
    })
}

pub(crate) fn render_mihomo_from_policy_v1(
    named_nodes: &[&ProxyNode],
    policy: &CompiledPolicyV1,
    limit_bytes: usize,
) -> Result<Vec<u8>, BuiltinMihomoError> {
    let document = MihomoRenderedDocument {
        mode: "rule",
        proxies: named_nodes
            .iter()
            .map(|node| MihomoProxy::from(*node))
            .collect(),
        proxy_groups: policy.groups().iter().map(mihomo_group).collect(),
        rules: policy.rules().iter().map(render_clash_rule).collect(),
    };
    let comments = comment_prefix(
        policy.report().omitted_url_regex,
        policy.report().empty_groups,
    );
    let body_limit = limit_bytes
        .checked_sub(comments.len())
        .ok_or(BuiltinMihomoError::OutputTooLarge { limit_bytes })?;
    let body = serialize_bounded(&document, body_limit)?;
    if comments.is_empty() {
        return Ok(body);
    }
    let mut bytes = Vec::with_capacity(comments.len() + body.len());
    bytes.extend_from_slice(comments.as_bytes());
    bytes.extend_from_slice(&body);
    Ok(bytes)
}

pub(crate) fn render_clash_rule(rule: &CompiledRuleV1) -> String {
    let target = rule.target().as_symbol();
    match rule.matcher() {
        RuleMatcherV1::Domain(value) => format!("DOMAIN,{value},{target}"),
        RuleMatcherV1::DomainSuffix(value) => format!("DOMAIN-SUFFIX,{value},{target}"),
        RuleMatcherV1::DomainKeyword(value) => format!("DOMAIN-KEYWORD,{value},{target}"),
        RuleMatcherV1::ProcessName(value) => format!("PROCESS-NAME,{value},{target}"),
        RuleMatcherV1::IpCidr {
            value,
            version,
            no_resolve,
        } => format!(
            "{},{value},{target}{}",
            match version {
                IpVersion::V4 => "IP-CIDR",
                IpVersion::V6 => "IP-CIDR6",
            },
            if *no_resolve { ",no-resolve" } else { "" }
        ),
        RuleMatcherV1::GeoIpCn => format!("GEOIP,CN,{target}"),
        RuleMatcherV1::Match => format!("MATCH,{target}"),
    }
}

fn comment_prefix(omitted_url_regex: u8, empty_groups: u8) -> String {
    let mut comments = String::new();
    if omitted_url_regex > 0 {
        comments.push_str(LOSSY_COMMENT);
    }
    if empty_groups > 0 {
        comments.push_str(EMPTY_GROUP_COMMENT_PREFIX);
        comments.push_str(&empty_groups.to_string());
        comments.push('\n');
    }
    comments
}

fn mihomo_group(group: &crate::policy::CompiledGroupV1) -> MihomoRenderedGroup {
    let proxies = group
        .members()
        .iter()
        .map(|member| member.as_symbol().to_owned())
        .collect();
    let (kind, url, interval, tolerance, strategy) = match group.strategy() {
        GroupStrategyV1::Select => ("select", None, None, None, None),
        GroupStrategyV1::UrlTest {
            url,
            interval,
            tolerance,
        } => (
            "url-test",
            Some(url.clone()),
            Some(*interval),
            *tolerance,
            None,
        ),
        GroupStrategyV1::Fallback { url, interval } => {
            ("fallback", Some(url.clone()), Some(*interval), None, None)
        }
        GroupStrategyV1::LoadBalance { url, interval } => (
            "load-balance",
            Some(url.clone()),
            Some(*interval),
            None,
            Some("consistent-hashing"),
        ),
    };
    MihomoRenderedGroup {
        name: group.name().to_owned(),
        kind,
        proxies,
        url,
        interval,
        tolerance,
        strategy,
    }
}

struct BoundedVec {
    bytes: Vec<u8>,
    limit: usize,
    overflowed: bool,
}

impl BoundedVec {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            overflowed: false,
        }
    }

    fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for BoundedVec {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if self.overflowed {
            return Err(io::Error::other("Mihomo output limit exceeded"));
        }
        let Some(next_len) = self.bytes.len().checked_add(input.len()) else {
            self.overflowed = true;
            return Err(io::Error::other("Mihomo output limit exceeded"));
        };
        if next_len > self.limit {
            self.overflowed = true;
            return Err(io::Error::other("Mihomo output limit exceeded"));
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.overflowed {
            Err(io::Error::other("Mihomo output limit exceeded"))
        } else {
            Ok(())
        }
    }
}

pub(crate) fn serialize_bounded<T: Serialize>(
    value: &T,
    limit_bytes: usize,
) -> Result<Vec<u8>, BuiltinMihomoError> {
    let mut sink = BoundedVec::new(limit_bytes);
    let serialization = serde_yaml_ng::to_writer(&mut sink, value);
    if sink.overflowed {
        return Err(BuiltinMihomoError::OutputTooLarge { limit_bytes });
    }
    serialization.map_err(|_| BuiltinMihomoError::Serialization)?;
    Ok(sink.into_inner())
}

#[derive(Serialize)]
struct MihomoRenderedDocument<'a> {
    mode: &'static str,
    proxies: Vec<MihomoProxy<'a>>,
    #[serde(rename = "proxy-groups")]
    proxy_groups: Vec<MihomoRenderedGroup>,
    rules: Vec<String>,
}

#[derive(Serialize)]
struct MihomoRenderedGroup {
    name: String,
    #[serde(rename = "type")]
    kind: &'static str,
    proxies: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    interval: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tolerance: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    strategy: Option<&'static str>,
}

#[derive(Serialize)]
#[serde(untagged)]
pub(crate) enum MihomoProxy<'a> {
    Vless(MihomoVlessProxy<'a>),
    Shadowsocks(MihomoShadowsocksProxy<'a>),
}

#[derive(Serialize)]
pub(crate) struct MihomoVlessProxy<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    kind: &'static str,
    server: String,
    port: u16,
    uuid: String,
    udp: bool,
    encryption: &'static str,
    network: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    flow: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    servername: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alpn: Option<&'a [String]>,
    #[serde(rename = "client-fingerprint", skip_serializing_if = "Option::is_none")]
    client_fingerprint: Option<&'static str>,
    #[serde(rename = "ws-opts", skip_serializing_if = "Option::is_none")]
    ws_opts: Option<MihomoWebSocketOptions<'a>>,
    #[serde(rename = "grpc-opts", skip_serializing_if = "Option::is_none")]
    grpc_opts: Option<MihomoGrpcOptions<'a>>,
    #[serde(rename = "reality-opts", skip_serializing_if = "Option::is_none")]
    reality_opts: Option<MihomoRealityOptions>,
}

impl<'a> From<&'a ProxyNode> for MihomoProxy<'a> {
    fn from(node: &'a ProxyNode) -> Self {
        match node.protocol() {
            NodeProtocol::Vless(vless) => Self::Vless(MihomoVlessProxy::from_node(node, vless)),
            NodeProtocol::Shadowsocks(shadowsocks) => {
                Self::Shadowsocks(MihomoShadowsocksProxy::from_node(
                    node,
                    shadowsocks.cipher(),
                    shadowsocks.credential(),
                ))
            }
        }
    }
}

impl<'a> MihomoVlessProxy<'a> {
    fn from_node(node: &'a ProxyNode, vless: &'a crate::node::vless::VlessNode) -> Self {
        let (network, ws_opts, grpc_opts) = match vless.transport() {
            VlessTransport::Tcp => ("tcp", None, None),
            VlessTransport::WebSocket { path, host } => (
                "ws",
                Some(MihomoWebSocketOptions {
                    path,
                    headers: host.as_deref().map(|host| MihomoWebSocketHeaders { host }),
                }),
                None,
            ),
            VlessTransport::Grpc { service_name, .. } => (
                "grpc",
                None,
                service_name
                    .as_deref()
                    .map(|service_name| MihomoGrpcOptions { service_name }),
            ),
        };
        let (tls, servername, alpn, client_fingerprint, reality_opts) = match vless.security() {
            VlessSecurity::None => (None, None, None, None, None),
            VlessSecurity::Tls(options) => (
                Some(true),
                Some(options.server_name()),
                options.alpn(),
                Some(render_fingerprint(options.fingerprint())),
                None,
            ),
            VlessSecurity::Reality(options) => (
                Some(true),
                Some(options.tls().server_name()),
                options.tls().alpn(),
                Some(render_fingerprint(options.tls().fingerprint())),
                Some(MihomoRealityOptions {
                    public_key: URL_SAFE_NO_PAD.encode(options.public_key().as_bytes()),
                    short_id: options
                        .short_id()
                        .map(|short_id| render_hex(short_id.as_bytes())),
                }),
            ),
        };
        MihomoVlessProxy {
            name: node.name().as_str(),
            kind: "vless",
            server: render_host(node.endpoint().host()),
            port: node.endpoint().port().get(),
            uuid: vless.id().as_uuid().hyphenated().to_string(),
            udp: true,
            encryption: "none",
            network,
            flow: vless.flow().map(|flow| match flow {
                VlessFlow::Vision => "xtls-rprx-vision",
            }),
            tls,
            servername,
            alpn,
            client_fingerprint,
            ws_opts,
            grpc_opts,
            reality_opts,
        }
    }
}

#[derive(Serialize)]
pub(crate) struct MihomoShadowsocksProxy<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    kind: &'static str,
    server: String,
    port: u16,
    cipher: &'static str,
    password: Cow<'a, str>,
    udp: bool,
}

impl<'a> MihomoShadowsocksProxy<'a> {
    fn from_node(
        node: &'a ProxyNode,
        cipher: &ShadowsocksCipher,
        credential: &'a ShadowsocksCredential,
    ) -> Self {
        let password = match credential {
            ShadowsocksCredential::Password(password) => Cow::Borrowed(password.expose()),
            ShadowsocksCredential::Psk(psk) => Cow::Owned(STANDARD.encode(psk.expose())),
        };
        Self {
            name: node.name().as_str(),
            kind: "ss",
            server: render_host(node.endpoint().host()),
            port: node.endpoint().port().get(),
            cipher: render_shadowsocks_cipher(cipher),
            password,
            udp: true,
        }
    }
}

#[derive(Serialize)]
struct MihomoWebSocketOptions<'a> {
    path: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    headers: Option<MihomoWebSocketHeaders<'a>>,
}

#[derive(Serialize)]
struct MihomoWebSocketHeaders<'a> {
    #[serde(rename = "Host")]
    host: &'a str,
}

#[derive(Serialize)]
struct MihomoGrpcOptions<'a> {
    #[serde(rename = "grpc-service-name")]
    service_name: &'a str,
}

#[derive(Serialize)]
struct MihomoRealityOptions {
    #[serde(rename = "public-key")]
    public_key: String,
    #[serde(rename = "short-id", skip_serializing_if = "Option::is_none")]
    short_id: Option<String>,
}

fn render_host(host: &Host) -> String {
    match host {
        Host::Domain(domain) => domain.clone(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => address.to_string(),
    }
}

const fn render_fingerprint(fingerprint: ClientFingerprint) -> &'static str {
    match fingerprint {
        ClientFingerprint::Chrome => "chrome",
        ClientFingerprint::Firefox => "firefox",
        ClientFingerprint::Safari => "safari",
        ClientFingerprint::Ios => "ios",
        ClientFingerprint::Android => "android",
        ClientFingerprint::Edge => "edge",
        ClientFingerprint::ThreeSixty => "360",
        ClientFingerprint::Qq => "qq",
        ClientFingerprint::Random => "random",
    }
}

fn render_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

const fn render_shadowsocks_cipher(cipher: &ShadowsocksCipher) -> &'static str {
    match cipher {
        ShadowsocksCipher::Aes128Gcm => "aes-128-gcm",
        ShadowsocksCipher::Aes256Gcm => "aes-256-gcm",
        ShadowsocksCipher::Chacha20IetfPoly1305 => "chacha20-ietf-poly1305",
        ShadowsocksCipher::Blake3Aes128Gcm => "2022-blake3-aes-128-gcm",
        ShadowsocksCipher::Blake3Aes256Gcm => "2022-blake3-aes-256-gcm",
    }
}

#[cfg(test)]
mod tests;
