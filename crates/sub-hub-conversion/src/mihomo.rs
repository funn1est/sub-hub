use std::borrow::Cow;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::Serialize;

use crate::{
    node::shadowsocks::{ShadowsocksCipher, ShadowsocksCredential},
    node::trojan::TrojanSecurity,
    node::vless::{VlessFlow, VlessSecurity, VlessTransport},
    node::vmess::VmessSecurity,
    node::{NodeProtocol, ProxyNode},
    policy::{CompiledPolicyV1, CompiledRuleV1, GroupStrategyV1, IpVersion, RuleMatcherV1},
    render::{
        AdapterRenderError, RenderedTargetV1, encode_hex, render_fingerprint, render_host_plain,
        serialize_bounded, shadowsocks_method,
    },
};

const LOSSY_COMMENT: &str =
    "# subconverter: lossy conversion; unsupported URL-REGEX rules omitted\n";
const EMPTY_GROUP_COMMENT_PREFIX: &str =
    "# subconverter: warning; empty proxy groups downgraded to select + REJECT; count=";

pub(crate) fn render_mihomo_from_policy_v1(
    named_nodes: &[&ProxyNode],
    policy: &CompiledPolicyV1,
    limit_bytes: usize,
) -> Result<RenderedTargetV1, AdapterRenderError> {
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
        .ok_or(AdapterRenderError::OutputTooLarge { limit_bytes })?;
    let body = serialize_bounded(&document, body_limit)?;
    if comments.is_empty() {
        return Ok(RenderedTargetV1 {
            bytes: body,
            capability_skips: 0,
        });
    }
    let mut bytes = Vec::with_capacity(comments.len() + body.len());
    bytes.extend_from_slice(comments.as_bytes());
    bytes.extend_from_slice(&body);
    Ok(RenderedTargetV1 {
        bytes,
        capability_skips: 0,
    })
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
    Trojan(MihomoTrojanProxy<'a>),
    Vmess(MihomoVmessProxy<'a>),
    Hysteria2(MihomoHysteria2Proxy<'a>),
    Tuic(MihomoTuicProxy<'a>),
}

#[derive(Serialize)]
pub(crate) struct MihomoTuicProxy<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    kind: &'static str,
    server: String,
    port: u16,
    uuid: String,
    password: &'a str,
    udp: bool,
    #[serde(
        rename = "congestion-controller",
        skip_serializing_if = "Option::is_none"
    )]
    congestion_controller: Option<&'static str>,
    #[serde(rename = "udp-relay-mode", skip_serializing_if = "Option::is_none")]
    udp_relay_mode: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sni: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alpn: Option<&'a [String]>,
}

impl<'a> MihomoTuicProxy<'a> {
    fn from_node(node: &'a ProxyNode, tuic: &'a crate::node::tuic::TuicNode) -> Self {
        Self {
            name: node.name().as_str(),
            kind: "tuic",
            server: render_host_plain(node.endpoint().host()),
            port: node.endpoint().port().get(),
            uuid: tuic.id().as_uuid().hyphenated().to_string(),
            password: tuic.password().expose(),
            udp: true,
            congestion_controller: (!tuic.congestion().is_default())
                .then(|| tuic.congestion().as_token()),
            udp_relay_mode: (!tuic.udp_relay().is_default()).then(|| tuic.udp_relay().as_token()),
            sni: tuic.sni(),
            alpn: tuic.alpn(),
        }
    }
}

#[derive(Serialize)]
pub(crate) struct MihomoHysteria2Proxy<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    kind: &'static str,
    server: String,
    port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    ports: Option<String>,
    password: &'a str,
    udp: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    obfs: Option<&'static str>,
    #[serde(rename = "obfs-password", skip_serializing_if = "Option::is_none")]
    obfs_password: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sni: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fingerprint: Option<String>,
}

impl<'a> MihomoHysteria2Proxy<'a> {
    fn from_node(
        node: &'a ProxyNode,
        hysteria2: &'a crate::node::hysteria2::Hysteria2Node,
    ) -> Self {
        let (obfs, obfs_password) = match hysteria2.obfs() {
            Some(obfs) => (Some(obfs.token()), Some(obfs.password())),
            None => (None, None),
        };
        Self {
            name: node.name().as_str(),
            kind: "hysteria2",
            server: render_host_plain(node.endpoint().host()),
            port: node.endpoint().port().get(),
            ports: hysteria2
                .ports()
                .is_hop()
                .then(|| hysteria2.ports().render_official()),
            password: hysteria2.auth().expose(),
            udp: true,
            obfs,
            obfs_password,
            sni: hysteria2.sni(),
            fingerprint: hysteria2.pin_sha256().map(|pin| encode_hex(pin)),
        }
    }
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
            NodeProtocol::Trojan(trojan) => {
                Self::Trojan(MihomoTrojanProxy::from_node(node, trojan))
            }
            NodeProtocol::Vmess(vmess) => Self::Vmess(MihomoVmessProxy::from_node(node, vmess)),
            NodeProtocol::Hysteria2(hysteria2) => {
                Self::Hysteria2(MihomoHysteria2Proxy::from_node(node, hysteria2))
            }
            NodeProtocol::Tuic(tuic) => Self::Tuic(MihomoTuicProxy::from_node(node, tuic)),
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
                        .map(|short_id| encode_hex(short_id.as_bytes())),
                }),
            ),
        };
        MihomoVlessProxy {
            name: node.name().as_str(),
            kind: "vless",
            server: render_host_plain(node.endpoint().host()),
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

#[derive(Serialize)]
pub(crate) struct MihomoTrojanProxy<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    kind: &'static str,
    server: String,
    port: u16,
    password: &'a str,
    udp: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    sni: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alpn: Option<&'a [String]>,
    #[serde(rename = "client-fingerprint", skip_serializing_if = "Option::is_none")]
    client_fingerprint: Option<&'static str>,
    network: &'static str,
    #[serde(rename = "ws-opts", skip_serializing_if = "Option::is_none")]
    ws_opts: Option<MihomoWebSocketOptions<'a>>,
    #[serde(rename = "grpc-opts", skip_serializing_if = "Option::is_none")]
    grpc_opts: Option<MihomoGrpcOptions<'a>>,
    #[serde(rename = "reality-opts", skip_serializing_if = "Option::is_none")]
    reality_opts: Option<MihomoRealityOptions>,
}

#[derive(Serialize)]
pub(crate) struct MihomoVmessProxy<'a> {
    name: &'a str,
    #[serde(rename = "type")]
    kind: &'static str,
    server: String,
    port: u16,
    uuid: String,
    #[serde(rename = "alterId")]
    alter_id: u16,
    cipher: &'static str,
    udp: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    servername: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alpn: Option<&'a [String]>,
    #[serde(rename = "client-fingerprint", skip_serializing_if = "Option::is_none")]
    client_fingerprint: Option<&'static str>,
    network: &'static str,
    #[serde(rename = "ws-opts", skip_serializing_if = "Option::is_none")]
    ws_opts: Option<MihomoWebSocketOptions<'a>>,
    #[serde(rename = "grpc-opts", skip_serializing_if = "Option::is_none")]
    grpc_opts: Option<MihomoGrpcOptions<'a>>,
}

impl<'a> MihomoVmessProxy<'a> {
    fn from_node(node: &'a ProxyNode, vmess: &'a crate::node::vmess::VmessNode) -> Self {
        let (network, ws_opts, grpc_opts) = match vmess.transport() {
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
        let (tls, servername, alpn, client_fingerprint) = match vmess.security() {
            VmessSecurity::None => (None, None, None, None),
            VmessSecurity::Tls(options) => (
                Some(true),
                Some(options.server_name()),
                options.alpn(),
                Some(render_fingerprint(options.fingerprint())),
            ),
        };
        Self {
            name: node.name().as_str(),
            kind: "vmess",
            server: render_host_plain(node.endpoint().host()),
            port: node.endpoint().port().get(),
            uuid: vmess.id().as_uuid().hyphenated().to_string(),
            alter_id: 0,
            cipher: vmess.cipher().as_token(),
            udp: true,
            tls,
            servername,
            alpn,
            client_fingerprint,
            network,
            ws_opts,
            grpc_opts,
        }
    }
}

impl<'a> MihomoTrojanProxy<'a> {
    fn from_node(node: &'a ProxyNode, trojan: &'a crate::node::trojan::TrojanNode) -> Self {
        let (network, ws_opts, grpc_opts) = match trojan.transport() {
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
        let tls = trojan.security().tls_options();
        let reality_opts = match trojan.security() {
            TrojanSecurity::Tls(_) => None,
            TrojanSecurity::Reality(options) => Some(MihomoRealityOptions {
                public_key: URL_SAFE_NO_PAD.encode(options.public_key().as_bytes()),
                short_id: options
                    .short_id()
                    .map(|short_id| encode_hex(short_id.as_bytes())),
            }),
        };
        Self {
            name: node.name().as_str(),
            kind: "trojan",
            server: render_host_plain(node.endpoint().host()),
            port: node.endpoint().port().get(),
            password: trojan.password().expose(),
            udp: true,
            sni: Some(tls.server_name()),
            alpn: tls.alpn(),
            client_fingerprint: Some(render_fingerprint(tls.fingerprint())),
            network,
            ws_opts,
            grpc_opts,
            reality_opts,
        }
    }
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
            server: render_host_plain(node.endpoint().host()),
            port: node.endpoint().port().get(),
            cipher: shadowsocks_method(cipher),
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

#[cfg(test)]
mod tests;
