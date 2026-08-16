use std::{borrow::Cow, fmt};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::Serialize;

use crate::{
    node::shadowsocks::{ShadowsocksCipher, ShadowsocksCredential},
    node::vless::{ClientFingerprint, VlessFlow, VlessSecurity, VlessTransport},
    node::{Host, NodeProtocol, ProxyNode},
    policy::{
        BUILTIN_AUTO_PROBE_URL, CompiledPolicyV1, CompiledRuleV1, GroupStrategyV1, PolicyMemberV1,
        RuleMatcherV1,
    },
};

const DEFAULT_URLTEST_TOLERANCE_MS: u16 = 50;

pub(crate) enum SingboxRenderError {
    NoValidNodes,
    OutputTooLarge { limit_bytes: usize },
    Internal,
}

pub(crate) fn render_singbox_from_policy_v1(
    named_nodes: &[&ProxyNode],
    policy: &CompiledPolicyV1,
    limit_bytes: usize,
) -> Result<Vec<u8>, SingboxRenderError> {
    let mut node_outbounds = Vec::new();
    let mut valid_tags = Vec::new();
    for node in named_nodes {
        let Some(tag) = singbox_node_tag(node.name().as_str()) else {
            continue;
        };
        node_outbounds.push(node_outbound(node, tag));
        valid_tags.push(tag.to_owned());
    }
    if node_outbounds.is_empty() {
        return Err(SingboxRenderError::NoValidNodes);
    }

    let valid = valid_tags.iter().map(String::as_str).collect::<Vec<_>>();
    let group_outbounds = render_groups(policy, &valid)?;
    let first_group = policy
        .groups()
        .first()
        .ok_or(SingboxRenderError::Internal)?;
    let final_tag = singbox_group_tag(first_group.name())?.to_owned();

    let mut outbounds = node_outbounds;
    outbounds.extend(group_outbounds);
    outbounds.push(Outbound::Simple(SimpleOutbound {
        kind: "direct",
        tag: "direct",
    }));
    outbounds.push(Outbound::Simple(SimpleOutbound {
        kind: "block",
        tag: "reject",
    }));

    let document = Document {
        log: Log {
            disabled: false,
            level: "info",
            timestamp: true,
        },
        dns: Dns {
            servers: vec![DnsServer {
                kind: "local",
                tag: "local",
            }],
            final_server: "local",
        },
        inbounds: vec![Inbound {
            kind: "mixed",
            tag: "mixed-in",
            listen: "127.0.0.1",
            listen_port: 2080,
            set_system_proxy: false,
        }],
        outbounds,
        route: Route {
            rules: render_rules(policy.rules(), &valid)?,
            final_outbound: final_tag,
            default_domain_resolver: "local",
        },
    };
    serialize_pretty(&document, limit_bytes)
}

fn singbox_node_tag(name: &str) -> Option<&str> {
    if name.is_empty()
        || name.chars().any(|character| character.is_ascii_control())
        || name.eq_ignore_ascii_case("direct")
        || name.eq_ignore_ascii_case("reject")
    {
        None
    } else {
        Some(name)
    }
}

fn singbox_group_tag(name: &str) -> Result<&str, SingboxRenderError> {
    if name.is_empty() || name.chars().any(|character| character.is_ascii_control()) {
        return Err(SingboxRenderError::Internal);
    }
    if name.eq_ignore_ascii_case("direct") || name.eq_ignore_ascii_case("reject") {
        return Err(SingboxRenderError::Internal);
    }
    Ok(name)
}

fn render_host(host: &Host) -> String {
    match host {
        Host::Domain(domain) => domain.clone(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => address.to_string(),
    }
}

fn node_outbound<'a>(node: &'a ProxyNode, tag: &'a str) -> Outbound<'a> {
    match node.protocol() {
        NodeProtocol::Vless(vless) => Outbound::Vless(vless_outbound(node, vless, tag)),
        NodeProtocol::Shadowsocks(shadowsocks) => Outbound::Shadowsocks(shadowsocks_outbound(
            node,
            shadowsocks.cipher(),
            shadowsocks.credential(),
            tag,
        )),
    }
}

fn vless_outbound<'a>(
    node: &'a ProxyNode,
    vless: &'a crate::node::vless::VlessNode,
    tag: &'a str,
) -> VlessOutbound<'a> {
    let transport = match vless.transport() {
        VlessTransport::Tcp => None,
        VlessTransport::WebSocket { path, host } => Some(Transport {
            kind: "ws",
            path: Some(path.as_str()),
            headers: host.as_deref().map(|host| TransportHeaders { host }),
            service_name: None,
        }),
        VlessTransport::Grpc { service_name, .. } => Some(Transport {
            kind: "grpc",
            path: None,
            headers: None,
            service_name: service_name.as_deref(),
        }),
    };
    let tls = match vless.security() {
        VlessSecurity::None => None,
        VlessSecurity::Tls(options) => Some(tls_object(
            options.server_name(),
            options.alpn(),
            options.fingerprint(),
            None,
        )),
        VlessSecurity::Reality(options) => Some(tls_object(
            options.tls().server_name(),
            options.tls().alpn(),
            options.tls().fingerprint(),
            Some(Reality {
                enabled: true,
                public_key: URL_SAFE_NO_PAD.encode(options.public_key().as_bytes()),
                short_id: options
                    .short_id()
                    .map(|short_id| encode_hex(short_id.as_bytes())),
            }),
        )),
    };
    VlessOutbound {
        kind: "vless",
        tag,
        server: render_host(node.endpoint().host()),
        server_port: node.endpoint().port().get(),
        uuid: vless.id().as_uuid().hyphenated().to_string(),
        flow: vless.flow().map(|flow| match flow {
            VlessFlow::Vision => "xtls-rprx-vision",
        }),
        tls,
        transport,
    }
}

fn tls_object<'a>(
    server_name: &'a str,
    alpn: Option<&'a [String]>,
    fingerprint: ClientFingerprint,
    reality: Option<Reality>,
) -> Tls<'a> {
    Tls {
        enabled: true,
        server_name,
        alpn,
        utls: Utls {
            enabled: true,
            fingerprint: render_fingerprint(fingerprint),
        },
        reality,
    }
}

fn shadowsocks_outbound<'a>(
    node: &'a ProxyNode,
    cipher: &ShadowsocksCipher,
    credential: &'a ShadowsocksCredential,
    tag: &'a str,
) -> ShadowsocksOutbound<'a> {
    let password = match credential {
        ShadowsocksCredential::Password(password) => Cow::Borrowed(password.expose()),
        ShadowsocksCredential::Psk(psk) => Cow::Owned(STANDARD.encode(psk.expose())),
    };
    ShadowsocksOutbound {
        kind: "shadowsocks",
        tag,
        server: render_host(node.endpoint().host()),
        server_port: node.endpoint().port().get(),
        method: shadowsocks_method(cipher),
        password,
    }
}

fn shadowsocks_method(cipher: &ShadowsocksCipher) -> &'static str {
    match cipher {
        ShadowsocksCipher::Aes128Gcm => "aes-128-gcm",
        ShadowsocksCipher::Aes256Gcm => "aes-256-gcm",
        ShadowsocksCipher::Chacha20IetfPoly1305 => "chacha20-ietf-poly1305",
        ShadowsocksCipher::Blake3Aes128Gcm => "2022-blake3-aes-128-gcm",
        ShadowsocksCipher::Blake3Aes256Gcm => "2022-blake3-aes-256-gcm",
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

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn member_tag(
    member: &PolicyMemberV1,
    valid_nodes: &[&str],
) -> Result<Option<String>, SingboxRenderError> {
    match member {
        PolicyMemberV1::Direct => Ok(Some("direct".to_owned())),
        PolicyMemberV1::Reject => Ok(Some("reject".to_owned())),
        PolicyMemberV1::Group(name) => singbox_group_tag(name).map(|tag| Some(tag.to_owned())),
        PolicyMemberV1::Node(name) => Ok(valid_nodes
            .iter()
            .any(|candidate| *candidate == name)
            .then(|| name.clone())),
    }
}

fn render_groups(
    policy: &CompiledPolicyV1,
    valid_nodes: &[&str],
) -> Result<Vec<Outbound<'static>>, SingboxRenderError> {
    let mut outbounds = Vec::new();
    for group in policy.groups() {
        let tag = singbox_group_tag(group.name())?.to_owned();
        let mut members = Vec::new();
        for member in group.members() {
            if let Some(token) = member_tag(member, valid_nodes)? {
                members.push(token);
            }
        }
        if members.is_empty() {
            members.push("reject".to_owned());
        }
        let outbound = match group.strategy() {
            GroupStrategyV1::Select | GroupStrategyV1::LoadBalance { .. } => {
                Outbound::Selector(SelectorOutbound {
                    kind: "selector",
                    tag,
                    outbounds: members,
                    interrupt_exist_connections: false,
                })
            }
            GroupStrategyV1::UrlTest {
                url,
                interval,
                tolerance,
            } => Outbound::Urltest(urltest_outbound(tag, members, url, *interval, *tolerance)),
            GroupStrategyV1::Fallback { url, interval } => {
                Outbound::Urltest(urltest_outbound(tag, members, url, *interval, None))
            }
        };
        outbounds.push(outbound);
    }
    Ok(outbounds)
}

fn urltest_outbound(
    tag: String,
    members: Vec<String>,
    url: &str,
    interval: u32,
    tolerance: Option<u16>,
) -> UrltestOutbound {
    UrltestOutbound {
        kind: "urltest",
        tag,
        outbounds: members,
        url: if url.is_empty() {
            BUILTIN_AUTO_PROBE_URL.to_owned()
        } else {
            url.to_owned()
        },
        interval: format!("{interval}s"),
        tolerance: tolerance.unwrap_or(DEFAULT_URLTEST_TOLERANCE_MS),
    }
}

fn render_rules(
    rules: &[CompiledRuleV1],
    valid_nodes: &[&str],
) -> Result<Vec<RouteRule>, SingboxRenderError> {
    let mut rendered = Vec::new();
    for rule in rules {
        let Some(outbound) = member_tag(rule.target(), valid_nodes)? else {
            continue;
        };
        let route = match rule.matcher() {
            RuleMatcherV1::Domain(value) => RouteRule {
                domain: Some(vec![value.clone()]),
                outbound,
                ..RouteRule::empty()
            },
            RuleMatcherV1::DomainSuffix(value) => RouteRule {
                domain_suffix: Some(vec![value.clone()]),
                outbound,
                ..RouteRule::empty()
            },
            RuleMatcherV1::DomainKeyword(value) => RouteRule {
                domain_keyword: Some(vec![value.clone()]),
                outbound,
                ..RouteRule::empty()
            },
            RuleMatcherV1::ProcessName(value) => RouteRule {
                process_name: Some(vec![value.clone()]),
                outbound,
                ..RouteRule::empty()
            },
            RuleMatcherV1::IpCidr { value, .. } => RouteRule {
                ip_cidr: Some(vec![value.clone()]),
                outbound,
                ..RouteRule::empty()
            },
            RuleMatcherV1::GeoIpCn | RuleMatcherV1::Match => continue,
        };
        rendered.push(route);
    }
    Ok(rendered)
}

fn serialize_pretty(
    document: &Document<'_>,
    limit_bytes: usize,
) -> Result<Vec<u8>, SingboxRenderError> {
    let mut body = serde_json::to_vec_pretty(document).map_err(|_| SingboxRenderError::Internal)?;
    body.push(b'\n');
    if body.len() > limit_bytes {
        return Err(SingboxRenderError::OutputTooLarge { limit_bytes });
    }
    Ok(body)
}

#[derive(Serialize)]
struct Document<'a> {
    log: Log,
    dns: Dns,
    inbounds: Vec<Inbound>,
    outbounds: Vec<Outbound<'a>>,
    route: Route,
}

#[derive(Serialize)]
struct Log {
    disabled: bool,
    level: &'static str,
    timestamp: bool,
}

#[derive(Serialize)]
struct Dns {
    servers: Vec<DnsServer>,
    #[serde(rename = "final")]
    final_server: &'static str,
}

#[derive(Serialize)]
struct DnsServer {
    #[serde(rename = "type")]
    kind: &'static str,
    tag: &'static str,
}

#[derive(Serialize)]
struct Inbound {
    #[serde(rename = "type")]
    kind: &'static str,
    tag: &'static str,
    listen: &'static str,
    listen_port: u16,
    set_system_proxy: bool,
}

#[derive(Serialize)]
#[serde(untagged)]
enum Outbound<'a> {
    Vless(VlessOutbound<'a>),
    Shadowsocks(ShadowsocksOutbound<'a>),
    Selector(SelectorOutbound),
    Urltest(UrltestOutbound),
    Simple(SimpleOutbound),
}

#[derive(Serialize)]
struct VlessOutbound<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    tag: &'a str,
    server: String,
    server_port: u16,
    uuid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    flow: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls: Option<Tls<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transport: Option<Transport<'a>>,
}

#[derive(Serialize)]
struct ShadowsocksOutbound<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    tag: &'a str,
    server: String,
    server_port: u16,
    method: &'static str,
    password: Cow<'a, str>,
}

#[derive(Serialize)]
struct SelectorOutbound {
    #[serde(rename = "type")]
    kind: &'static str,
    tag: String,
    outbounds: Vec<String>,
    interrupt_exist_connections: bool,
}

#[derive(Serialize)]
struct UrltestOutbound {
    #[serde(rename = "type")]
    kind: &'static str,
    tag: String,
    outbounds: Vec<String>,
    url: String,
    interval: String,
    tolerance: u16,
}

#[derive(Serialize)]
struct SimpleOutbound {
    #[serde(rename = "type")]
    kind: &'static str,
    tag: &'static str,
}

#[derive(Serialize)]
struct Tls<'a> {
    enabled: bool,
    server_name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    alpn: Option<&'a [String]>,
    utls: Utls,
    #[serde(skip_serializing_if = "Option::is_none")]
    reality: Option<Reality>,
}

#[derive(Serialize)]
struct Utls {
    enabled: bool,
    fingerprint: &'static str,
}

#[derive(Serialize)]
struct Reality {
    enabled: bool,
    public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    short_id: Option<String>,
}

#[derive(Serialize)]
struct Transport<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    headers: Option<TransportHeaders<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service_name: Option<&'a str>,
}

#[derive(Serialize)]
struct TransportHeaders<'a> {
    #[serde(rename = "Host")]
    host: &'a str,
}

#[derive(Serialize)]
struct Route {
    rules: Vec<RouteRule>,
    #[serde(rename = "final")]
    final_outbound: String,
    default_domain_resolver: &'static str,
}

#[derive(Serialize)]
struct RouteRule {
    #[serde(skip_serializing_if = "Option::is_none")]
    domain: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain_suffix: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain_keyword: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    process_name: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip_cidr: Option<Vec<String>>,
    outbound: String,
}

impl RouteRule {
    const fn empty() -> Self {
        Self {
            domain: None,
            domain_suffix: None,
            domain_keyword: None,
            process_name: None,
            ip_cidr: None,
            outbound: String::new(),
        }
    }
}

impl fmt::Debug for SingboxRenderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoValidNodes => formatter.write_str("NoValidNodes"),
            Self::OutputTooLarge { limit_bytes } => formatter
                .debug_struct("OutputTooLarge")
                .field("limit_bytes", limit_bytes)
                .finish(),
            Self::Internal => formatter.write_str("Internal"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CompiledPolicyV1, CompiledRuleV1, GroupStrategyV1, PolicyMemberV1, RuleMatcherV1,
        SingboxRenderError, render_singbox_from_policy_v1,
    };
    use crate::mihomo::{MAX_MIHOMO_OUTPUT_BYTES, render_builtin_singbox_v1};
    use crate::node_name::{NamedNodeOccurrence, resolve_node_names};
    use crate::policy::{CompiledGroupV1, PolicyReportV1};
    use crate::subscription_source::parse_subscription_sources;

    const BUILTIN_TCP_VLESS: &str = concat!(
        "{\n",
        "  \"log\": {\n",
        "    \"disabled\": false,\n",
        "    \"level\": \"info\",\n",
        "    \"timestamp\": true\n",
        "  },\n",
        "  \"dns\": {\n",
        "    \"servers\": [\n",
        "      {\n",
        "        \"type\": \"local\",\n",
        "        \"tag\": \"local\"\n",
        "      }\n",
        "    ],\n",
        "    \"final\": \"local\"\n",
        "  },\n",
        "  \"inbounds\": [\n",
        "    {\n",
        "      \"type\": \"mixed\",\n",
        "      \"tag\": \"mixed-in\",\n",
        "      \"listen\": \"127.0.0.1\",\n",
        "      \"listen_port\": 2080,\n",
        "      \"set_system_proxy\": false\n",
        "    }\n",
        "  ],\n",
        "  \"outbounds\": [\n",
        "    {\n",
        "      \"type\": \"vless\",\n",
        "      \"tag\": \"Alpha\",\n",
        "      \"server\": \"example.com\",\n",
        "      \"server_port\": 443,\n",
        "      \"uuid\": \"01234567-89ab-cdef-0123-456789abcdef\"\n",
        "    },\n",
        "    {\n",
        "      \"type\": \"selector\",\n",
        "      \"tag\": \"PROXY\",\n",
        "      \"outbounds\": [\n",
        "        \"AUTO\",\n",
        "        \"Alpha\",\n",
        "        \"direct\"\n",
        "      ],\n",
        "      \"interrupt_exist_connections\": false\n",
        "    },\n",
        "    {\n",
        "      \"type\": \"urltest\",\n",
        "      \"tag\": \"AUTO\",\n",
        "      \"outbounds\": [\n",
        "        \"Alpha\"\n",
        "      ],\n",
        "      \"url\": \"https://www.gstatic.com/generate_204\",\n",
        "      \"interval\": \"300s\",\n",
        "      \"tolerance\": 50\n",
        "    },\n",
        "    {\n",
        "      \"type\": \"direct\",\n",
        "      \"tag\": \"direct\"\n",
        "    },\n",
        "    {\n",
        "      \"type\": \"block\",\n",
        "      \"tag\": \"reject\"\n",
        "    }\n",
        "  ],\n",
        "  \"route\": {\n",
        "    \"rules\": [],\n",
        "    \"final\": \"PROXY\",\n",
        "    \"default_domain_resolver\": \"local\"\n",
        "  }\n",
        "}\n",
    );

    #[test]
    fn builtin_tcp_vless_matches_the_frozen_singbox_shape() {
        let parsed = parse_subscription_sources(&[
            &b"vless://01234567-89ab-cdef-0123-456789abcdef@EXAMPLE.COM:443#Alpha"[..],
        ])
        .expect("valid");
        let output = render_builtin_singbox_v1(parsed).expect("rendered");
        assert_eq!(
            std::str::from_utf8(output.config()).expect("utf8"),
            BUILTIN_TCP_VLESS
        );
    }

    #[test]
    fn grpc_and_vision_without_reality_are_kept() {
        let source = concat!(
            "vless://00000000-0000-4000-8000-000000000003@[2001:db8::1]:9443?type=grpc&serviceName=svc%2Fprod&security=reality&sni=reality.example&fp=safari&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&sid=0a1b#Reality\n",
            "vless://00000000-0000-4000-8000-000000000004@vision.example:443?security=tls&flow=xtls-rprx-vision#Vision\n",
        );
        let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid");
        let output = render_builtin_singbox_v1(parsed).expect("rendered");
        let text = std::str::from_utf8(output.config()).expect("utf8");
        assert!(text.contains("\"tag\": \"Reality\""));
        assert!(text.contains("\"type\": \"grpc\""));
        assert!(text.contains("\"service_name\": \"svc/prod\""));
        assert!(text.contains("\"server\": \"2001:db8::1\""));
        assert!(!text.contains("[2001:db8::1]"));
        assert!(text.contains("\"tag\": \"Vision\""));
        assert!(text.contains("\"flow\": \"xtls-rprx-vision\""));
        assert!(text.contains("\"fingerprint\": \"chrome\""));
        assert!(text.contains("\"fingerprint\": \"safari\""));
    }

    #[test]
    fn websocket_tls_and_shadowsocks_project_supported_fields() {
        let source = concat!(
            "vless://01234567-89ab-cdef-0123-456789abcdef@EXAMPLE.COM:443?type=ws&path=%2Fws&host=cdn.example&security=tls&sni=edge.example&alpn=h2%2Chttp%2F1.1&fp=firefox#WS\n",
            "ss://aes-128-gcm:p%40ss%3Aword@example.com:8388#Classic\n",
        );
        let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid");
        let output = render_builtin_singbox_v1(parsed).expect("rendered");
        let text = std::str::from_utf8(output.config()).expect("utf8");
        assert!(text.contains("\"type\": \"ws\""));
        assert!(text.contains("\"path\": \"/ws\""));
        assert!(text.contains("\"Host\": \"cdn.example\""));
        assert!(text.contains("\"server_name\": \"edge.example\""));
        assert!(text.contains("\"fingerprint\": \"firefox\""));
        assert!(text.contains("\"type\": \"shadowsocks\""));
        assert!(text.contains("\"method\": \"aes-128-gcm\""));
        assert!(text.contains("\"password\": \"p@ss:word\""));
    }

    #[test]
    fn reserved_node_tags_are_skipped_and_empty_members_become_reject() {
        let parsed = parse_subscription_sources(&[
            &b"vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#direct\nvless://fedcba98-7654-3210-fedc-ba9876543210@example.net:8443#Alpha"[..],
        ])
        .expect("valid");
        let named = resolve_node_names(parsed, &["PROXY", "AUTO"]).expect("names");
        let nodes = named
            .occurrences()
            .iter()
            .filter_map(|occurrence| match occurrence {
                NamedNodeOccurrence::Accepted { node, .. } => Some(node.as_ref()),
                NamedNodeOccurrence::Rejected { .. } => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(nodes.len(), 2);
        let policy = CompiledPolicyV1::new(
            vec![CompiledGroupV1::new(
                "PROXY".to_owned(),
                GroupStrategyV1::Select,
                vec![PolicyMemberV1::Node("direct".to_owned())],
            )],
            vec![],
            PolicyReportV1::default(),
        );
        let output =
            render_singbox_from_policy_v1(&nodes, &policy, MAX_MIHOMO_OUTPUT_BYTES).expect("ok");
        let text = std::str::from_utf8(&output).expect("utf8");
        assert!(text.contains("\"tag\": \"Alpha\""));
        assert!(!text.contains("\"server\": \"example.com\""));
        assert!(text.contains("\"outbounds\": [\n        \"reject\"\n      ]"));
    }

    #[test]
    fn only_reserved_node_tags_are_no_valid_nodes() {
        let parsed = parse_subscription_sources(&[
            &b"vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#reject"[..],
        ])
        .expect("valid");
        let named = resolve_node_names(parsed, &["PROXY", "AUTO"]).expect("names");
        let nodes = named
            .occurrences()
            .iter()
            .filter_map(|occurrence| match occurrence {
                NamedNodeOccurrence::Accepted { node, .. } => Some(node.as_ref()),
                NamedNodeOccurrence::Rejected { .. } => None,
            })
            .collect::<Vec<_>>();
        let policy = CompiledPolicyV1::new(vec![], vec![], PolicyReportV1::default());
        let error = render_singbox_from_policy_v1(&nodes, &policy, MAX_MIHOMO_OUTPUT_BYTES)
            .expect_err("no valid nodes");
        assert!(matches!(error, SingboxRenderError::NoValidNodes));
    }

    #[test]
    fn fallback_and_load_balance_are_normalized_and_geoip_cn_is_omitted() {
        let parsed = parse_subscription_sources(&[
            &b"vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha"[..],
        ])
        .expect("valid");
        let named = resolve_node_names(parsed, &["Fallback", "Hash"]).expect("names");
        let nodes = named
            .occurrences()
            .iter()
            .filter_map(|occurrence| match occurrence {
                NamedNodeOccurrence::Accepted { node, .. } => Some(node.as_ref()),
                NamedNodeOccurrence::Rejected { .. } => None,
            })
            .collect::<Vec<_>>();
        let policy = CompiledPolicyV1::new(
            vec![
                CompiledGroupV1::new(
                    "Fallback".to_owned(),
                    GroupStrategyV1::Fallback {
                        url: "https://www.gstatic.com/generate_204".to_owned(),
                        interval: 60,
                    },
                    vec![PolicyMemberV1::Node("Alpha".to_owned())],
                ),
                CompiledGroupV1::new(
                    "Hash".to_owned(),
                    GroupStrategyV1::LoadBalance {
                        url: String::new(),
                        interval: 30,
                    },
                    vec![PolicyMemberV1::Node("Alpha".to_owned())],
                ),
            ],
            vec![
                CompiledRuleV1::new(RuleMatcherV1::GeoIpCn, PolicyMemberV1::Direct),
                CompiledRuleV1::new(
                    RuleMatcherV1::DomainSuffix("example.com".to_owned()),
                    PolicyMemberV1::Group("Fallback".to_owned()),
                ),
                CompiledRuleV1::new(
                    RuleMatcherV1::Match,
                    PolicyMemberV1::Group("Fallback".to_owned()),
                ),
            ],
            PolicyReportV1::default(),
        );
        let omitted = policy
            .rules()
            .iter()
            .filter(|rule| matches!(rule.matcher(), RuleMatcherV1::GeoIpCn))
            .count();
        assert_eq!(omitted, 1);
        let output =
            render_singbox_from_policy_v1(&nodes, &policy, MAX_MIHOMO_OUTPUT_BYTES).expect("ok");
        let text = std::str::from_utf8(&output).expect("utf8");
        assert!(text.contains("\"type\": \"urltest\""));
        assert!(text.contains("\"tag\": \"Fallback\""));
        assert!(text.contains("\"interval\": \"60s\""));
        assert!(text.contains("\"type\": \"selector\""));
        assert!(text.contains("\"tag\": \"Hash\""));
        assert!(!text.contains("geoip"));
        assert!(text.contains("\"domain_suffix\""));
        assert!(text.contains("example.com"));
        assert!(text.contains("\"final\": \"Fallback\""));
        assert!(!text.contains("\"outbound\": \"direct\""));
        assert_eq!(text.matches("\"outbound\":").count(), 1);
    }

    #[test]
    fn group_named_direct_is_internal() {
        let parsed = parse_subscription_sources(&[
            &b"vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha"[..],
        ])
        .expect("valid");
        let named = resolve_node_names(parsed, &["direct"]).expect("names");
        let nodes = named
            .occurrences()
            .iter()
            .filter_map(|occurrence| match occurrence {
                NamedNodeOccurrence::Accepted { node, .. } => Some(node.as_ref()),
                NamedNodeOccurrence::Rejected { .. } => None,
            })
            .collect::<Vec<_>>();
        let policy = CompiledPolicyV1::new(
            vec![CompiledGroupV1::new(
                "direct".to_owned(),
                GroupStrategyV1::Select,
                vec![PolicyMemberV1::Node("Alpha".to_owned())],
            )],
            vec![],
            PolicyReportV1::default(),
        );
        let error = render_singbox_from_policy_v1(&nodes, &policy, MAX_MIHOMO_OUTPUT_BYTES)
            .expect_err("reserved group");
        assert!(matches!(error, SingboxRenderError::Internal));
    }

    #[test]
    fn oversized_output_is_rejected() {
        let parsed = parse_subscription_sources(&[
            &b"vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha"[..],
        ])
        .expect("valid");
        let named = resolve_node_names(parsed, &["PROXY", "AUTO"]).expect("names");
        let nodes = named
            .occurrences()
            .iter()
            .filter_map(|occurrence| match occurrence {
                NamedNodeOccurrence::Accepted { node, .. } => Some(node.as_ref()),
                NamedNodeOccurrence::Rejected { .. } => None,
            })
            .collect::<Vec<_>>();
        let policy = crate::policy::compile_builtin_policy_v1(&nodes);
        let error = render_singbox_from_policy_v1(&nodes, &policy, 8).expect_err("limit");
        assert!(matches!(
            error,
            SingboxRenderError::OutputTooLarge { limit_bytes: 8 }
        ));
    }

    #[test]
    fn debug_output_does_not_retain_node_names() {
        let parsed = parse_subscription_sources(&[
            &b"vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#SecretCanary"[..],
        ])
        .expect("valid");
        let output = render_builtin_singbox_v1(parsed).expect("rendered");
        let debug = format!("{output:?}");
        assert!(!debug.contains("SecretCanary"));
        assert!(!debug.contains("gstatic"));
        let error_debug = format!(
            "{:?}",
            SingboxRenderError::OutputTooLarge { limit_bytes: 4 }
        );
        assert!(!error_debug.contains("SecretCanary"));
    }
}
