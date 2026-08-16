use std::fmt;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::Serialize;

use crate::{
    mihomo::{BuiltinMihomoError, serialize_bounded},
    node::shadowsocks::{ShadowsocksCipher, ShadowsocksCredential},
    node::vless::{VlessFlow, VlessSecurity, VlessTransport},
    node::{Host, NodeProtocol, ProxyNode},
    policy::{
        BUILTIN_AUTO_PROBE_URL, CompiledPolicyV1, CompiledRuleV1, GroupStrategyV1, IpVersion,
        PolicyMemberV1, RuleMatcherV1,
    },
};

pub(crate) enum EgernRenderError {
    NoValidNodes,
    OutputTooLarge { limit_bytes: usize },
    Internal,
}

pub(crate) fn render_egern_from_policy_v1(
    named_nodes: &[&ProxyNode],
    policy: &CompiledPolicyV1,
    limit_bytes: usize,
) -> Result<Vec<u8>, EgernRenderError> {
    let mut proxies = Vec::new();
    let mut valid_tags = Vec::new();
    for node in named_nodes {
        let Some(tag) = egern_node_tag(node.name().as_str()) else {
            continue;
        };
        let Some(entry) = proxy_entry(node, tag) else {
            continue;
        };
        valid_tags.push(tag.to_owned());
        proxies.push(entry);
    }
    if proxies.is_empty() {
        return Err(EgernRenderError::NoValidNodes);
    }

    let valid = valid_tags.iter().map(String::as_str).collect::<Vec<_>>();
    let policy_groups = render_groups(policy, &valid)?;
    let rules = render_rules(policy.rules(), &valid)?;
    let document = Document {
        proxy_latency_test_url: shared_health_url(policy).map(str::to_owned),
        proxies,
        policy_groups,
        rules,
    };
    let mut body = serialize_bounded(&document, limit_bytes).map_err(|error| match error {
        BuiltinMihomoError::OutputTooLarge { limit_bytes } => {
            EgernRenderError::OutputTooLarge { limit_bytes }
        }
        BuiltinMihomoError::NodeNaming(_)
        | BuiltinMihomoError::NoValidNodes { .. }
        | BuiltinMihomoError::Serialization => EgernRenderError::Internal,
    })?;
    if !body.ends_with(b"\n") {
        if body.len() == limit_bytes {
            return Err(EgernRenderError::OutputTooLarge { limit_bytes });
        }
        body.push(b'\n');
    }
    Ok(body)
}

fn egern_node_tag(name: &str) -> Option<&str> {
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

fn egern_group_tag(name: &str) -> Result<&str, EgernRenderError> {
    if name.is_empty() || name.chars().any(|character| character.is_ascii_control()) {
        return Err(EgernRenderError::Internal);
    }
    if name.eq_ignore_ascii_case("direct") || name.eq_ignore_ascii_case("reject") {
        return Err(EgernRenderError::Internal);
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

fn proxy_entry(node: &ProxyNode, tag: &str) -> Option<ProxyEntry> {
    match node.protocol() {
        NodeProtocol::Vless(vless) => Some(ProxyEntry {
            vless: Some(Box::new(vless_proxy(node, vless, tag)?)),
            shadowsocks: None,
        }),
        NodeProtocol::Shadowsocks(shadowsocks) => Some(ProxyEntry {
            vless: None,
            shadowsocks: Some(ShadowsocksProxy {
                name: tag.to_owned(),
                method: shadowsocks_method(shadowsocks.cipher()),
                password: match shadowsocks.credential() {
                    ShadowsocksCredential::Password(password) => password.expose().to_owned(),
                    ShadowsocksCredential::Psk(psk) => STANDARD.encode(psk.expose()),
                },
                server: render_host(node.endpoint().host()),
                port: node.endpoint().port().get(),
                tfo: false,
                udp_relay: true,
            }),
        }),
    }
}

fn vless_proxy(
    node: &ProxyNode,
    vless: &crate::node::vless::VlessNode,
    tag: &str,
) -> Option<VlessProxy> {
    if matches!(
        (vless.transport(), vless.security()),
        (VlessTransport::WebSocket { .. }, VlessSecurity::Reality(_))
    ) {
        return None;
    }
    Some(VlessProxy {
        name: tag.to_owned(),
        server: render_host(node.endpoint().host()),
        port: node.endpoint().port().get(),
        user_id: vless.id().as_uuid().hyphenated().to_string(),
        flow: vless.flow().map(|flow| match flow {
            VlessFlow::Vision => "xtls-rprx-vision",
        }),
        tfo: false,
        udp_relay: true,
        transport: vless_transport(vless),
    })
}

fn vless_transport(vless: &crate::node::vless::VlessNode) -> Option<Transport> {
    let tls = tls_block(vless.security());
    match vless.transport() {
        VlessTransport::Tcp => tls.map(|tls| Transport {
            tls: Some(tls),
            ..Transport::empty()
        }),
        VlessTransport::WebSocket { path, host } => {
            let headers = host.as_deref().map(|host| WsHeaders {
                host: host.to_owned(),
            });
            match vless.security() {
                VlessSecurity::None => Some(Transport {
                    ws: Some(WsTransport {
                        path: path.clone(),
                        headers,
                    }),
                    ..Transport::empty()
                }),
                VlessSecurity::Tls(options) => Some(Transport {
                    wss: Some(WssTransport {
                        path: path.clone(),
                        headers,
                        sni: Some(options.server_name().to_owned()),
                        skip_tls_verify: Some(false),
                    }),
                    ..Transport::empty()
                }),
                VlessSecurity::Reality(_) => None,
            }
        }
        VlessTransport::Grpc { service_name, .. } => Some(Transport {
            grpc: Some(GrpcTransport {
                service_name: service_name.clone(),
                sni: tls.as_ref().and_then(|block| block.sni.clone()),
                skip_tls_verify: matches!(vless.security(), VlessSecurity::Tls(_)).then_some(false),
                reality: tls.and_then(|block| block.reality),
            }),
            ..Transport::empty()
        }),
    }
}

fn tls_block(security: &VlessSecurity) -> Option<TlsTransport> {
    match security {
        VlessSecurity::None => None,
        VlessSecurity::Tls(options) => Some(TlsTransport {
            sni: Some(options.server_name().to_owned()),
            skip_tls_verify: Some(false),
            reality: None,
        }),
        VlessSecurity::Reality(options) => Some(TlsTransport {
            sni: Some(options.tls().server_name().to_owned()),
            skip_tls_verify: None,
            reality: Some(Reality {
                public_key: URL_SAFE_NO_PAD.encode(options.public_key().as_bytes()),
                short_id: options
                    .short_id()
                    .map(|short_id| encode_hex(short_id.as_bytes())),
            }),
        }),
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

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn member_token(
    member: &PolicyMemberV1,
    valid_nodes: &[&str],
) -> Result<Option<String>, EgernRenderError> {
    match member {
        PolicyMemberV1::Direct => Ok(Some("DIRECT".to_owned())),
        PolicyMemberV1::Reject => Ok(Some("REJECT".to_owned())),
        PolicyMemberV1::Group(name) => egern_group_tag(name).map(|tag| Some(tag.to_owned())),
        PolicyMemberV1::Node(name) => Ok(valid_nodes
            .iter()
            .any(|candidate| *candidate == name)
            .then(|| name.clone())),
    }
}

fn render_groups(
    policy: &CompiledPolicyV1,
    valid_nodes: &[&str],
) -> Result<Vec<GroupEntry>, EgernRenderError> {
    let mut groups = Vec::new();
    for group in policy.groups() {
        let name = egern_group_tag(group.name())?.to_owned();
        let mut policies = Vec::new();
        for member in group.members() {
            if let Some(token) = member_token(member, valid_nodes)? {
                policies.push(token);
            }
        }
        if policies.is_empty() {
            policies.push("REJECT".to_owned());
        }
        groups.push(match group.strategy() {
            GroupStrategyV1::Select => GroupEntry {
                select: Some(SelectGroup { name, policies }),
                auto_test: None,
                fallback: None,
                load_balance: None,
            },
            GroupStrategyV1::UrlTest {
                url,
                interval,
                tolerance,
            } => GroupEntry {
                select: None,
                auto_test: Some(AutoTestGroup {
                    name,
                    policies,
                    interval: *interval,
                    tolerance: *tolerance,
                    latency_test_url: health_url(url).to_owned(),
                }),
                fallback: None,
                load_balance: None,
            },
            GroupStrategyV1::Fallback { url, interval } => GroupEntry {
                select: None,
                auto_test: None,
                fallback: Some(FallbackGroup {
                    name,
                    policies,
                    interval: *interval,
                    latency_test_url: health_url(url).to_owned(),
                }),
                load_balance: None,
            },
            GroupStrategyV1::LoadBalance { url, interval } => GroupEntry {
                select: None,
                auto_test: None,
                fallback: None,
                load_balance: Some(LoadBalanceGroup {
                    name,
                    policies,
                    algorithm: "hash",
                    interval: *interval,
                    latency_test_url: health_url(url).to_owned(),
                }),
            },
        });
    }
    Ok(groups)
}

fn health_url(url: &str) -> &str {
    if url.is_empty() {
        BUILTIN_AUTO_PROBE_URL
    } else {
        url
    }
}

fn shared_health_url(policy: &CompiledPolicyV1) -> Option<&str> {
    let mut urls = Vec::new();
    for group in policy.groups() {
        let url = match group.strategy() {
            GroupStrategyV1::UrlTest { url, .. }
            | GroupStrategyV1::Fallback { url, .. }
            | GroupStrategyV1::LoadBalance { url, .. } => health_url(url),
            GroupStrategyV1::Select => continue,
        };
        if urls.iter().all(|seen: &&str| *seen != url) {
            urls.push(url);
        }
    }
    (urls.len() == 1).then_some(urls[0])
}

fn render_rules(
    rules: &[CompiledRuleV1],
    valid_nodes: &[&str],
) -> Result<Vec<RuleEntry>, EgernRenderError> {
    let mut rendered = Vec::new();
    for rule in rules {
        let Some(policy) = member_token(rule.target(), valid_nodes)? else {
            continue;
        };
        let entry = match rule.matcher() {
            RuleMatcherV1::Domain(value) => RuleEntry::domain(MatchPolicy {
                match_value: value.clone(),
                policy,
                no_resolve: None,
            }),
            RuleMatcherV1::DomainSuffix(value) => RuleEntry::domain_suffix(MatchPolicy {
                match_value: value.clone(),
                policy,
                no_resolve: None,
            }),
            RuleMatcherV1::DomainKeyword(value) => RuleEntry::domain_keyword(MatchPolicy {
                match_value: value.clone(),
                policy,
                no_resolve: None,
            }),
            RuleMatcherV1::IpCidr {
                value,
                version,
                no_resolve,
            } => {
                let body = MatchPolicy {
                    match_value: value.clone(),
                    policy,
                    no_resolve: no_resolve.then_some(true),
                };
                match version {
                    IpVersion::V4 => RuleEntry::ip_cidr(body),
                    IpVersion::V6 => RuleEntry::ip_cidr6(body),
                }
            }
            RuleMatcherV1::GeoIpCn => RuleEntry::geoip(MatchPolicy {
                match_value: "CN".to_owned(),
                policy,
                no_resolve: None,
            }),
            RuleMatcherV1::Match => RuleEntry::default_policy(policy),
            RuleMatcherV1::ProcessName(_) => continue,
        };
        rendered.push(entry);
    }
    Ok(rendered)
}

#[derive(Serialize)]
struct Document {
    #[serde(skip_serializing_if = "Option::is_none")]
    proxy_latency_test_url: Option<String>,
    proxies: Vec<ProxyEntry>,
    policy_groups: Vec<GroupEntry>,
    rules: Vec<RuleEntry>,
}

#[derive(Serialize)]
struct ProxyEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    vless: Option<Box<VlessProxy>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shadowsocks: Option<ShadowsocksProxy>,
}

#[derive(Serialize)]
struct VlessProxy {
    name: String,
    server: String,
    port: u16,
    user_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    flow: Option<&'static str>,
    tfo: bool,
    udp_relay: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    transport: Option<Transport>,
}

#[derive(Serialize)]
struct ShadowsocksProxy {
    name: String,
    method: &'static str,
    password: String,
    server: String,
    port: u16,
    tfo: bool,
    udp_relay: bool,
}

#[derive(Serialize)]
struct Transport {
    #[serde(skip_serializing_if = "Option::is_none")]
    tls: Option<TlsTransport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ws: Option<WsTransport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wss: Option<WssTransport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grpc: Option<GrpcTransport>,
}

impl Transport {
    const fn empty() -> Self {
        Self {
            tls: None,
            ws: None,
            wss: None,
            grpc: None,
        }
    }
}

#[derive(Serialize)]
struct TlsTransport {
    #[serde(skip_serializing_if = "Option::is_none")]
    sni: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    skip_tls_verify: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reality: Option<Reality>,
}

#[derive(Serialize)]
struct Reality {
    public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    short_id: Option<String>,
}

#[derive(Serialize)]
struct WsTransport {
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    headers: Option<WsHeaders>,
}

#[derive(Serialize)]
struct WssTransport {
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    headers: Option<WsHeaders>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sni: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    skip_tls_verify: Option<bool>,
}

#[derive(Serialize)]
struct WsHeaders {
    #[serde(rename = "Host")]
    host: String,
}

#[derive(Serialize)]
struct GrpcTransport {
    #[serde(skip_serializing_if = "Option::is_none")]
    service_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sni: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    skip_tls_verify: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reality: Option<Reality>,
}

#[derive(Serialize)]
struct GroupEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    select: Option<SelectGroup>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auto_test: Option<AutoTestGroup>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fallback: Option<FallbackGroup>,
    #[serde(skip_serializing_if = "Option::is_none")]
    load_balance: Option<LoadBalanceGroup>,
}

#[derive(Serialize)]
struct SelectGroup {
    name: String,
    policies: Vec<String>,
}

#[derive(Serialize)]
struct AutoTestGroup {
    name: String,
    policies: Vec<String>,
    interval: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    tolerance: Option<u16>,
    latency_test_url: String,
}

#[derive(Serialize)]
struct FallbackGroup {
    name: String,
    policies: Vec<String>,
    interval: u32,
    latency_test_url: String,
}

#[derive(Serialize)]
struct LoadBalanceGroup {
    name: String,
    policies: Vec<String>,
    algorithm: &'static str,
    interval: u32,
    latency_test_url: String,
}

#[derive(Serialize)]
struct RuleEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    domain: Option<MatchPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain_suffix: Option<MatchPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain_keyword: Option<MatchPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip_cidr: Option<MatchPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ip_cidr6: Option<MatchPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    geoip: Option<MatchPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    default: Option<DefaultRule>,
}

#[derive(Serialize)]
struct DefaultRule {
    policy: String,
}

impl RuleEntry {
    fn empty() -> Self {
        Self {
            domain: None,
            domain_suffix: None,
            domain_keyword: None,
            ip_cidr: None,
            ip_cidr6: None,
            geoip: None,
            default: None,
        }
    }

    fn domain(body: MatchPolicy) -> Self {
        Self {
            domain: Some(body),
            ..Self::empty()
        }
    }

    fn domain_suffix(body: MatchPolicy) -> Self {
        Self {
            domain_suffix: Some(body),
            ..Self::empty()
        }
    }

    fn domain_keyword(body: MatchPolicy) -> Self {
        Self {
            domain_keyword: Some(body),
            ..Self::empty()
        }
    }

    fn ip_cidr(body: MatchPolicy) -> Self {
        Self {
            ip_cidr: Some(body),
            ..Self::empty()
        }
    }

    fn ip_cidr6(body: MatchPolicy) -> Self {
        Self {
            ip_cidr6: Some(body),
            ..Self::empty()
        }
    }

    fn geoip(body: MatchPolicy) -> Self {
        Self {
            geoip: Some(body),
            ..Self::empty()
        }
    }

    fn default_policy(policy: String) -> Self {
        Self {
            default: Some(DefaultRule { policy }),
            ..Self::empty()
        }
    }
}

#[derive(Serialize)]
struct MatchPolicy {
    #[serde(rename = "match")]
    match_value: String,
    policy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    no_resolve: Option<bool>,
}

impl fmt::Debug for EgernRenderError {
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
        CompiledPolicyV1, CompiledRuleV1, EgernRenderError, GroupStrategyV1, PolicyMemberV1,
        RuleMatcherV1, render_egern_from_policy_v1,
    };
    use crate::mihomo::{MAX_MIHOMO_OUTPUT_BYTES, render_builtin_egern_v1};
    use crate::node_name::{NamedNodeOccurrence, resolve_node_names};
    use crate::policy::{CompiledGroupV1, IpVersion, PolicyReportV1, compile_builtin_policy_v1};
    use crate::subscription_source::parse_subscription_sources;

    #[test]
    fn builtin_tcp_vless_matches_the_frozen_egern_shape() {
        let parsed = parse_subscription_sources(&[
            &b"vless://01234567-89ab-cdef-0123-456789abcdef@EXAMPLE.COM:443#Alpha"[..],
        ])
        .expect("valid");
        let output = render_builtin_egern_v1(parsed).expect("rendered");
        assert_eq!(
            std::str::from_utf8(output.config()).expect("utf8"),
            concat!(
                "proxy_latency_test_url: https://www.gstatic.com/generate_204\n",
                "proxies:\n",
                "- vless:\n",
                "    name: Alpha\n",
                "    server: example.com\n",
                "    port: 443\n",
                "    user_id: 01234567-89ab-cdef-0123-456789abcdef\n",
                "    tfo: false\n",
                "    udp_relay: true\n",
                "policy_groups:\n",
                "- select:\n",
                "    name: PROXY\n",
                "    policies:\n",
                "    - AUTO\n",
                "    - Alpha\n",
                "    - DIRECT\n",
                "- auto_test:\n",
                "    name: AUTO\n",
                "    policies:\n",
                "    - Alpha\n",
                "    interval: 300\n",
                "    latency_test_url: https://www.gstatic.com/generate_204\n",
                "rules:\n",
                "- default:\n",
                "    policy: PROXY\n",
            )
        );
    }

    #[test]
    fn websocket_reality_is_skipped_and_grpc_vision_are_kept() {
        let source = concat!(
            "vless://00000000-0000-4000-8000-000000000003@[2001:db8::1]:9443?type=grpc&serviceName=svc%2Fprod&security=reality&sni=reality.example&fp=safari&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&sid=0a1b#Grpc\n",
            "vless://00000000-0000-4000-8000-000000000004@vision.example:443?security=tls&flow=xtls-rprx-vision#Vision\n",
            "vless://00000000-0000-4000-8000-000000000005@ws.example:443?type=ws&path=%2Fws&security=reality&sni=edge.example&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8#WsReality\n",
        );
        let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid");
        let output = render_builtin_egern_v1(parsed).expect("rendered");
        let text = std::str::from_utf8(output.config()).expect("utf8");
        assert!(text.contains("name: Grpc"));
        assert!(text.contains("name: Vision"));
        assert!(text.contains("flow: xtls-rprx-vision"));
        assert!(text.contains("grpc:"));
        assert!(text.contains("service_name: svc/prod"));
        assert!(text.contains("server: 2001:db8::1"));
        assert!(!text.contains("name: WsReality"));
        assert!(!text.contains("fingerprint"));
    }

    #[test]
    fn process_name_is_omitted_and_load_balance_uses_hash() {
        let parsed = parse_subscription_sources(&[
            &b"vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha"[..],
        ])
        .expect("valid");
        let named = resolve_node_names(parsed, &["Hash"]).expect("names");
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
                "Hash".to_owned(),
                GroupStrategyV1::LoadBalance {
                    url: String::new(),
                    interval: 30,
                },
                vec![PolicyMemberV1::Node("Alpha".to_owned())],
            )],
            vec![
                CompiledRuleV1::new(
                    RuleMatcherV1::ProcessName("Telegram.exe".to_owned()),
                    PolicyMemberV1::Direct,
                ),
                CompiledRuleV1::new(
                    RuleMatcherV1::IpCidr {
                        value: "10.0.0.0/8".to_owned(),
                        version: IpVersion::V4,
                        no_resolve: true,
                    },
                    PolicyMemberV1::Direct,
                ),
                CompiledRuleV1::new(RuleMatcherV1::Match, PolicyMemberV1::Direct),
            ],
            PolicyReportV1::default(),
        );
        let omitted = policy
            .rules()
            .iter()
            .filter(|rule| matches!(rule.matcher(), RuleMatcherV1::ProcessName(_)))
            .count();
        assert_eq!(omitted, 1);
        let output =
            render_egern_from_policy_v1(&nodes, &policy, MAX_MIHOMO_OUTPUT_BYTES).expect("ok");
        let text = std::str::from_utf8(&output).expect("utf8");
        assert!(text.contains("load_balance:"));
        assert!(text.contains("algorithm: hash"));
        assert!(text.contains("ip_cidr:"));
        assert!(text.contains("no_resolve: true"));
        assert!(text.contains("default:\n    policy: DIRECT"));
        assert!(!text.contains("Telegram"));
        assert!(!text.contains("process"));
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
        let policy = compile_builtin_policy_v1(&nodes);
        let error = render_egern_from_policy_v1(&nodes, &policy, 8).expect_err("limit");
        assert!(matches!(
            error,
            EgernRenderError::OutputTooLarge { limit_bytes: 8 }
        ));
    }

    #[test]
    fn debug_output_does_not_retain_node_names() {
        let parsed = parse_subscription_sources(&[
            &b"vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#SecretCanary"[..],
        ])
        .expect("valid");
        let output = render_builtin_egern_v1(parsed).expect("rendered");
        let debug = format!("{output:?}");
        assert!(!debug.contains("SecretCanary"));
        assert!(!debug.contains("gstatic"));
    }
}
