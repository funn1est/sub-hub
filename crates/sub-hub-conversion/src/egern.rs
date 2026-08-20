use serde::Serialize;

use crate::{
    node::trojan::TrojanSecurity,
    node::vless::{RealityOptions, VlessFlow, VlessSecurity, VlessTransport},
    node::vmess::VmessSecurity,
    node::{NodeProtocol, ProxyNode},
    policy::{
        CompiledPolicyV1, CompiledRuleV1, GroupStrategyV1, IpVersion, PolicyMemberV1, RuleMatcherV1,
    },
    render::{
        AdapterRenderError, NodeKeep, RenderedTargetV1, encode_hex, hysteria2_official_ports,
        keep_named, keep_tagged, map_compiled_rules, plain_group_tag, plain_node_tag,
        policy_member_token, probe_url_or_default, reality_public_key_base64, reality_short_id_hex,
        reject_when_empty, render_host_plain, serialize_bounded, shadowsocks_method,
        shadowsocks_password, shared_probe_url,
    },
};

pub(crate) fn render_egern_from_policy_v1(
    named_nodes: &[&ProxyNode],
    policy: &CompiledPolicyV1,
    limit_bytes: usize,
) -> Result<RenderedTargetV1, AdapterRenderError> {
    let (kept, valid_tags, proxies) = keep_tagged(named_nodes, encode_node)?;
    let valid = valid_tags.iter().map(String::as_str).collect::<Vec<_>>();
    let policy_groups = render_groups(policy, &valid)?;
    let (rules, omitted_url_regex) = render_rules(policy.rules(), &valid)?;
    let document = Document {
        proxy_latency_test_url: shared_probe_url(policy).map(str::to_owned),
        proxies,
        policy_groups,
        rules,
    };
    let mut body = serialize_bounded(&document, limit_bytes)?;
    if !body.ends_with(b"\n") {
        if body.len() == limit_bytes {
            return Err(AdapterRenderError::OutputTooLarge { limit_bytes });
        }
        body.push(b'\n');
    }
    Ok(RenderedTargetV1::from_parts(body, &kept, omitted_url_regex))
}

fn encode_node(node: &ProxyNode) -> Result<(String, ProxyEntry), NodeKeep> {
    keep_named(plain_node_tag(node.name().as_str()), |tag| {
        proxy_entry(node, tag)
    })
}

fn proxy_entry(node: &ProxyNode, tag: &str) -> Option<ProxyEntry> {
    match node.protocol() {
        NodeProtocol::Vless(vless) => Some(ProxyEntry {
            vless: Some(Box::new(vless_proxy(node, vless, tag)?)),
            shadowsocks: None,
            trojan: None,
            vmess: None,
            hysteria2: None,
            tuic: None,
        }),
        NodeProtocol::Shadowsocks(shadowsocks) => Some(ProxyEntry {
            vless: None,
            shadowsocks: Some(ShadowsocksProxy {
                name: tag.to_owned(),
                method: shadowsocks_method(shadowsocks.cipher()),
                password: shadowsocks_password(shadowsocks.credential()).into_owned(),
                server: render_host_plain(node.endpoint().host()),
                port: node.endpoint().port().get(),
                tfo: false,
                udp_relay: true,
            }),
            trojan: None,
            vmess: None,
            hysteria2: None,
            tuic: None,
        }),
        NodeProtocol::Trojan(trojan) => Some(ProxyEntry {
            vless: None,
            shadowsocks: None,
            trojan: Some(trojan_proxy(node, trojan, tag)?),
            vmess: None,
            hysteria2: None,
            tuic: None,
        }),
        NodeProtocol::Vmess(vmess) => Some(ProxyEntry {
            vless: None,
            shadowsocks: None,
            trojan: None,
            vmess: Some(vmess_proxy(node, vmess, tag)?),
            hysteria2: None,
            tuic: None,
        }),
        NodeProtocol::Hysteria2(hysteria2) => Some(ProxyEntry {
            vless: None,
            shadowsocks: None,
            trojan: None,
            vmess: None,
            hysteria2: Some(hysteria2_proxy(node, hysteria2, tag)?),
            tuic: None,
        }),
        NodeProtocol::Tuic(tuic) => Some(ProxyEntry {
            vless: None,
            shadowsocks: None,
            trojan: None,
            vmess: None,
            hysteria2: None,
            tuic: Some(tuic_proxy(node, tuic, tag)?),
        }),
    }
}

fn tuic_proxy(
    node: &ProxyNode,
    tuic: &crate::node::tuic::TuicNode,
    tag: &str,
) -> Option<TuicProxy> {
    if !tuic.congestion().is_default() {
        return None;
    }
    Some(TuicProxy {
        name: tag.to_owned(),
        server: render_host_plain(node.endpoint().host()),
        port: node.endpoint().port().get(),
        uuid: tuic.id().as_uuid().hyphenated().to_string(),
        password: tuic.password().expose().to_owned(),
        udp_relay_mode: (!tuic.udp_relay().is_default()).then(|| tuic.udp_relay().as_token()),
        sni: tuic.sni().map(str::to_owned),
        alpn: tuic.alpn().map(<[String]>::to_vec),
        skip_tls_verify: false,
    })
}

fn hysteria2_proxy(
    node: &ProxyNode,
    hysteria2: &crate::node::hysteria2::Hysteria2Node,
    tag: &str,
) -> Option<Hysteria2Proxy> {
    if hysteria2
        .obfs()
        .is_some_and(crate::node::hysteria2::Hysteria2Obfs::is_gecko)
    {
        return None;
    }
    let pin = hysteria2.pin_sha256().map(|pin| encode_hex(pin));
    let (obfs, obfs_password) = match hysteria2.obfs() {
        Some(obfs) => (Some(obfs.token()), Some(obfs.password().to_owned())),
        None => (None, None),
    };
    Some(Hysteria2Proxy {
        name: tag.to_owned(),
        server: render_host_plain(node.endpoint().host()),
        port: node.endpoint().port().get(),
        auth: hysteria2.auth().expose().to_owned(),
        sni: hysteria2.sni().map(str::to_owned),
        obfs,
        obfs_password,
        skip_tls_verify: pin.is_none().then_some(false),
        fingerprint_sha256: pin,
        port_hopping: hysteria2_official_ports(hysteria2.ports()),
    })
}

fn vmess_proxy(
    node: &ProxyNode,
    vmess: &crate::node::vmess::VmessNode,
    tag: &str,
) -> Option<VmessProxy> {
    if matches!(
        (vmess.transport(), vmess.security()),
        (VlessTransport::Grpc { .. }, VmessSecurity::None)
    ) {
        return None;
    }
    Some(VmessProxy {
        name: tag.to_owned(),
        server: render_host_plain(node.endpoint().host()),
        port: node.endpoint().port().get(),
        user_id: vmess.id().as_uuid().hyphenated().to_string(),
        security: vmess.cipher().as_token(),
        legacy: false,
        tfo: false,
        udp_relay: true,
        transport: vmess_transport(vmess),
    })
}

fn vmess_transport(vmess: &crate::node::vmess::VmessNode) -> Option<Transport> {
    match vmess.transport() {
        VlessTransport::Tcp => match vmess.security() {
            VmessSecurity::None => None,
            VmessSecurity::Tls(options) => Some(Transport {
                tls: Some(TlsTransport {
                    sni: Some(options.server_name().to_owned()),
                    skip_tls_verify: Some(false),
                    reality: None,
                }),
                ..Transport::empty()
            }),
        },
        VlessTransport::WebSocket { path, host } => {
            let headers = host.as_deref().map(|host| WsHeaders {
                host: host.to_owned(),
            });
            match vmess.security() {
                VmessSecurity::None => Some(Transport {
                    ws: Some(WsTransport {
                        path: path.clone(),
                        headers,
                    }),
                    ..Transport::empty()
                }),
                VmessSecurity::Tls(options) => Some(Transport {
                    wss: Some(WssTransport {
                        path: path.clone(),
                        headers,
                        sni: Some(options.server_name().to_owned()),
                        skip_tls_verify: Some(false),
                    }),
                    ..Transport::empty()
                }),
            }
        }
        VlessTransport::Grpc { service_name, .. } => match vmess.security() {
            VmessSecurity::None => None,
            VmessSecurity::Tls(options) => Some(Transport {
                grpc: Some(GrpcTransport {
                    service_name: service_name.clone(),
                    sni: Some(options.server_name().to_owned()),
                    skip_tls_verify: Some(false),
                    reality: None,
                }),
                ..Transport::empty()
            }),
        },
    }
}

fn trojan_proxy(
    node: &ProxyNode,
    trojan: &crate::node::trojan::TrojanNode,
    tag: &str,
) -> Option<TrojanProxy> {
    if matches!(trojan.transport(), VlessTransport::Grpc { .. }) {
        return None;
    }
    let tls = trojan.security().tls_options();
    let reality = match trojan.security() {
        TrojanSecurity::Tls(_) => None,
        TrojanSecurity::Reality(options) => Some(Reality::from_options(options)),
    };
    let websocket = match trojan.transport() {
        VlessTransport::Tcp => None,
        VlessTransport::WebSocket { path, host } => Some(TrojanWebsocket {
            path: path.clone(),
            host: host.clone(),
        }),
        VlessTransport::Grpc { .. } => return None,
    };
    Some(TrojanProxy {
        name: tag.to_owned(),
        server: render_host_plain(node.endpoint().host()),
        port: node.endpoint().port().get(),
        password: trojan.password().expose().to_owned(),
        sni: tls.server_name().to_owned(),
        tfo: false,
        udp_relay: true,
        skip_tls_verify: false,
        reality,
        websocket,
    })
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
        server: render_host_plain(node.endpoint().host()),
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
            reality: Some(Reality::from_options(options)),
        }),
    }
}

fn member_token(
    member: &PolicyMemberV1,
    valid_nodes: &[&str],
) -> Result<Option<String>, AdapterRenderError> {
    policy_member_token(
        member,
        "DIRECT",
        "REJECT",
        |name| plain_group_tag(name).map(|tag| Some(tag.to_owned())),
        valid_nodes,
    )
}

fn render_groups(
    policy: &CompiledPolicyV1,
    valid_nodes: &[&str],
) -> Result<Vec<GroupEntry>, AdapterRenderError> {
    let mut groups = Vec::new();
    for group in policy.groups() {
        let name = plain_group_tag(group.name())?.to_owned();
        let mut policies = Vec::new();
        for member in group.members() {
            if let Some(token) = member_token(member, valid_nodes)? {
                policies.push(token);
            }
        }
        reject_when_empty(&mut policies, "REJECT");
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
                    latency_test_url: probe_url_or_default(url).to_owned(),
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
                    latency_test_url: probe_url_or_default(url).to_owned(),
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
                    latency_test_url: probe_url_or_default(url).to_owned(),
                }),
            },
        });
    }
    Ok(groups)
}

fn render_rules(
    rules: &[CompiledRuleV1],
    valid_nodes: &[&str],
) -> Result<(Vec<RuleEntry>, u8), AdapterRenderError> {
    map_compiled_rules(rules, |rule| {
        let Some(policy) = member_token(rule.target(), valid_nodes)? else {
            return Ok(None);
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
            RuleMatcherV1::UrlRegex(_) | RuleMatcherV1::ProcessName(_) => return Ok(None),
        };
        Ok(Some(entry))
    })
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
    #[serde(skip_serializing_if = "Option::is_none")]
    trojan: Option<TrojanProxy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vmess: Option<VmessProxy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hysteria2: Option<Hysteria2Proxy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tuic: Option<TuicProxy>,
}

#[derive(Serialize)]
struct TuicProxy {
    name: String,
    server: String,
    port: u16,
    uuid: String,
    password: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    udp_relay_mode: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sni: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alpn: Option<Vec<String>>,
    skip_tls_verify: bool,
}

#[derive(Serialize)]
struct Hysteria2Proxy {
    name: String,
    server: String,
    port: u16,
    auth: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sni: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    obfs: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    obfs_password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    skip_tls_verify: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fingerprint_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port_hopping: Option<String>,
}

#[derive(Serialize)]
struct VmessProxy {
    name: String,
    server: String,
    port: u16,
    user_id: String,
    security: &'static str,
    legacy: bool,
    tfo: bool,
    udp_relay: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    transport: Option<Transport>,
}

#[derive(Serialize)]
struct TrojanProxy {
    name: String,
    server: String,
    port: u16,
    password: String,
    sni: String,
    tfo: bool,
    udp_relay: bool,
    skip_tls_verify: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reality: Option<Reality>,
    #[serde(skip_serializing_if = "Option::is_none")]
    websocket: Option<TrojanWebsocket>,
}

#[derive(Serialize)]
struct TrojanWebsocket {
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,
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

impl Reality {
    fn from_options(options: &RealityOptions) -> Self {
        Self {
            public_key: reality_public_key_base64(options),
            short_id: reality_short_id_hex(options),
        }
    }
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

#[cfg(test)]
mod tests;
