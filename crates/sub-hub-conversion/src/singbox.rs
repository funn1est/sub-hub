use std::borrow::Cow;

use serde::Serialize;

use crate::{
    node::shadowsocks::{ShadowsocksCipher, ShadowsocksCredential},
    node::trojan::TrojanSecurity,
    node::vless::{ClientFingerprint, RealityOptions, VlessFlow, VlessSecurity, VlessTransport},
    node::vmess::VmessSecurity,
    node::{NodeProtocol, ProxyNode},
    policy::{CompiledPolicyV1, CompiledRuleV1, GroupStrategyV1, PolicyMemberV1, RuleMatcherV1},
    render::{
        AdapterRenderError, KeptNodes, NodeKeep, RenderedTargetV1, plain_group_tag, plain_node_tag,
        policy_member_token, probe_url_or_default, reality_public_key_base64, reality_short_id_hex,
        reject_when_empty, render_fingerprint, render_host_plain, shadowsocks_method,
        shadowsocks_password,
    },
};

const DEFAULT_URLTEST_TOLERANCE_MS: u16 = 50;

pub(crate) fn render_singbox_from_policy_v1(
    named_nodes: &[&ProxyNode],
    policy: &CompiledPolicyV1,
    limit_bytes: usize,
) -> Result<RenderedTargetV1, AdapterRenderError> {
    let (kept, encoded) = KeptNodes::encode(named_nodes, encode_node)?;
    let mut valid_tags = Vec::with_capacity(encoded.len());
    let mut node_outbounds = Vec::with_capacity(encoded.len());
    for (tag, outbound) in encoded {
        valid_tags.push(tag);
        node_outbounds.push(outbound);
    }

    let valid = valid_tags.iter().map(String::as_str).collect::<Vec<_>>();
    let group_outbounds = render_groups(policy, &valid)?;
    let first_group = policy
        .groups()
        .first()
        .ok_or(AdapterRenderError::Internal)?;
    let final_tag = plain_group_tag(first_group.name())?.to_owned();

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

    let (route_rules, omitted_url_regex) = render_rules(policy.rules(), &valid)?;
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
            rules: route_rules,
            final_outbound: final_tag,
            default_domain_resolver: "local",
        },
    };
    let bytes = serialize_pretty(&document, limit_bytes)?;
    Ok(RenderedTargetV1::from_parts(
        bytes,
        &kept,
        omitted_url_regex,
    ))
}

fn encode_node(node: &ProxyNode) -> Result<(String, Outbound<'_>), NodeKeep> {
    let Some(tag) = plain_node_tag(node.name().as_str()) else {
        return Err(NodeKeep::Name);
    };
    let Some(outbound) = node_outbound(node, tag) else {
        return Err(NodeKeep::Capability);
    };
    Ok((tag.to_owned(), outbound))
}

fn node_outbound<'a>(node: &'a ProxyNode, tag: &'a str) -> Option<Outbound<'a>> {
    Some(match node.protocol() {
        NodeProtocol::Vless(vless) => Outbound::Vless(vless_outbound(node, vless, tag)),
        NodeProtocol::Shadowsocks(shadowsocks) => Outbound::Shadowsocks(shadowsocks_outbound(
            node,
            shadowsocks.cipher(),
            shadowsocks.credential(),
            tag,
        )),
        NodeProtocol::Trojan(trojan) => Outbound::Trojan(trojan_outbound(node, trojan, tag)),
        NodeProtocol::Vmess(vmess) => Outbound::Vmess(vmess_outbound(node, vmess, tag)),
        NodeProtocol::Hysteria2(hysteria2) => {
            Outbound::Hysteria2(hysteria2_outbound(node, hysteria2, tag)?)
        }
        NodeProtocol::Tuic(tuic) => Outbound::Tuic(tuic_outbound(node, tuic, tag)),
    })
}

fn tuic_outbound<'a>(
    node: &'a ProxyNode,
    tuic: &'a crate::node::tuic::TuicNode,
    tag: &'a str,
) -> TuicOutbound<'a> {
    TuicOutbound {
        kind: "tuic",
        tag,
        server: render_host_plain(node.endpoint().host()),
        server_port: node.endpoint().port().get(),
        uuid: tuic.id().as_uuid().hyphenated().to_string(),
        password: tuic.password().expose(),
        congestion_control: (!tuic.congestion().is_default()).then(|| tuic.congestion().as_token()),
        udp_relay_mode: (!tuic.udp_relay().is_default()).then(|| tuic.udp_relay().as_token()),
        tls: TuicTls {
            enabled: true,
            server_name: tuic.sni(),
            alpn: tuic.alpn(),
        },
    }
}

fn hysteria2_outbound<'a>(
    node: &'a ProxyNode,
    hysteria2: &'a crate::node::hysteria2::Hysteria2Node,
    tag: &'a str,
) -> Option<Hysteria2Outbound<'a>> {
    if hysteria2.pin_sha256().is_some()
        || hysteria2
            .obfs()
            .is_some_and(crate::node::hysteria2::Hysteria2Obfs::is_gecko)
    {
        return None;
    }
    let (server_port, server_ports) = if hysteria2.ports().is_hop() {
        (None, Some(hysteria2.ports().render_singbox()))
    } else {
        (Some(node.endpoint().port().get()), None)
    };
    let obfs = hysteria2.obfs().map(|obfs| Hysteria2ObfsObject {
        kind: obfs.token(),
        password: obfs.password(),
    });
    Some(Hysteria2Outbound {
        kind: "hysteria2",
        tag,
        server: render_host_plain(node.endpoint().host()),
        server_port,
        server_ports,
        password: hysteria2.auth().expose(),
        obfs,
        tls: Hysteria2Tls {
            enabled: true,
            server_name: hysteria2.sni(),
        },
    })
}

/// Maps the shared VLESS-shaped transport onto the sing-box `transport` object;
/// plain TCP omits the object entirely.
fn stream_transport(transport: &VlessTransport) -> Option<Transport<'_>> {
    match transport {
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
    }
}

fn vmess_outbound<'a>(
    node: &'a ProxyNode,
    vmess: &'a crate::node::vmess::VmessNode,
    tag: &'a str,
) -> VmessOutbound<'a> {
    let transport = stream_transport(vmess.transport());
    let tls = match vmess.security() {
        VmessSecurity::None => None,
        VmessSecurity::Tls(options) => Some(tls_object(
            options.server_name(),
            options.alpn(),
            options.fingerprint(),
            None,
        )),
    };
    VmessOutbound {
        kind: "vmess",
        tag,
        server: render_host_plain(node.endpoint().host()),
        server_port: node.endpoint().port().get(),
        uuid: vmess.id().as_uuid().hyphenated().to_string(),
        security: vmess.cipher().as_token(),
        alter_id: 0,
        tls,
        transport,
    }
}

fn trojan_outbound<'a>(
    node: &'a ProxyNode,
    trojan: &'a crate::node::trojan::TrojanNode,
    tag: &'a str,
) -> TrojanOutbound<'a> {
    let transport = stream_transport(trojan.transport());
    let tls_options = trojan.security().tls_options();
    let reality = match trojan.security() {
        TrojanSecurity::Tls(_) => None,
        TrojanSecurity::Reality(options) => Some(Reality::from_options(options)),
    };
    TrojanOutbound {
        kind: "trojan",
        tag,
        server: render_host_plain(node.endpoint().host()),
        server_port: node.endpoint().port().get(),
        password: trojan.password().expose(),
        tls: tls_object(
            tls_options.server_name(),
            tls_options.alpn(),
            tls_options.fingerprint(),
            reality,
        ),
        transport,
    }
}

fn vless_outbound<'a>(
    node: &'a ProxyNode,
    vless: &'a crate::node::vless::VlessNode,
    tag: &'a str,
) -> VlessOutbound<'a> {
    let transport = stream_transport(vless.transport());
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
            Some(Reality::from_options(options)),
        )),
    };
    VlessOutbound {
        kind: "vless",
        tag,
        server: render_host_plain(node.endpoint().host()),
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
    ShadowsocksOutbound {
        kind: "shadowsocks",
        tag,
        server: render_host_plain(node.endpoint().host()),
        server_port: node.endpoint().port().get(),
        method: shadowsocks_method(cipher),
        password: shadowsocks_password(credential),
    }
}

fn member_tag(
    member: &PolicyMemberV1,
    valid_nodes: &[&str],
) -> Result<Option<String>, AdapterRenderError> {
    policy_member_token(
        member,
        "direct",
        "reject",
        |name| plain_group_tag(name).map(|tag| Some(tag.to_owned())),
        valid_nodes,
    )
}

fn render_groups(
    policy: &CompiledPolicyV1,
    valid_nodes: &[&str],
) -> Result<Vec<Outbound<'static>>, AdapterRenderError> {
    let mut outbounds = Vec::new();
    for group in policy.groups() {
        let tag = plain_group_tag(group.name())?.to_owned();
        let mut members = Vec::new();
        for member in group.members() {
            if let Some(token) = member_tag(member, valid_nodes)? {
                members.push(token);
            }
        }
        reject_when_empty(&mut members, "reject");
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
        url: probe_url_or_default(url).to_owned(),
        interval: format!("{interval}s"),
        tolerance: tolerance.unwrap_or(DEFAULT_URLTEST_TOLERANCE_MS),
    }
}

fn render_rules(
    rules: &[CompiledRuleV1],
    valid_nodes: &[&str],
) -> Result<(Vec<RouteRule>, u8), AdapterRenderError> {
    let mut rendered = Vec::new();
    let mut omitted_url_regex = 0_u8;
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
            RuleMatcherV1::UrlRegex(_) => {
                omitted_url_regex = omitted_url_regex.saturating_add(1);
                continue;
            }
            RuleMatcherV1::GeoIpCn | RuleMatcherV1::Match => continue,
        };
        rendered.push(route);
    }
    Ok((rendered, omitted_url_regex))
}

fn serialize_pretty(
    document: &Document<'_>,
    limit_bytes: usize,
) -> Result<Vec<u8>, AdapterRenderError> {
    let mut body = serde_json::to_vec_pretty(document).map_err(|_| AdapterRenderError::Internal)?;
    body.push(b'\n');
    if body.len() > limit_bytes {
        return Err(AdapterRenderError::OutputTooLarge { limit_bytes });
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
    Trojan(TrojanOutbound<'a>),
    Vmess(VmessOutbound<'a>),
    Hysteria2(Hysteria2Outbound<'a>),
    Tuic(TuicOutbound<'a>),
    Selector(SelectorOutbound),
    Urltest(UrltestOutbound),
    Simple(SimpleOutbound),
}

#[derive(Serialize)]
struct Hysteria2Outbound<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    tag: &'a str,
    server: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    server_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    server_ports: Option<Vec<String>>,
    password: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    obfs: Option<Hysteria2ObfsObject<'a>>,
    tls: Hysteria2Tls<'a>,
}

#[derive(Serialize)]
struct Hysteria2ObfsObject<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    password: &'a str,
}

#[derive(Serialize)]
struct Hysteria2Tls<'a> {
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    server_name: Option<&'a str>,
}

#[derive(Serialize)]
struct TuicOutbound<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    tag: &'a str,
    server: String,
    server_port: u16,
    uuid: String,
    password: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    congestion_control: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    udp_relay_mode: Option<&'static str>,
    tls: TuicTls<'a>,
}

#[derive(Serialize)]
struct TuicTls<'a> {
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    server_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alpn: Option<&'a [String]>,
}

#[derive(Serialize)]
struct VmessOutbound<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    tag: &'a str,
    server: String,
    server_port: u16,
    uuid: String,
    security: &'static str,
    alter_id: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls: Option<Tls<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transport: Option<Transport<'a>>,
}

#[derive(Serialize)]
struct TrojanOutbound<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    tag: &'a str,
    server: String,
    server_port: u16,
    password: &'a str,
    tls: Tls<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    transport: Option<Transport<'a>>,
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

impl Reality {
    fn from_options(options: &RealityOptions) -> Self {
        Self {
            enabled: true,
            public_key: reality_public_key_base64(options),
            short_id: reality_short_id_hex(options),
        }
    }
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

#[cfg(test)]
mod tests;
