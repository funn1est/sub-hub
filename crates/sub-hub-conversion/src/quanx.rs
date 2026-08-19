use crate::{
    node::trojan::TrojanSecurity,
    node::vless::{VlessFlow, VlessSecurity, VlessTransport},
    node::vmess::{VmessCipher, VmessSecurity},
    node::{NodeProtocol, ProxyNode},
    policy::{
        CompiledPolicyV1, CompiledRuleV1, GroupStrategyV1, IpVersion, PolicyMemberV1, RuleMatcherV1,
    },
    render::{
        AdapterRenderError, NodeKeep, RenderedTargetV1, encode_hex, policy_member_token,
        reality_public_key_base64, reality_short_id_hex, render_host_bracketed, shadowsocks_method,
        shadowsocks_password,
    },
};

pub(crate) fn render_quanx_from_policy_v1(
    named_nodes: &[&ProxyNode],
    policy: &CompiledPolicyV1,
    limit_bytes: usize,
) -> Result<RenderedTargetV1, AdapterRenderError> {
    let mut servers = Vec::new();
    let mut valid_tags = Vec::new();
    let mut capability_skips = 0_u32;
    let mut name_skips = 0_u32;
    for node in named_nodes {
        let Some(tag) = quanx_node_tag(node.name().as_str()) else {
            name_skips = name_skips.saturating_add(1);
            continue;
        };
        let Some(line) = render_server_line(node, tag) else {
            capability_skips = capability_skips.saturating_add(1);
            continue;
        };
        valid_tags.push(tag.to_owned());
        servers.push(ServerRecord {
            original_tag: tag.to_owned(),
            line,
        });
    }
    if servers.is_empty() {
        return Err(AdapterRenderError::NoValidNodes {
            capability_skips,
            name_skips,
        });
    }

    let valid = valid_tags.iter().map(String::as_str).collect::<Vec<_>>();
    let unique_urls = unique_health_urls(policy);
    let groups = render_groups(policy, &valid, &unique_urls)?;
    let servers = expand_servers(servers, policy, &valid, &unique_urls)?;
    let rules = render_rules(policy.rules());

    let mut body = String::new();
    if let Some(url) = unique_urls.first() {
        if !is_safe_field(url) {
            return Err(AdapterRenderError::Internal);
        }
        body.push_str("[general]\n");
        body.push_str("server_check_url=");
        body.push_str(url);
        body.push('\n');
        body.push('\n');
    }
    body.push_str("[server_local]\n");
    for line in &servers {
        body.push_str(line);
        body.push('\n');
    }
    body.push('\n');
    body.push_str("[policy]\n");
    for line in &groups {
        body.push_str(line);
        body.push('\n');
    }
    body.push('\n');
    body.push_str("[filter_local]\n");
    for line in &rules {
        body.push_str(line);
        body.push('\n');
    }
    if body.len() > limit_bytes {
        return Err(AdapterRenderError::OutputTooLarge { limit_bytes });
    }
    Ok(RenderedTargetV1 {
        bytes: body.into_bytes(),
        capability_skips,
        name_skips,
    })
}

pub(crate) fn classify_node(node: &ProxyNode) -> NodeKeep {
    let Some(tag) = quanx_node_tag(node.name().as_str()) else {
        return NodeKeep::Name;
    };
    if render_server_line(node, tag).is_none() {
        NodeKeep::Capability
    } else {
        NodeKeep::Keep
    }
}

struct ServerRecord {
    original_tag: String,
    line: String,
}

fn quanx_group_tag(name: &str) -> Option<&str> {
    if name.is_empty() || name.contains([',', '\r', '\n']) {
        None
    } else {
        Some(name)
    }
}

fn quanx_node_tag(name: &str) -> Option<&str> {
    if quanx_group_tag(name).is_some()
        && !name.eq_ignore_ascii_case("direct")
        && !name.eq_ignore_ascii_case("reject")
        && !name.eq_ignore_ascii_case("proxy")
    {
        Some(name)
    } else {
        None
    }
}

fn is_safe_field(value: &str) -> bool {
    !value.is_empty() && !value.contains([',', '\r', '\n'])
}

fn render_server_line(node: &ProxyNode, tag: &str) -> Option<String> {
    let endpoint = format!(
        "{}:{}",
        render_host_bracketed(node.endpoint().host()),
        node.endpoint().port()
    );
    if !is_safe_field(&endpoint) {
        return None;
    }
    let line = match node.protocol() {
        NodeProtocol::Vless(vless) => render_vless_line(&endpoint, vless, tag)?,
        NodeProtocol::Shadowsocks(shadowsocks) => {
            let password = shadowsocks_password(shadowsocks.credential());
            if !is_safe_field(&password) {
                return None;
            }
            format!(
                "shadowsocks={endpoint}, method={}, password={password}, udp-relay=true, fast-open=false, tag={tag}",
                shadowsocks_method(shadowsocks.cipher())
            )
        }
        NodeProtocol::Trojan(trojan) => render_trojan_line(&endpoint, trojan, tag)?,
        NodeProtocol::Vmess(vmess) => render_vmess_line(&endpoint, vmess, tag)?,
        NodeProtocol::Hysteria2(_) | NodeProtocol::Tuic(_) => return None,
    };
    Some(line)
}

fn render_vless_line(
    endpoint: &str,
    vless: &crate::node::vless::VlessNode,
    tag: &str,
) -> Option<String> {
    if matches!(vless.transport(), VlessTransport::Grpc { .. }) {
        return None;
    }
    if matches!(vless.flow(), Some(VlessFlow::Vision))
        && !matches!(vless.security(), VlessSecurity::Reality(_))
    {
        return None;
    }

    let mut fields = vec![
        format!("vless={endpoint}"),
        "method=none".to_owned(),
        format!("password={}", vless.id().as_uuid().hyphenated()),
    ];

    match vless.transport() {
        VlessTransport::Tcp => match vless.security() {
            VlessSecurity::None => {}
            VlessSecurity::Tls(options) => {
                push_tls_fields(
                    &mut fields,
                    "over-tls",
                    options.server_name(),
                    options.alpn(),
                )?;
            }
            VlessSecurity::Reality(options) => {
                push_reality_fields(&mut fields, "over-tls", options)?;
            }
        },
        VlessTransport::WebSocket { path, host } => {
            if !is_safe_field(path) {
                return None;
            }
            match vless.security() {
                VlessSecurity::None => {
                    fields.push("obfs=ws".to_owned());
                    if let Some(host) = host {
                        if !is_safe_field(host) {
                            return None;
                        }
                        fields.push(format!("obfs-host={host}"));
                    }
                    fields.push(format!("obfs-uri={path}"));
                }
                VlessSecurity::Tls(options) => {
                    fields.push("obfs=wss".to_owned());
                    let host = host.as_deref().unwrap_or(options.server_name());
                    if !is_safe_field(host) {
                        return None;
                    }
                    fields.push(format!("obfs-host={host}"));
                    fields.push(format!("obfs-uri={path}"));
                    if let Some(alpn) = options.alpn() {
                        fields.push(format!("tls-alpn={}", encode_alpn_hex(alpn)?));
                    }
                }
                VlessSecurity::Reality(_) => return None,
            }
        }
        VlessTransport::Grpc { .. } => return None,
    }

    if let Some(VlessFlow::Vision) = vless.flow() {
        fields.push("vless-flow=xtls-rprx-vision".to_owned());
    }
    fields.push("udp-relay=true".to_owned());
    fields.push("fast-open=false".to_owned());
    fields.push(format!("tag={tag}"));
    Some(fields.join(", "))
}

fn render_vmess_line(
    endpoint: &str,
    vmess: &crate::node::vmess::VmessNode,
    tag: &str,
) -> Option<String> {
    if matches!(vmess.transport(), VlessTransport::Grpc { .. }) {
        return None;
    }
    if matches!(vmess.cipher(), VmessCipher::Auto | VmessCipher::Zero) {
        return None;
    }

    let mut fields = vec![
        format!("vmess={endpoint}"),
        format!("method={}", vmess.cipher().as_token()),
        format!("password={}", vmess.id().as_uuid().hyphenated()),
    ];
    match vmess.transport() {
        VlessTransport::Tcp => match vmess.security() {
            VmessSecurity::None => {}
            VmessSecurity::Tls(options) => {
                push_tls_fields(
                    &mut fields,
                    "over-tls",
                    options.server_name(),
                    options.alpn(),
                )?;
            }
        },
        VlessTransport::WebSocket { path, host } => {
            if !is_safe_field(path) {
                return None;
            }
            match vmess.security() {
                VmessSecurity::None => {
                    fields.push("obfs=ws".to_owned());
                    if let Some(host) = host {
                        if !is_safe_field(host) {
                            return None;
                        }
                        fields.push(format!("obfs-host={host}"));
                    }
                    fields.push(format!("obfs-uri={path}"));
                }
                VmessSecurity::Tls(options) => {
                    fields.push("obfs=wss".to_owned());
                    let host = host.as_deref().unwrap_or(options.server_name());
                    if !is_safe_field(host) {
                        return None;
                    }
                    fields.push(format!("obfs-host={host}"));
                    fields.push(format!("obfs-uri={path}"));
                    fields.push("tls-verification=true".to_owned());
                    if let Some(alpn) = options.alpn() {
                        fields.push(format!("tls-alpn={}", encode_alpn_hex(alpn)?));
                    }
                }
            }
        }
        VlessTransport::Grpc { .. } => return None,
    }
    fields.push("udp-relay=true".to_owned());
    fields.push("fast-open=false".to_owned());
    fields.push(format!("tag={tag}"));
    Some(fields.join(", "))
}

fn render_trojan_line(
    endpoint: &str,
    trojan: &crate::node::trojan::TrojanNode,
    tag: &str,
) -> Option<String> {
    if matches!(trojan.transport(), VlessTransport::Grpc { .. }) {
        return None;
    }
    let password = trojan.password().expose();
    if !is_safe_field(password) {
        return None;
    }

    let mut fields = vec![format!("trojan={endpoint}"), format!("password={password}")];
    match trojan.transport() {
        VlessTransport::Tcp => match trojan.security() {
            TrojanSecurity::Tls(options) => {
                push_trojan_tls_fields(&mut fields, options.server_name(), options.alpn())?;
            }
            TrojanSecurity::Reality(options) => {
                push_trojan_tls_fields(&mut fields, options.tls().server_name(), None)?;
                push_trojan_reality_fields(&mut fields, options);
            }
        },
        VlessTransport::WebSocket { path, host } => {
            if !is_safe_field(path) {
                return None;
            }
            let sni = trojan.security().tls_options().server_name();
            let host = host.as_deref().unwrap_or(sni);
            if !is_safe_field(host) {
                return None;
            }
            fields.push("obfs=wss".to_owned());
            fields.push(format!("obfs-host={host}"));
            fields.push(format!("obfs-uri={path}"));
            match trojan.security() {
                TrojanSecurity::Tls(options) => {
                    fields.push("tls-verification=true".to_owned());
                    if let Some(alpn) = options.alpn() {
                        fields.push(format!("tls-alpn={}", encode_alpn_hex(alpn)?));
                    }
                }
                TrojanSecurity::Reality(options) => {
                    fields.push("tls-verification=true".to_owned());
                    push_trojan_reality_fields(&mut fields, options);
                }
            }
        }
        VlessTransport::Grpc { .. } => return None,
    }
    fields.push("udp-relay=true".to_owned());
    fields.push("fast-open=false".to_owned());
    fields.push(format!("tag={tag}"));
    Some(fields.join(", "))
}

fn push_trojan_tls_fields(
    fields: &mut Vec<String>,
    server_name: &str,
    alpn: Option<&[String]>,
) -> Option<()> {
    if !is_safe_field(server_name) {
        return None;
    }
    fields.push("over-tls=true".to_owned());
    fields.push(format!("tls-host={server_name}"));
    fields.push("tls-verification=true".to_owned());
    if let Some(alpn) = alpn {
        fields.push(format!("tls-alpn={}", encode_alpn_hex(alpn)?));
    }
    Some(())
}

fn push_trojan_reality_fields(
    fields: &mut Vec<String>,
    options: &crate::node::vless::RealityOptions,
) {
    fields.push(format!(
        "reality-base64-pubkey={}",
        reality_public_key_base64(options)
    ));
    if let Some(short_id) = reality_short_id_hex(options) {
        fields.push(format!("reality-hex-shortid={short_id}"));
    }
}

fn push_tls_fields(
    fields: &mut Vec<String>,
    obfs: &str,
    server_name: &str,
    alpn: Option<&[String]>,
) -> Option<()> {
    if !is_safe_field(server_name) {
        return None;
    }
    fields.push(format!("obfs={obfs}"));
    fields.push(format!("obfs-host={server_name}"));
    fields.push("tls-verification=true".to_owned());
    if let Some(alpn) = alpn {
        fields.push(format!("tls-alpn={}", encode_alpn_hex(alpn)?));
    }
    Some(())
}

fn push_reality_fields(
    fields: &mut Vec<String>,
    obfs: &str,
    options: &crate::node::vless::RealityOptions,
) -> Option<()> {
    let server_name = options.tls().server_name();
    if !is_safe_field(server_name) {
        return None;
    }
    fields.push(format!("obfs={obfs}"));
    fields.push(format!("obfs-host={server_name}"));
    fields.push(format!(
        "reality-base64-pubkey={}",
        reality_public_key_base64(options)
    ));
    if let Some(short_id) = reality_short_id_hex(options) {
        fields.push(format!("reality-hex-shortid={short_id}"));
    }
    Some(())
}

fn encode_alpn_hex(protocols: &[String]) -> Option<String> {
    let mut bytes = Vec::new();
    for protocol in protocols {
        let len = u8::try_from(protocol.len()).ok()?;
        if protocol.is_empty() || protocol.bytes().any(|byte| byte == b',') {
            return None;
        }
        bytes.push(len);
        bytes.extend_from_slice(protocol.as_bytes());
    }
    Some(encode_hex(&bytes))
}

fn member_token(
    member: &PolicyMemberV1,
    valid_nodes: &[&str],
) -> Result<Option<String>, AdapterRenderError> {
    policy_member_token(
        member,
        "direct",
        "reject",
        |name| Ok(quanx_group_tag(name).map(str::to_owned)),
        valid_nodes,
    )
}

fn render_groups(
    policy: &CompiledPolicyV1,
    valid_nodes: &[&str],
    unique_urls: &[&str],
) -> Result<Vec<String>, AdapterRenderError> {
    let mut lines = Vec::new();
    for group in policy.groups() {
        let name = quanx_group_tag(group.name()).ok_or(AdapterRenderError::Internal)?;
        let group_url = automatic_url(group.strategy());
        let mut members = Vec::new();
        for member in group.members() {
            let Some(token) = member_token(member, valid_nodes)? else {
                continue;
            };
            let token = match (member, group_url) {
                (PolicyMemberV1::Node(original), Some(url)) => {
                    health_tag(original, url, unique_urls)
                }
                _ => token,
            };
            members.push(token);
        }
        if members.is_empty() {
            lines.push(format!("static = {name}, reject"));
            continue;
        }
        let joined = members.join(", ");
        let line = match group.strategy() {
            GroupStrategyV1::Select => format!("static = {name}, {joined}"),
            GroupStrategyV1::UrlTest {
                interval,
                tolerance,
                ..
            } => format!(
                "url-latency-benchmark = {name}, {joined}, check-interval={interval}, alive-checking=true, tolerance={}",
                tolerance.unwrap_or(0)
            ),
            GroupStrategyV1::Fallback { .. } => format!("available = {name}, {joined}"),
            GroupStrategyV1::LoadBalance { .. } => format!("dest-hash = {name}, {joined}"),
        };
        lines.push(line);
    }
    Ok(lines)
}

fn automatic_url(strategy: &GroupStrategyV1) -> Option<&str> {
    match strategy {
        GroupStrategyV1::UrlTest { url, .. } | GroupStrategyV1::Fallback { url, .. } => Some(url),
        _ => None,
    }
}

fn unique_health_urls(policy: &CompiledPolicyV1) -> Vec<&str> {
    let mut urls = Vec::new();
    for group in policy.groups() {
        let Some(url) = automatic_url(group.strategy()) else {
            continue;
        };
        if urls.iter().all(|seen: &&str| *seen != url) {
            urls.push(url);
        }
    }
    urls
}

fn health_tag(original: &str, url: &str, unique_urls: &[&str]) -> String {
    if unique_urls.len() <= 1 {
        return original.to_owned();
    }
    match unique_urls.iter().position(|candidate| *candidate == url) {
        Some(0) | None => original.to_owned(),
        Some(index) => format!("{original}~u{}", index + 1),
    }
}

fn expand_servers(
    servers: Vec<ServerRecord>,
    policy: &CompiledPolicyV1,
    valid_nodes: &[&str],
    unique_urls: &[&str],
) -> Result<Vec<String>, AdapterRenderError> {
    let mut lines = Vec::new();
    for server in servers {
        if !valid_nodes.contains(&server.original_tag.as_str()) {
            continue;
        }
        let mut urls = Vec::new();
        for group in policy.groups() {
            let Some(url) = automatic_url(group.strategy()) else {
                continue;
            };
            let used = group.members().iter().any(|member| match member {
                PolicyMemberV1::Node(name) => name == &server.original_tag,
                _ => false,
            });
            if used && urls.iter().all(|seen: &&str| *seen != url) {
                urls.push(url);
            }
        }
        if urls.is_empty() {
            lines.push(server.line);
            continue;
        }
        for url in urls {
            if !is_safe_field(url) {
                return Err(AdapterRenderError::Internal);
            }
            let tag = health_tag(&server.original_tag, url, unique_urls);
            let mut line = replace_tag(&server.line, &server.original_tag, &tag);
            if unique_urls.len() > 1 && unique_urls.first().is_some_and(|general| *general != url) {
                line = insert_before_tag(&line, &format!("server_check_url={url}"));
            }
            lines.push(line);
        }
    }
    Ok(lines)
}

fn replace_tag(line: &str, original: &str, next: &str) -> String {
    let needle = format!("tag={original}");
    let replacement = format!("tag={next}");
    line.replacen(&needle, &replacement, 1)
}

fn insert_before_tag(line: &str, field: &str) -> String {
    match line.rfind(", tag=") {
        Some(index) => format!("{}, {}{}", &line[..index], field, &line[index..]),
        None => format!("{line}, {field}"),
    }
}

fn render_rules(rules: &[CompiledRuleV1]) -> Vec<String> {
    let mut lines = Vec::new();
    for rule in rules {
        let Some(policy) = (match rule.target() {
            PolicyMemberV1::Direct => Some("direct"),
            PolicyMemberV1::Reject => Some("reject"),
            PolicyMemberV1::Group(name) => quanx_group_tag(name),
            PolicyMemberV1::Node(_) => None,
        }) else {
            continue;
        };
        let line = match rule.matcher() {
            RuleMatcherV1::Domain(value) if is_safe_field(value) => {
                format!("host, {value}, {policy}")
            }
            RuleMatcherV1::DomainSuffix(value) if is_safe_field(value) => {
                format!("host-suffix, {value}, {policy}")
            }
            RuleMatcherV1::DomainKeyword(value) if is_safe_field(value) => {
                format!("host-keyword, {value}, {policy}")
            }
            RuleMatcherV1::IpCidr { value, version, .. } if is_safe_field(value) => match version {
                IpVersion::V4 => format!("ip-cidr, {value}, {policy}"),
                IpVersion::V6 => format!("ip6-cidr, {value}, {policy}"),
            },
            RuleMatcherV1::GeoIpCn => format!("geoip, cn, {policy}"),
            RuleMatcherV1::Match => format!("final, {policy}"),
            RuleMatcherV1::ProcessName(_)
            | RuleMatcherV1::UrlRegex(_)
            | RuleMatcherV1::Domain(_)
            | RuleMatcherV1::DomainSuffix(_)
            | RuleMatcherV1::DomainKeyword(_)
            | RuleMatcherV1::IpCidr { .. } => continue,
        };
        lines.push(line);
    }
    lines
}

#[cfg(test)]
mod tests;
