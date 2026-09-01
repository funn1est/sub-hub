use std::collections::BTreeSet;

use crate::{
    node::trojan::TrojanSecurity,
    node::vless::{VlessFlow, VlessSecurity, VlessTransport},
    node::vmess::{VmessCipher, VmessSecurity},
    node::{NodeProtocol, ProxyNode},
    policy::{
        CompiledPolicyV1, CompiledRuleV1, GroupStrategyV1, IpVersion, PolicyMemberV1, RuleMatcherV1,
    },
    render::{
        AdapterRenderError, KeptNodes, NodeKeep, RenderedTargetV1, WalkedGroupItem,
        bounded_text_sections, encode_hex, is_reserved_tag, is_safe_field as ini_safe_field,
        keep_named, map_compiled_rules, reality_public_key_base64, reality_short_id_hex,
        render_host_bracketed, shadowsocks_method, shadowsocks_password, walk_group_members,
    },
};

pub(crate) fn render_quanx_from_policy_v1(
    named_nodes: &[&ProxyNode],
    policy: &CompiledPolicyV1,
    limit_bytes: usize,
) -> Result<RenderedTargetV1, AdapterRenderError> {
    let (kept, servers) = KeptNodes::encode_or_unexpanded(named_nodes, policy, encode_node)?;
    let valid_tags = servers
        .iter()
        .map(|server| server.original_tag.clone())
        .collect::<Vec<_>>();

    let valid = valid_tags.iter().map(String::as_str).collect::<Vec<_>>();
    let unique_urls = unique_health_urls(policy);
    let remote_tags = quanx_unexpanded_tags(policy, &valid)?;
    let remotes = render_server_remote(policy, &remote_tags)?;
    let groups = render_groups(policy, &valid, &unique_urls, &remote_tags)?;
    let servers = expand_servers(servers, policy, &valid, &unique_urls)?;
    let (rules, omitted_url_regex) = render_rules(policy.rules())?;

    let mut leading = String::new();
    leading.push_str("[general]\n");
    if let Some(url) = unique_urls.first() {
        if !is_safe_field(url) {
            return Err(AdapterRenderError::Internal);
        }
        leading.push_str("server_check_url=");
        leading.push_str(url);
        leading.push('\n');
    }
    leading.push('\n');
    leading.push_str(QUANX_DNS);
    leading.push('\n');
    // Official sample order. Quantumult X reports a missing-module parse
    // error for any absent heading, including empty `[server_remote]`.
    let empty: &[String] = &[];
    bounded_text_sections(
        &leading,
        &[
            ("[policy]", groups.as_slice()),
            ("[server_remote]", remotes.as_slice()),
            ("[filter_remote]", empty),
            ("[rewrite_remote]", empty),
            ("[server_local]", servers.as_slice()),
            ("[filter_local]", rules.as_slice()),
            ("[rewrite_local]", empty),
            ("[task_local]", empty),
            ("[http_backend]", empty),
            ("[mitm]", empty),
        ],
        limit_bytes,
        &kept,
        omitted_url_regex,
    )
}

fn encode_node(node: &ProxyNode) -> Result<ServerRecord, NodeKeep> {
    keep_named(quanx_node_tag(node.name().as_str()), |tag| {
        render_server_line(node, tag)
    })
    .map(|(original_tag, line)| ServerRecord { original_tag, line })
}

struct ServerRecord {
    original_tag: String,
    line: String,
}

const QUANX_RESERVED_NODE_TAGS: [&str; 3] = ["direct", "reject", "proxy"];

/// Official sample's uncommented resolvers.
const QUANX_DNS: &str = "[dns]\nserver=223.5.5.5\nserver=119.29.29.29\n";

fn quanx_group_tag(name: &str) -> Option<&str> {
    is_safe_field(name).then_some(name)
}

fn quanx_node_tag(name: &str) -> Option<&str> {
    quanx_group_tag(name).filter(|name| !is_reserved_tag(name, &QUANX_RESERVED_NODE_TAGS))
}

fn is_safe_field(value: &str) -> bool {
    ini_safe_field(value, false)
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
            let mut line = format!(
                "shadowsocks={endpoint}, method={}, password={password}, udp-relay=true, fast-open=false",
                shadowsocks_method(shadowsocks.cipher())
            );
            if let Some(obfs) = shadowsocks.obfs() {
                line.push_str(", obfs=");
                line.push_str(obfs.mode().as_token());
                if let Some(host) = obfs.host() {
                    if !is_safe_field(host) {
                        return None;
                    }
                    line.push_str(", obfs-host=");
                    line.push_str(host);
                }
            }
            line.push_str(", tag=");
            line.push_str(tag);
            line
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

fn render_server_remote(
    policy: &CompiledPolicyV1,
    remote_tags: &[String],
) -> Result<Vec<String>, AdapterRenderError> {
    let remotes = policy.unexpanded_subscriptions();
    if remotes.len() != remote_tags.len() {
        return Err(AdapterRenderError::Internal);
    }
    let mut lines = Vec::new();
    for (sub, tag) in remotes.iter().zip(remote_tags) {
        if !is_safe_field(sub.url()) || !is_safe_field(tag) {
            return Err(AdapterRenderError::Internal);
        }
        lines.push(format!(
            "{}, tag={tag}, update-interval=86400, as-policy=static",
            sub.url()
        ));
    }
    Ok(lines)
}

/// Quantumult X policy/server tags reject `.`. Unexpanded names are DNS hosts,
/// so the adapter spells each `.` as `-` and suffixes on collision with a
/// reserved, group, node, or earlier remote tag.
fn quanx_unexpanded_tags(
    policy: &CompiledPolicyV1,
    node_tags: &[&str],
) -> Result<Vec<String>, AdapterRenderError> {
    let mut used = BTreeSet::new();
    for reserved in QUANX_RESERVED_NODE_TAGS {
        used.insert(reserved.to_ascii_lowercase());
    }
    for group in policy.groups() {
        used.insert(group.name().to_ascii_lowercase());
    }
    for tag in node_tags {
        used.insert(tag.to_ascii_lowercase());
    }
    let mut tags = Vec::new();
    for sub in policy.unexpanded_subscriptions() {
        if quanx_group_tag(sub.name()).is_none() {
            return Err(AdapterRenderError::Internal);
        }
        let base = sub.name().replace('.', "-");
        if base.is_empty() || !is_safe_field(&base) {
            return Err(AdapterRenderError::Internal);
        }
        tags.push(occupy_tag(base, &mut used));
    }
    Ok(tags)
}

fn occupy_tag(base: String, used: &mut BTreeSet<String>) -> String {
    if occupy_if_free(&base, used) {
        return base;
    }
    for index in 2_u32..=99_999 {
        let candidate = format!("{base}-{index}");
        if occupy_if_free(&candidate, used) {
            return candidate;
        }
    }
    base
}

fn occupy_if_free(name: &str, used: &mut BTreeSet<String>) -> bool {
    let key = name.to_ascii_lowercase();
    if used.contains(&key) {
        return false;
    }
    used.insert(key);
    true
}

fn render_groups(
    policy: &CompiledPolicyV1,
    valid_nodes: &[&str],
    unique_urls: &[&str],
    remote_tags: &[String],
) -> Result<Vec<String>, AdapterRenderError> {
    let mut lines = Vec::new();
    for group in policy.groups() {
        let name = quanx_group_tag(group.name()).ok_or(AdapterRenderError::Internal)?;
        let group_url = automatic_url(group.strategy());
        let walked = walk_group_members(
            group.members(),
            "direct",
            "reject",
            |name| Ok(quanx_group_tag(name).map(str::to_owned)),
            valid_nodes,
            |member, token| match (member, group_url) {
                (PolicyMemberV1::Node(original), Some(url)) => {
                    health_tag(original, url, unique_urls)
                }
                _ => token,
            },
        )?;
        let mut members = Vec::new();
        let mut unexpanded_in_group = false;
        for item in walked.items {
            match item {
                WalkedGroupItem::Token(token) => members.push(token),
                WalkedGroupItem::Unexpanded => {
                    unexpanded_in_group = true;
                    // `as-policy=static` is a policy. Only `static` groups may
                    // list that tag. url-latency-benchmark pulls the remote's
                    // servers via resource-tag-regex instead.
                    if matches!(group.strategy(), GroupStrategyV1::Select) {
                        members.extend(remote_tags.iter().cloned());
                    }
                }
            }
        }
        let include_remotes = unexpanded_in_group && !remote_tags.is_empty();
        if members.is_empty() && !include_remotes {
            lines.push(format!("static = {name}, reject"));
            continue;
        }
        let line = match group.strategy() {
            GroupStrategyV1::Select => {
                if members.is_empty() {
                    format!("static = {name}, reject")
                } else {
                    format!("static = {name}, {}", members.join(", "))
                }
            }
            GroupStrategyV1::UrlTest {
                interval,
                tolerance,
                ..
            } => automatic_group_line(
                "url-latency-benchmark",
                name,
                &members,
                include_remotes.then_some(remote_tags),
                &format!(
                    "check-interval={interval}, alive-checking=true, tolerance={}",
                    tolerance.unwrap_or(0)
                ),
            )?,
            GroupStrategyV1::Fallback { .. } => automatic_group_line(
                "available",
                name,
                &members,
                include_remotes.then_some(remote_tags),
                "",
            )?,
            GroupStrategyV1::LoadBalance { .. } => automatic_group_line(
                "dest-hash",
                name,
                &members,
                include_remotes.then_some(remote_tags),
                "",
            )?,
        };
        lines.push(line);
    }
    Ok(lines)
}

fn automatic_group_line(
    kind: &str,
    name: &str,
    server_tokens: &[String],
    remote_tags: Option<&[String]>,
    params: &str,
) -> Result<String, AdapterRenderError> {
    let mut fields = vec![format!("{kind} = {name}")];
    match remote_tags {
        Some(tags) if !tags.is_empty() => {
            fields.push(format!("resource-tag-regex={}", regex_alternation(tags)?));
            if !server_tokens.is_empty() {
                fields.push(format!(
                    "server-tag-regex={}",
                    regex_alternation(server_tokens)?
                ));
            }
        }
        _ => fields.extend(server_tokens.iter().cloned()),
    }
    if !params.is_empty() {
        fields.push(params.to_owned());
    }
    Ok(fields.join(", "))
}

fn regex_alternation(tags: &[String]) -> Result<String, AdapterRenderError> {
    let escaped = tags
        .iter()
        .map(|tag| regex_literal(tag))
        .collect::<Vec<_>>();
    let pattern = if escaped.len() == 1 {
        format!("^{}$", escaped[0])
    } else {
        format!("^(?:{})$", escaped.join("|"))
    };
    if !is_safe_field(&pattern) {
        return Err(AdapterRenderError::Internal);
    }
    Ok(pattern)
}

fn regex_literal(value: &str) -> String {
    let mut escaped = String::new();
    for character in value.chars() {
        if matches!(
            character,
            '\\' | '.' | '+' | '*' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|'
        ) {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
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

fn render_rules(rules: &[CompiledRuleV1]) -> Result<(Vec<String>, u8), AdapterRenderError> {
    map_compiled_rules(rules, |rule| {
        let Some(policy) = (match rule.target() {
            PolicyMemberV1::Direct => Some("direct"),
            PolicyMemberV1::Reject => Some("reject"),
            PolicyMemberV1::Group(name) => quanx_group_tag(name),
            PolicyMemberV1::Node(_) | PolicyMemberV1::UnexpandedAll => None,
        }) else {
            return Ok(None);
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
            RuleMatcherV1::UrlRegex(_)
            | RuleMatcherV1::ProcessName(_)
            | RuleMatcherV1::Domain(_)
            | RuleMatcherV1::DomainSuffix(_)
            | RuleMatcherV1::DomainKeyword(_)
            | RuleMatcherV1::IpCidr { .. } => return Ok(None),
        };
        Ok(Some(line))
    })
}

#[cfg(test)]
mod tests;
