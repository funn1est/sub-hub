use std::fmt;

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};

use crate::{
    node::shadowsocks::{ShadowsocksCipher, ShadowsocksCredential},
    node::vless::{VlessFlow, VlessSecurity, VlessTransport},
    node::{Host, NodeProtocol, ProxyNode},
    policy::{
        CompiledPolicyV1, CompiledRuleV1, GroupStrategyV1, IpVersion, PolicyMemberV1, RuleMatcherV1,
    },
};

pub(crate) enum QuanxRenderError {
    NoValidNodes,
    OutputTooLarge { limit_bytes: usize },
    Internal,
}

pub(crate) fn render_quanx_from_policy_v1(
    named_nodes: &[&ProxyNode],
    policy: &CompiledPolicyV1,
    limit_bytes: usize,
) -> Result<Vec<u8>, QuanxRenderError> {
    let mut servers = Vec::new();
    let mut valid_tags = Vec::new();
    for node in named_nodes {
        let Some(tag) = quanx_node_tag(node.name().as_str()) else {
            continue;
        };
        let Some(line) = render_server_line(node, tag) else {
            continue;
        };
        valid_tags.push(tag.to_owned());
        servers.push(ServerRecord {
            original_tag: tag.to_owned(),
            line,
        });
    }
    if servers.is_empty() {
        return Err(QuanxRenderError::NoValidNodes);
    }

    let valid = valid_tags.iter().map(String::as_str).collect::<Vec<_>>();
    let unique_urls = unique_health_urls(policy);
    let groups = render_groups(policy, &valid, &unique_urls)?;
    let servers = expand_servers(servers, policy, &valid, &unique_urls)?;
    let rules = render_rules(policy.rules());

    let mut body = String::new();
    if let Some(url) = unique_urls.first() {
        if !is_safe_field(url) {
            return Err(QuanxRenderError::Internal);
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
        return Err(QuanxRenderError::OutputTooLarge { limit_bytes });
    }
    Ok(body.into_bytes())
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

fn render_host(host: &Host) -> String {
    match host {
        Host::Domain(domain) => domain.clone(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => format!("[{address}]"),
    }
}

fn render_server_line(node: &ProxyNode, tag: &str) -> Option<String> {
    let endpoint = format!(
        "{}:{}",
        render_host(node.endpoint().host()),
        node.endpoint().port()
    );
    if !is_safe_field(&endpoint) {
        return None;
    }
    let line = match node.protocol() {
        NodeProtocol::Vless(vless) => render_vless_line(&endpoint, vless, tag)?,
        NodeProtocol::Shadowsocks(shadowsocks) => {
            let password = match shadowsocks.credential() {
                ShadowsocksCredential::Password(password) => password.expose().to_owned(),
                ShadowsocksCredential::Psk(psk) => STANDARD.encode(psk.expose()),
            };
            if !is_safe_field(&password) {
                return None;
            }
            format!(
                "shadowsocks={endpoint}, method={}, password={password}, udp-relay=true, fast-open=false, tag={tag}",
                shadowsocks_method(shadowsocks.cipher())
            )
        }
    };
    Some(line)
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
        URL_SAFE_NO_PAD.encode(options.public_key().as_bytes())
    ));
    if let Some(short_id) = options.short_id() {
        fields.push(format!(
            "reality-hex-shortid={}",
            encode_hex(short_id.as_bytes())
        ));
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

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn member_token(member: &PolicyMemberV1, valid_nodes: &[&str]) -> Option<String> {
    match member {
        PolicyMemberV1::Direct => Some("direct".to_owned()),
        PolicyMemberV1::Reject => Some("reject".to_owned()),
        PolicyMemberV1::Group(name) => quanx_group_tag(name).map(str::to_owned),
        PolicyMemberV1::Node(name) => valid_nodes
            .iter()
            .any(|candidate| *candidate == name)
            .then(|| name.clone()),
    }
}

fn render_groups(
    policy: &CompiledPolicyV1,
    valid_nodes: &[&str],
    unique_urls: &[&str],
) -> Result<Vec<String>, QuanxRenderError> {
    let mut lines = Vec::new();
    for group in policy.groups() {
        let name = quanx_group_tag(group.name()).ok_or(QuanxRenderError::Internal)?;
        let group_url = automatic_url(group.strategy());
        let mut members = Vec::new();
        for member in group.members() {
            let Some(token) = member_token(member, valid_nodes) else {
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
) -> Result<Vec<String>, QuanxRenderError> {
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
                return Err(QuanxRenderError::Internal);
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
            | RuleMatcherV1::Domain(_)
            | RuleMatcherV1::DomainSuffix(_)
            | RuleMatcherV1::DomainKeyword(_)
            | RuleMatcherV1::IpCidr { .. } => continue,
        };
        lines.push(line);
    }
    lines
}

impl fmt::Debug for QuanxRenderError {
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
    use crate::mihomo::render_builtin_quanx_v1;
    use crate::subscription_source::parse_subscription_sources;

    #[test]
    fn builtin_tcp_vless_matches_the_frozen_quanx_shape() {
        let parsed = parse_subscription_sources(&[
            &b"vless://01234567-89ab-cdef-0123-456789abcdef@EXAMPLE.COM:443#Alpha"[..],
        ])
        .expect("valid");
        let output = render_builtin_quanx_v1(parsed).expect("rendered");
        assert_eq!(
            std::str::from_utf8(output.config()).expect("utf8"),
            concat!(
                "[general]\n",
                "server_check_url=https://www.gstatic.com/generate_204\n",
                "\n",
                "[server_local]\n",
                "vless=example.com:443, method=none, password=01234567-89ab-cdef-0123-456789abcdef, udp-relay=true, fast-open=false, tag=Alpha\n",
                "\n",
                "[policy]\n",
                "static = PROXY, AUTO, Alpha, direct\n",
                "url-latency-benchmark = AUTO, Alpha, check-interval=300, alive-checking=true, tolerance=0\n",
                "\n",
                "[filter_local]\n",
                "final, PROXY\n",
            )
        );
    }

    #[test]
    fn grpc_and_vision_without_reality_are_skipped() {
        let source = concat!(
            "vless://00000000-0000-4000-8000-000000000003@[2001:db8::1]:9443?type=grpc&serviceName=svc%2Fprod&security=reality&sni=reality.example&fp=safari&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&sid=0a1b#Reality\n",
            "vless://00000000-0000-4000-8000-000000000004@vision.example:443?security=tls&flow=xtls-rprx-vision#Vision\n",
            "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha\n",
        );
        let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid");
        let output = render_builtin_quanx_v1(parsed).expect("rendered");
        let text = std::str::from_utf8(output.config()).expect("utf8");
        assert!(text.contains("tag=Alpha"));
        assert!(!text.contains("tag=Reality"));
        assert!(!text.contains("tag=Vision"));
        assert!(!text.contains("grpc"));
    }

    #[test]
    fn debug_output_does_not_retain_node_names() {
        let parsed = parse_subscription_sources(&[
            &b"vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#SecretCanary"[..],
        ])
        .expect("valid");
        let output = render_builtin_quanx_v1(parsed).expect("rendered");
        let debug = format!("{output:?}");
        assert!(!debug.contains("SecretCanary"));
    }
}
