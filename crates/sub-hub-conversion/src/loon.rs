use crate::{
    node::trojan::TrojanSecurity,
    node::vless::{ClientFingerprint, VlessFlow, VlessSecurity, VlessTransport},
    node::vmess::{VmessCipher, VmessSecurity},
    node::{NodeProtocol, ProxyNode},
    policy::{
        CompiledPolicyV1, CompiledRuleV1, GroupStrategyV1, IpVersion, PolicyMemberV1, RuleMatcherV1,
    },
    render::{
        AdapterRenderError, NodeKeep, RenderedTargetV1, bounded_text, keep_named, keep_tagged,
        map_compiled_rules, policy_member_token, probe_url_or_default, reality_public_key_base64,
        reality_short_id_hex, reject_when_empty, render_host_plain, shadowsocks_method,
        shadowsocks_password, shared_probe_url,
    },
};

const RESERVED_NODE_TAGS: [&str; 7] = [
    "direct",
    "reject",
    "reject-img",
    "reject-dict",
    "reject-array",
    "reject-drop",
    "proxy",
];

pub(crate) fn render_loon_from_policy_v1(
    named_nodes: &[&ProxyNode],
    policy: &CompiledPolicyV1,
    limit_bytes: usize,
) -> Result<RenderedTargetV1, AdapterRenderError> {
    let (kept, valid_tags, proxies) = keep_tagged(named_nodes, encode_node)?;
    let valid = valid_tags.iter().map(String::as_str).collect::<Vec<_>>();
    let groups = render_groups(policy, &valid)?;
    let (rules, omitted_url_regex) = render_rules(policy.rules(), &valid)?;

    let mut body = String::new();
    if let Some(url) = shared_probe_url(policy) {
        if !is_safe_field(url) {
            return Err(AdapterRenderError::Internal);
        }
        body.push_str("[General]\n");
        body.push_str("proxy-test-url = ");
        body.push_str(url);
        body.push('\n');
        body.push('\n');
    }
    body.push_str("[Proxy]\n");
    for line in &proxies {
        body.push_str(line);
        body.push('\n');
    }
    body.push('\n');
    body.push_str("[Proxy Group]\n");
    for line in &groups {
        body.push_str(line);
        body.push('\n');
    }
    body.push('\n');
    body.push_str("[Rule]\n");
    for line in &rules {
        body.push_str(line);
        body.push('\n');
    }
    bounded_text(body, limit_bytes, &kept, omitted_url_regex)
}

fn encode_node(node: &ProxyNode) -> Result<(String, String), NodeKeep> {
    keep_named(loon_node_tag(node.name().as_str()), |tag| {
        render_proxy_line(node, tag)
    })
}

fn loon_node_tag(name: &str) -> Option<&str> {
    if name.is_empty()
        || name.chars().any(|character| character.is_ascii_control())
        || name.contains(',')
        || RESERVED_NODE_TAGS
            .iter()
            .any(|reserved| name.eq_ignore_ascii_case(reserved))
    {
        None
    } else {
        Some(name)
    }
}

fn loon_group_tag(name: &str) -> Result<&str, AdapterRenderError> {
    if name.is_empty()
        || name.chars().any(|character| character.is_ascii_control())
        || name.contains(',')
    {
        return Err(AdapterRenderError::Internal);
    }
    if name.eq_ignore_ascii_case("proxy") {
        return Ok(name);
    }
    if RESERVED_NODE_TAGS
        .iter()
        .any(|reserved| name.eq_ignore_ascii_case(reserved))
    {
        return Err(AdapterRenderError::Internal);
    }
    Ok(name)
}

fn is_safe_field(value: &str) -> bool {
    !value.is_empty()
        && !value.contains([',', '"', '\r', '\n'])
        && !value.chars().any(|character| character.is_ascii_control())
}

fn quote(value: &str) -> Option<String> {
    is_safe_field(value).then(|| format!("\"{value}\""))
}

fn render_proxy_line(node: &ProxyNode, tag: &str) -> Option<String> {
    let host = render_host_plain(node.endpoint().host());
    if !is_safe_field(&host) {
        return None;
    }
    let port = node.endpoint().port().get();
    match node.protocol() {
        NodeProtocol::Vless(vless) => render_vless_line(tag, &host, port, vless),
        NodeProtocol::Shadowsocks(shadowsocks) => {
            render_shadowsocks_line(tag, &host, port, shadowsocks)
        }
        NodeProtocol::Trojan(trojan) => render_trojan_line(tag, &host, port, trojan),
        NodeProtocol::Vmess(vmess) => render_vmess_line(tag, &host, port, vmess),
        NodeProtocol::Hysteria2(hysteria2) => render_hysteria2_line(tag, &host, port, hysteria2),
        NodeProtocol::Tuic(_) => None,
    }
}

fn render_hysteria2_line(
    tag: &str,
    host: &str,
    port: u16,
    hysteria2: &crate::node::hysteria2::Hysteria2Node,
) -> Option<String> {
    if hysteria2.ports().is_hop()
        || hysteria2.pin_sha256().is_some()
        || hysteria2
            .obfs()
            .is_some_and(crate::node::hysteria2::Hysteria2Obfs::is_gecko)
    {
        return None;
    }
    let auth = if hysteria2.auth().expose().is_empty() {
        "\"\"".to_owned()
    } else {
        quote(hysteria2.auth().expose())?
    };
    let mut fields = vec![
        format!("{tag} = Hysteria2"),
        host.to_owned(),
        port.to_string(),
        auth,
    ];
    if let Some(sni) = hysteria2.sni() {
        if !is_safe_field(sni) {
            return None;
        }
        fields.push(format!("sni={sni}"));
    }
    fields.push("skip-cert-verify=false".to_owned());
    if let Some(obfs) = hysteria2.obfs() {
        let password = quote(obfs.password())?;
        fields.push(format!("salamander-password={password}"));
    }
    fields.push("udp=true".to_owned());
    Some(fields.join(","))
}

fn render_vmess_line(
    tag: &str,
    host: &str,
    port: u16,
    vmess: &crate::node::vmess::VmessNode,
) -> Option<String> {
    if matches!(vmess.transport(), VlessTransport::Grpc { .. }) {
        return None;
    }
    if !matches!(vmess.cipher(), VmessCipher::Aes128Gcm) {
        return None;
    }
    let uuid = quote(&vmess.id().as_uuid().hyphenated().to_string())?;
    let mut fields = vec![
        format!("{tag} = vmess"),
        host.to_owned(),
        port.to_string(),
        vmess.cipher().as_token().to_owned(),
        uuid,
    ];
    match vmess.transport() {
        VlessTransport::Tcp => fields.push("transport=tcp".to_owned()),
        VlessTransport::WebSocket {
            path,
            host: ws_host,
        } => {
            if !is_safe_field(path) {
                return None;
            }
            fields.push("transport=ws".to_owned());
            fields.push(format!("path={path}"));
            if let Some(ws_host) = ws_host {
                if !is_safe_field(ws_host) {
                    return None;
                }
                fields.push(format!("host={ws_host}"));
            }
        }
        VlessTransport::Grpc { .. } => return None,
    }
    fields.push("alterId=0".to_owned());
    match vmess.security() {
        VmessSecurity::None => fields.push("over-tls=false".to_owned()),
        VmessSecurity::Tls(options) => {
            if !is_safe_field(options.server_name()) {
                return None;
            }
            fields.push("over-tls=true".to_owned());
            fields.push(format!("sni={}", options.server_name()));
            fields.push("skip-cert-verify=false".to_owned());
            if let Some(profile) = tls_profile(options.fingerprint()) {
                fields.push(format!("tls-profile={profile}"));
            }
        }
    }
    fields.push("udp=true".to_owned());
    Some(fields.join(","))
}

fn render_trojan_line(
    tag: &str,
    host: &str,
    port: u16,
    trojan: &crate::node::trojan::TrojanNode,
) -> Option<String> {
    if matches!(trojan.transport(), VlessTransport::Grpc { .. }) {
        return None;
    }
    if matches!(trojan.security(), TrojanSecurity::Reality(_)) {
        return None;
    }

    let password = quote(trojan.password().expose())?;
    let mut fields = vec![
        format!("{tag} = trojan"),
        host.to_owned(),
        port.to_string(),
        password,
    ];

    match trojan.transport() {
        VlessTransport::Tcp => {}
        VlessTransport::WebSocket {
            path,
            host: ws_host,
        } => {
            if !is_safe_field(path) {
                return None;
            }
            fields.push("transport=ws".to_owned());
            fields.push(format!("path={path}"));
            if let Some(ws_host) = ws_host {
                if !is_safe_field(ws_host) {
                    return None;
                }
                fields.push(format!("host={ws_host}"));
            }
        }
        VlessTransport::Grpc { .. } => return None,
    }

    let TrojanSecurity::Tls(options) = trojan.security() else {
        return None;
    };
    if let Some(alpn) = options.alpn()
        && alpn.len() == 1
        && is_safe_field(&alpn[0])
    {
        fields.push(format!("alpn={}", alpn[0]));
    }
    if !is_safe_field(options.server_name()) {
        return None;
    }
    fields.push(format!("sni={}", options.server_name()));
    fields.push("skip-cert-verify=false".to_owned());
    if let Some(profile) = tls_profile(options.fingerprint()) {
        fields.push(format!("tls-profile={profile}"));
    }
    fields.push("udp=true".to_owned());
    Some(fields.join(","))
}

fn render_vless_line(
    tag: &str,
    host: &str,
    port: u16,
    vless: &crate::node::vless::VlessNode,
) -> Option<String> {
    if matches!(vless.transport(), VlessTransport::Grpc { .. }) {
        return None;
    }
    let has_vision = matches!(vless.flow(), Some(VlessFlow::Vision));
    let has_reality = matches!(vless.security(), VlessSecurity::Reality(_));
    if has_vision != has_reality {
        return None;
    }
    if has_reality && !matches!(vless.transport(), VlessTransport::Tcp) {
        return None;
    }

    let uuid = quote(&vless.id().as_uuid().hyphenated().to_string())?;
    let mut fields = vec![
        format!("{tag} = VLESS"),
        host.to_owned(),
        port.to_string(),
        uuid,
    ];

    match vless.transport() {
        VlessTransport::Tcp => fields.push("transport=tcp".to_owned()),
        VlessTransport::WebSocket {
            path,
            host: ws_host,
        } => {
            if !is_safe_field(path) {
                return None;
            }
            fields.push("transport=ws".to_owned());
            fields.push(format!("path={path}"));
            if let Some(ws_host) = ws_host {
                if !is_safe_field(ws_host) {
                    return None;
                }
                fields.push(format!("host={ws_host}"));
            }
        }
        VlessTransport::Grpc { .. } => return None,
    }

    match vless.security() {
        VlessSecurity::None => fields.push("over-tls=false".to_owned()),
        VlessSecurity::Tls(options) => {
            push_tls_fields(&mut fields, options.server_name(), options.fingerprint())?;
        }
        VlessSecurity::Reality(options) => {
            fields.push("flow=xtls-rprx-vision".to_owned());
            fields.push(format!(
                "public-key={}",
                quote(&reality_public_key_base64(options))?
            ));
            if let Some(hex) = reality_short_id_hex(options) {
                if !is_safe_field(&hex) {
                    return None;
                }
                fields.push(format!("short-id={hex}"));
            }
            push_tls_fields(
                &mut fields,
                options.tls().server_name(),
                options.tls().fingerprint(),
            )?;
        }
    }

    fields.push("udp=true".to_owned());
    Some(fields.join(","))
}

fn push_tls_fields(
    fields: &mut Vec<String>,
    server_name: &str,
    fingerprint: ClientFingerprint,
) -> Option<()> {
    if !is_safe_field(server_name) {
        return None;
    }
    fields.push("over-tls=true".to_owned());
    fields.push(format!("sni={server_name}"));
    fields.push("skip-cert-verify=false".to_owned());
    if let Some(profile) = tls_profile(fingerprint) {
        fields.push(format!("tls-profile={profile}"));
    }
    Some(())
}

const fn tls_profile(fingerprint: ClientFingerprint) -> Option<&'static str> {
    match fingerprint {
        ClientFingerprint::Chrome => Some("chrome"),
        ClientFingerprint::Safari => Some("safari"),
        ClientFingerprint::Firefox
        | ClientFingerprint::Ios
        | ClientFingerprint::Android
        | ClientFingerprint::Edge
        | ClientFingerprint::ThreeSixty
        | ClientFingerprint::Qq
        | ClientFingerprint::Random => None,
    }
}

fn render_shadowsocks_line(
    tag: &str,
    host: &str,
    port: u16,
    shadowsocks: &crate::node::shadowsocks::ShadowsocksNode,
) -> Option<String> {
    let password = shadowsocks_password(shadowsocks.credential());
    let password = quote(&password)?;
    Some(format!(
        "{tag} = Shadowsocks,{host},{port},{},{password},fast-open=false,udp=true",
        shadowsocks_method(shadowsocks.cipher())
    ))
}

fn member_token(
    member: &PolicyMemberV1,
    valid_nodes: &[&str],
) -> Result<Option<String>, AdapterRenderError> {
    policy_member_token(
        member,
        "DIRECT",
        "REJECT",
        |name| loon_group_tag(name).map(|tag| Some(tag.to_owned())),
        valid_nodes,
    )
}

fn render_groups(
    policy: &CompiledPolicyV1,
    valid_nodes: &[&str],
) -> Result<Vec<String>, AdapterRenderError> {
    let mut lines = Vec::new();
    for group in policy.groups() {
        let name = loon_group_tag(group.name())?;
        let mut members = Vec::new();
        for member in group.members() {
            if let Some(token) = member_token(member, valid_nodes)? {
                members.push(token);
            }
        }
        reject_when_empty(&mut members, "REJECT");
        let joined = members.join(",");
        let line = match group.strategy() {
            GroupStrategyV1::Select => format!("{name} = select,{joined}"),
            GroupStrategyV1::UrlTest {
                url,
                interval,
                tolerance,
            } => {
                let url = health_url(url)?;
                let mut line =
                    format!("{name} = url-test,{joined},url = {url},interval = {interval}");
                if let Some(tolerance) = tolerance {
                    line.push_str(",tolerance=");
                    line.push_str(&tolerance.to_string());
                }
                line
            }
            GroupStrategyV1::Fallback { url, interval } => {
                let url = health_url(url)?;
                format!("{name} = fallback,{joined},url = {url},interval = {interval}")
            }
            GroupStrategyV1::LoadBalance { url, interval } => {
                let url = health_url(url)?;
                format!(
                    "{name} = load-balance,{joined},url = {url},interval = {interval},algorithm = pcc"
                )
            }
        };
        lines.push(line);
    }
    Ok(lines)
}

fn health_url(url: &str) -> Result<&str, AdapterRenderError> {
    let url = probe_url_or_default(url);
    if is_safe_field(url) {
        Ok(url)
    } else {
        Err(AdapterRenderError::Internal)
    }
}

fn render_rules(
    rules: &[CompiledRuleV1],
    valid_nodes: &[&str],
) -> Result<(Vec<String>, u8), AdapterRenderError> {
    map_compiled_rules(rules, |rule| {
        let Some(policy) = member_token(rule.target(), valid_nodes)? else {
            return Ok(None);
        };
        let line = match rule.matcher() {
            RuleMatcherV1::Domain(value) if is_safe_field(value) => {
                format!("DOMAIN,{value},{policy}")
            }
            RuleMatcherV1::DomainSuffix(value) if is_safe_field(value) => {
                format!("DOMAIN-SUFFIX,{value},{policy}")
            }
            RuleMatcherV1::DomainKeyword(value) if is_safe_field(value) => {
                format!("DOMAIN-KEYWORD,{value},{policy}")
            }
            RuleMatcherV1::IpCidr {
                value,
                version,
                no_resolve,
            } if is_safe_field(value) => {
                let kind = match version {
                    IpVersion::V4 => "IP-CIDR",
                    IpVersion::V6 => "IP-CIDR6",
                };
                if *no_resolve {
                    format!("{kind},{value},{policy},no-resolve")
                } else {
                    format!("{kind},{value},{policy}")
                }
            }
            RuleMatcherV1::GeoIpCn => format!("GEOIP,CN,{policy}"),
            RuleMatcherV1::Match => format!("FINAL,{policy}"),
            RuleMatcherV1::UrlRegex(value)
                if !value.is_empty()
                    && !value.chars().any(|character| character.is_ascii_control()) =>
            {
                format!("URL-REGEX,{value},{policy}")
            }
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
