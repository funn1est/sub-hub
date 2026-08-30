use crate::{
    node::hysteria2::Hysteria2Obfs,
    node::trojan::TrojanSecurity,
    node::vless::VlessTransport,
    node::vmess::{VmessCipher, VmessSecurity},
    node::{NodeProtocol, ProxyNode},
    policy::{CompiledPolicyV1, CompiledRuleV1, GroupStrategyV1, IpVersion, RuleMatcherV1},
    render::{
        AdapterRenderError, NodeKeep, RenderedTargetV1, WalkedGroupItem, bounded_text_sections,
        encode_hex, hysteria2_has_pin, is_safe_field as ini_safe_field, keep_named,
        keep_tagged_or_unexpanded, map_compiled_rules, policy_member_token, reject_when_empty,
        render_host_plain, reserved_group_tag, reserved_node_tag, shadowsocks_method,
        shadowsocks_password, shared_probe_url, walk_group_members,
    },
};

const RESERVED_NODE_TAGS: [&str; 2] = ["direct", "reject"];

pub(crate) fn render_surge_from_policy_v1(
    named_nodes: &[&ProxyNode],
    policy: &CompiledPolicyV1,
    limit_bytes: usize,
) -> Result<RenderedTargetV1, AdapterRenderError> {
    let (kept, valid_tags, proxies) = keep_tagged_or_unexpanded(named_nodes, policy, encode_node)?;
    let valid = valid_tags.iter().map(String::as_str).collect::<Vec<_>>();
    let groups = render_groups(policy, &valid)?;
    let (rules, omitted_url_regex) = render_rules(policy, &valid)?;

    let mut leading = String::new();
    if let Some(url) = shared_probe_url(policy) {
        if !is_safe_field(url) {
            return Err(AdapterRenderError::Internal);
        }
        leading.push_str("[General]\n");
        leading.push_str("proxy-test-url = ");
        leading.push_str(url);
        leading.push('\n');
        leading.push('\n');
    }
    let mut sections: Vec<(&str, &[String])> = Vec::new();
    if !proxies.is_empty() {
        sections.push(("[Proxy]", proxies.as_slice()));
    }
    sections.push(("[Proxy Group]", groups.as_slice()));
    if !rules.is_empty() {
        sections.push(("[Rule]", rules.as_slice()));
    }
    bounded_text_sections(&leading, &sections, limit_bytes, &kept, omitted_url_regex)
}

fn encode_node(node: &ProxyNode) -> Result<(String, String), NodeKeep> {
    keep_named(surge_node_tag(node.name().as_str()), |tag| {
        render_proxy_line(node, tag)
    })
}

fn surge_node_tag(name: &str) -> Option<&str> {
    reserved_node_tag(name, &RESERVED_NODE_TAGS)
}

fn surge_group_tag(name: &str) -> Result<&str, AdapterRenderError> {
    reserved_group_tag(name, &RESERVED_NODE_TAGS, &[])
}

fn is_safe_field(value: &str) -> bool {
    ini_safe_field(value, true)
}

fn render_proxy_line(node: &ProxyNode, tag: &str) -> Option<String> {
    let host = render_host_plain(node.endpoint().host());
    if !is_safe_field(&host) {
        return None;
    }
    let port = node.endpoint().port().get();
    match node.protocol() {
        NodeProtocol::Vless(_) => None,
        NodeProtocol::Shadowsocks(shadowsocks) => {
            if shadowsocks.obfs().is_some() {
                return None;
            }
            render_shadowsocks_line(tag, &host, port, shadowsocks)
        }
        NodeProtocol::Trojan(trojan) => render_trojan_line(tag, &host, port, trojan),
        NodeProtocol::Vmess(vmess) => render_vmess_line(tag, &host, port, vmess),
        NodeProtocol::Hysteria2(hysteria2) => render_hysteria2_line(tag, &host, port, hysteria2),
        NodeProtocol::Tuic(tuic) => render_tuic_line(tag, &host, port, tuic),
    }
}

fn render_shadowsocks_line(
    tag: &str,
    host: &str,
    port: u16,
    shadowsocks: &crate::node::shadowsocks::ShadowsocksNode,
) -> Option<String> {
    let password = shadowsocks_password(shadowsocks.credential());
    if !is_safe_field(&password) {
        return None;
    }
    Some(format!(
        "{tag} = ss, {host}, {port}, encrypt-method={}, password={password}",
        shadowsocks_method(shadowsocks.cipher())
    ))
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
    let password = trojan.password().expose();
    if !is_safe_field(password) {
        return None;
    }
    let TrojanSecurity::Tls(options) = trojan.security() else {
        return None;
    };
    if !is_safe_field(options.server_name()) {
        return None;
    }
    let mut fields = vec![
        format!("{tag} = trojan, {host}, {port}"),
        format!("password={password}"),
        format!("sni={}", options.server_name()),
        "skip-cert-verify=false".to_owned(),
    ];
    push_alpn(&mut fields, options.alpn())?;
    push_ws(&mut fields, trojan.transport())?;
    Some(fields.join(", "))
}

fn render_vmess_line(
    tag: &str,
    host: &str,
    port: u16,
    vmess: &crate::node::vmess::VmessNode,
) -> Option<String> {
    if !matches!(vmess.cipher(), VmessCipher::Aes128Gcm) {
        return None;
    }
    if matches!(vmess.transport(), VlessTransport::Grpc { .. }) {
        return None;
    }
    let uuid = vmess.id().as_uuid().hyphenated().to_string();
    if !is_safe_field(&uuid) {
        return None;
    }
    let mut fields = vec![
        format!("{tag} = vmess, {host}, {port}"),
        format!("username={uuid}"),
        "encrypt-method=aes-128-gcm".to_owned(),
    ];
    match vmess.security() {
        VmessSecurity::None => fields.push("tls=false".to_owned()),
        VmessSecurity::Tls(options) => {
            if !is_safe_field(options.server_name()) {
                return None;
            }
            fields.push("tls=true".to_owned());
            fields.push(format!("sni={}", options.server_name()));
            fields.push("skip-cert-verify=false".to_owned());
            push_alpn(&mut fields, options.alpn())?;
        }
    }
    push_ws(&mut fields, vmess.transport())?;
    Some(fields.join(", "))
}

fn render_hysteria2_line(
    tag: &str,
    host: &str,
    port: u16,
    hysteria2: &crate::node::hysteria2::Hysteria2Node,
) -> Option<String> {
    if hysteria2.ports().is_hop() {
        return None;
    }
    let password = hysteria2.auth().expose();
    if !is_safe_field(password) {
        return None;
    }
    let mut fields = vec![
        format!("{tag} = hysteria2, {host}, {port}"),
        format!("password={password}"),
    ];
    if let Some(sni) = hysteria2.sni() {
        if !is_safe_field(sni) {
            return None;
        }
        fields.push(format!("sni={sni}"));
    }
    match hysteria2.obfs() {
        Some(Hysteria2Obfs::Salamander { password }) => {
            if !is_safe_field(password) {
                return None;
            }
            fields.push(format!("salamander-password={password}"));
        }
        Some(Hysteria2Obfs::Gecko { password }) => {
            if !is_safe_field(password) {
                return None;
            }
            fields.push(format!("gecko-password={password}"));
        }
        None => {}
    }
    if hysteria2_has_pin(hysteria2) {
        let hex = encode_hex(hysteria2.pin_sha256()?);
        fields.push(format!("server-cert-fingerprint-sha256={hex}"));
    } else {
        fields.push("skip-cert-verify=false".to_owned());
    }
    Some(fields.join(", "))
}

fn render_tuic_line(
    tag: &str,
    host: &str,
    port: u16,
    tuic: &crate::node::tuic::TuicNode,
) -> Option<String> {
    if !tuic.congestion().is_default() || !tuic.udp_relay().is_default() {
        return None;
    }
    let uuid = tuic.id().as_uuid().hyphenated().to_string();
    let password = tuic.password().expose();
    if !is_safe_field(&uuid) || !is_safe_field(password) {
        return None;
    }
    let mut fields = vec![
        format!("{tag} = tuic-v5, {host}, {port}"),
        format!("uuid={uuid}"),
        format!("password={password}"),
        "skip-cert-verify=false".to_owned(),
    ];
    if let Some(sni) = tuic.sni() {
        if !is_safe_field(sni) {
            return None;
        }
        fields.push(format!("sni={sni}"));
    }
    push_alpn(&mut fields, tuic.alpn())?;
    Some(fields.join(", "))
}

fn push_alpn(fields: &mut Vec<String>, alpn: Option<&[String]>) -> Option<()> {
    if let Some(alpn) = alpn
        && alpn.len() == 1
    {
        if !is_safe_field(&alpn[0]) {
            return None;
        }
        fields.push(format!("alpn={}", alpn[0]));
    }
    Some(())
}

fn push_ws(fields: &mut Vec<String>, transport: &VlessTransport) -> Option<()> {
    match transport {
        VlessTransport::Tcp => Some(()),
        VlessTransport::WebSocket {
            path,
            host: ws_host,
        } => {
            if !is_safe_field(path) {
                return None;
            }
            fields.push("ws=true".to_owned());
            fields.push(format!("ws-path={path}"));
            if let Some(ws_host) = ws_host {
                if !is_safe_field(ws_host) {
                    return None;
                }
                fields.push(format!("ws-headers=Host:{ws_host}"));
            }
            Some(())
        }
        VlessTransport::Grpc { .. } => None,
    }
}

fn render_groups(
    policy: &CompiledPolicyV1,
    valid_nodes: &[&str],
) -> Result<Vec<String>, AdapterRenderError> {
    let remotes = policy.unexpanded_subscriptions();
    let mut lines = Vec::new();
    for group in policy.groups() {
        let name = surge_group_tag(group.name())?;
        let walked = walk_group_members(
            group.members(),
            "DIRECT",
            "REJECT",
            |name| surge_group_tag(name).map(|tag| Some(tag.to_owned())),
            valid_nodes,
            |_, token| token,
        )?;
        let unexpanded = walked.unexpanded();
        let mut members = Vec::new();
        for item in walked.items {
            match item {
                WalkedGroupItem::Token(token) => members.push(token),
                WalkedGroupItem::Unexpanded => {
                    for sub in remotes {
                        if !is_safe_field(sub.url()) {
                            return Err(AdapterRenderError::Internal);
                        }
                        members.push(format!("policy-path={}", sub.url()));
                    }
                }
            }
        }
        reject_when_empty(&mut members, "REJECT");
        let joined = members.join(", ");
        let mut line = match group.strategy() {
            GroupStrategyV1::Select => format!("{name} = select, {joined}"),
            GroupStrategyV1::UrlTest {
                interval,
                tolerance,
                ..
            } => {
                let mut line = format!("{name} = url-test, {joined}, interval={interval}");
                if let Some(tolerance) = tolerance {
                    line.push_str(", tolerance=");
                    line.push_str(&tolerance.to_string());
                }
                line
            }
            GroupStrategyV1::Fallback { interval, .. } => {
                format!("{name} = fallback, {joined}, interval={interval}")
            }
            GroupStrategyV1::LoadBalance { interval, .. } => {
                format!("{name} = load-balance, {joined}, persistent=true, interval={interval}")
            }
        };
        if unexpanded {
            line.push_str(", update-interval=86400");
        }
        lines.push(line);
    }
    Ok(lines)
}

fn render_rules(
    policy: &CompiledPolicyV1,
    valid_nodes: &[&str],
) -> Result<(Vec<String>, u8), AdapterRenderError> {
    let (mut rules, omitted_url_regex) =
        map_compiled_rules(policy.rules(), |rule| spell_rule(rule, valid_nodes))?;
    let mut finals = Vec::new();
    rules.retain(|line| {
        if line.starts_with("FINAL,") {
            finals.push(line.clone());
            false
        } else {
            true
        }
    });
    for rule_set in policy.remote_rule_sets() {
        if !is_safe_field(rule_set.url()) {
            return Err(AdapterRenderError::Internal);
        }
        let Some(policy_name) = policy_member_token(
            rule_set.target(),
            "DIRECT",
            "REJECT",
            |name| surge_group_tag(name).map(|tag| Some(tag.to_owned())),
            valid_nodes,
        )?
        else {
            continue;
        };
        rules.push(format!("RULE-SET,{},{policy_name}", rule_set.url()));
    }
    rules.extend(finals);
    Ok((rules, omitted_url_regex))
}

fn spell_rule(
    rule: &CompiledRuleV1,
    valid_nodes: &[&str],
) -> Result<Option<String>, AdapterRenderError> {
    let Some(policy) = policy_member_token(
        rule.target(),
        "DIRECT",
        "REJECT",
        |name| surge_group_tag(name).map(|tag| Some(tag.to_owned())),
        valid_nodes,
    )?
    else {
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
}

#[cfg(test)]
mod tests;
