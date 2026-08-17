use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};

use crate::{
    node::shadowsocks::ShadowsocksCredential,
    node::trojan::TrojanSecurity,
    node::vless::{ClientFingerprint, VlessFlow, VlessSecurity, VlessTransport},
    node::vmess::{VmessCipher, VmessSecurity},
    node::{NodeProtocol, ProxyNode},
    policy::{
        CompiledPolicyV1, CompiledRuleV1, GroupStrategyV1, IpVersion, PolicyMemberV1, RuleMatcherV1,
    },
    render::{
        AdapterRenderError, RenderedTargetV1, encode_hex, probe_url_or_default, reject_when_empty,
        render_host_plain, shadowsocks_method, shared_probe_url,
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
    let mut proxies = Vec::new();
    let mut valid_tags = Vec::new();
    let mut capability_skips = 0_u32;
    for node in named_nodes {
        let Some(tag) = loon_node_tag(node.name().as_str()) else {
            continue;
        };
        let Some(line) = render_proxy_line(node, tag) else {
            capability_skips = capability_skips.saturating_add(1);
            continue;
        };
        valid_tags.push(tag.to_owned());
        proxies.push(line);
    }
    if proxies.is_empty() {
        return Err(AdapterRenderError::NoValidNodes);
    }

    let valid = valid_tags.iter().map(String::as_str).collect::<Vec<_>>();
    let groups = render_groups(policy, &valid)?;
    let rules = render_rules(policy.rules(), &valid)?;

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
    if body.len() > limit_bytes {
        return Err(AdapterRenderError::OutputTooLarge { limit_bytes });
    }
    Ok(RenderedTargetV1 {
        bytes: body.into_bytes(),
        capability_skips,
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
    }
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
                quote(&URL_SAFE_NO_PAD.encode(options.public_key().as_bytes()))?
            ));
            if let Some(short_id) = options.short_id() {
                let hex = encode_hex(short_id.as_bytes());
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
    let password = match shadowsocks.credential() {
        ShadowsocksCredential::Password(password) => password.expose().to_owned(),
        ShadowsocksCredential::Psk(psk) => STANDARD.encode(psk.expose()),
    };
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
    match member {
        PolicyMemberV1::Direct => Ok(Some("DIRECT".to_owned())),
        PolicyMemberV1::Reject => Ok(Some("REJECT".to_owned())),
        PolicyMemberV1::Group(name) => loon_group_tag(name).map(|tag| Some(tag.to_owned())),
        PolicyMemberV1::Node(name) => Ok(valid_nodes
            .iter()
            .any(|candidate| *candidate == name)
            .then(|| name.clone())),
    }
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
) -> Result<Vec<String>, AdapterRenderError> {
    let mut lines = Vec::new();
    for rule in rules {
        let Some(policy) = member_token(rule.target(), valid_nodes)? else {
            continue;
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
            RuleMatcherV1::ProcessName(_)
            | RuleMatcherV1::Domain(_)
            | RuleMatcherV1::DomainSuffix(_)
            | RuleMatcherV1::DomainKeyword(_)
            | RuleMatcherV1::IpCidr { .. } => continue,
        };
        lines.push(line);
    }
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::{
        AdapterRenderError, CompiledPolicyV1, CompiledRuleV1, GroupStrategyV1, PolicyMemberV1,
        RuleMatcherV1, render_loon_from_policy_v1,
    };
    use crate::node_name::{NamedNodeOccurrence, resolve_node_names};
    use crate::policy::{CompiledGroupV1, IpVersion, PolicyReportV1, compile_builtin_policy_v1};
    use crate::render::{MAX_OUTPUT_BYTES, render_builtin_loon_v1};
    use crate::subscription_source::parse_subscription_sources;

    const BUILTIN_TCP_VLESS: &str = concat!(
        "[General]\n",
        "proxy-test-url = https://www.gstatic.com/generate_204\n",
        "\n",
        "[Proxy]\n",
        "Alpha = VLESS,example.com,443,\"01234567-89ab-cdef-0123-456789abcdef\",transport=tcp,over-tls=false,udp=true\n",
        "\n",
        "[Proxy Group]\n",
        "PROXY = select,AUTO,Alpha,DIRECT\n",
        "AUTO = url-test,Alpha,url = https://www.gstatic.com/generate_204,interval = 300\n",
        "\n",
        "[Rule]\n",
        "FINAL,PROXY\n",
    );

    #[test]
    fn builtin_tcp_vless_matches_the_frozen_loon_shape() {
        let parsed = parse_subscription_sources(&[
            &b"vless://01234567-89ab-cdef-0123-456789abcdef@EXAMPLE.COM:443#Alpha"[..],
        ])
        .expect("valid");
        let output = render_builtin_loon_v1(parsed).expect("rendered");
        assert_eq!(
            std::str::from_utf8(output.config()).expect("utf8"),
            BUILTIN_TCP_VLESS
        );
    }

    #[test]
    fn unsupported_vless_combinations_are_skipped() {
        let source = concat!(
            "vless://00000000-0000-4000-8000-000000000003@[2001:db8::1]:9443?type=grpc&serviceName=svc%2Fprod&security=reality&sni=reality.example&fp=safari&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&sid=0a1b#Grpc\n",
            "vless://00000000-0000-4000-8000-000000000004@vision.example:443?security=tls&flow=xtls-rprx-vision#Vision\n",
            "vless://00000000-0000-4000-8000-000000000005@reality.example:443?security=reality&sni=reality.example&fp=chrome&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&sid=0a1b#BareReality\n",
            "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha\n",
        );
        let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid");
        let output = render_builtin_loon_v1(parsed).expect("rendered");
        let text = std::str::from_utf8(output.config()).expect("utf8");
        assert!(text.contains("Alpha = VLESS"));
        assert!(!text.contains("Grpc ="));
        assert!(!text.contains("Vision ="));
        assert!(!text.contains("BareReality ="));
        assert!(!text.contains("grpc"));
        assert_eq!(output.diagnostics().capability_skips(), 3);
    }

    #[test]
    fn vmess_aes_is_exact_and_other_ciphers_are_skipped() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let id = "01234567-89ab-cdef-0123-456789abcdef";
        let encode = |json: &str| format!("vmess://{}", STANDARD.encode(json.as_bytes()));
        let source = [
            encode(&format!(
                r#"{{"ps":"Aes","add":"example.com","port":443,"id":"{id}","scy":"aes-128-gcm"}}"#
            )),
            encode(&format!(
                r#"{{"ps":"Auto","add":"example.com","port":443,"id":"{id}","scy":"auto"}}"#
            )),
            encode(&format!(
                r#"{{"ps":"Grpc","add":"example.com","port":443,"id":"{id}","scy":"aes-128-gcm","net":"grpc"}}"#
            )),
        ]
        .join("\n");
        let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid");
        let output = render_builtin_loon_v1(parsed).expect("rendered");
        let text = std::str::from_utf8(output.config()).expect("utf8");
        assert!(text.contains(
            "Aes = vmess,example.com,443,aes-128-gcm,\"01234567-89ab-cdef-0123-456789abcdef\",transport=tcp,alterId=0,over-tls=false,udp=true"
        ));
        assert!(!text.contains("Auto ="));
        assert!(!text.contains("Grpc ="));
        assert_eq!(output.diagnostics().capability_skips(), 2);
    }

    #[test]
    fn trojan_tcp_tls_is_exact_and_reality_grpc_are_skipped() {
        let source = concat!(
            "trojan://password@EXAMPLE.COM:443#TcpTls\n",
            "trojan://password@example.com:443?type=ws&path=%2Fws&host=cdn.example&fp=safari#Ws\n",
            "trojan://password@example.com:443?security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA#Reality\n",
            "trojan://password@example.com:443?type=grpc&serviceName=svc#Grpc\n",
        );
        let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid");
        let output = render_builtin_loon_v1(parsed).expect("rendered");
        let text = std::str::from_utf8(output.config()).expect("utf8");
        assert!(text.contains(
            "TcpTls = trojan,example.com,443,\"password\",sni=example.com,skip-cert-verify=false,tls-profile=chrome,udp=true"
        ));
        assert!(text.contains("transport=ws"));
        assert!(text.contains("path=/ws"));
        assert!(text.contains("host=cdn.example"));
        assert!(text.contains("tls-profile=safari"));
        assert!(!text.contains("Reality ="));
        assert!(!text.contains("Grpc ="));
        assert!(!text.contains("fast-open"));
        assert_eq!(output.diagnostics().capability_skips(), 2);
    }

    #[test]
    fn reality_vision_websocket_tls_and_shadowsocks_project_supported_fields() {
        let source = concat!(
            "vless://00000000-0000-4000-8000-000000000006@example.com:443?security=reality&flow=xtls-rprx-vision&sni=douyin.com&fp=safari&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&sid=0a1b#Reality\n",
            "vless://01234567-89ab-cdef-0123-456789abcdef@EXAMPLE.COM:443?type=ws&path=%2Fws&host=cdn.example&security=tls&sni=edge.example&alpn=h2&fp=firefox#WS\n",
            "ss://aes-128-gcm:p%40ss%3Aword@example.com:8388#Classic\n",
        );
        let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid");
        let output = render_builtin_loon_v1(parsed).expect("rendered");
        let text = std::str::from_utf8(output.config()).expect("utf8");
        assert!(text.contains("flow=xtls-rprx-vision"));
        assert!(text.contains("public-key=\""));
        assert!(text.contains("short-id=0a1b"));
        assert!(text.contains("sni=douyin.com"));
        assert!(text.contains("tls-profile=safari"));
        assert!(text.contains("transport=ws"));
        assert!(text.contains("path=/ws"));
        assert!(text.contains("host=cdn.example"));
        assert!(text.contains("sni=edge.example"));
        assert!(!text.contains("tls-profile=firefox"));
        assert!(!text.contains("alpn="));
        assert!(text.contains("Classic = Shadowsocks,example.com,8388,aes-128-gcm,\"p@ss:word\",fast-open=false,udp=true"));
    }

    #[test]
    fn process_name_is_omitted_and_fallback_load_balance_are_normalized() {
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
        let output = render_loon_from_policy_v1(&nodes, &policy, MAX_OUTPUT_BYTES).expect("ok");
        let text = std::str::from_utf8(&output.bytes).expect("utf8");
        assert!(text.contains(
            "Fallback = fallback,Alpha,url = https://www.gstatic.com/generate_204,interval = 60"
        ));
        assert!(text.contains(
            "Hash = load-balance,Alpha,url = https://www.gstatic.com/generate_204,interval = 30,algorithm = pcc"
        ));
        assert!(text.contains("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve"));
        assert!(text.contains("FINAL,DIRECT"));
        assert!(!text.contains("PROCESS"));
        assert!(!text.contains("Telegram"));
    }

    #[test]
    fn reserved_node_tags_are_skipped() {
        let parsed = parse_subscription_sources(&[
            &b"vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#reject\nvless://fedcba98-7654-3210-fedc-ba9876543210@example.net:8443#Alpha"[..],
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
        let policy = compile_builtin_policy_v1(&nodes);
        let output = render_loon_from_policy_v1(&nodes, &policy, MAX_OUTPUT_BYTES).expect("ok");
        let text = std::str::from_utf8(&output.bytes).expect("utf8");
        assert!(text.contains("Alpha = VLESS"));
        assert!(!text.contains("reject = VLESS"));
        assert!(!text.contains("example.com"));
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
        let error = render_loon_from_policy_v1(&nodes, &policy, MAX_OUTPUT_BYTES)
            .expect_err("reserved group");
        assert!(matches!(error, AdapterRenderError::Internal));
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
        let error = render_loon_from_policy_v1(&nodes, &policy, 8).expect_err("limit");
        assert!(matches!(
            error,
            AdapterRenderError::OutputTooLarge { limit_bytes: 8 }
        ));
    }

    #[test]
    fn debug_output_does_not_retain_node_names() {
        let parsed = parse_subscription_sources(&[
            &b"vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#SecretCanary"[..],
        ])
        .expect("valid");
        let output = render_builtin_loon_v1(parsed).expect("rendered");
        let debug = format!("{output:?}");
        assert!(!debug.contains("SecretCanary"));
        assert!(!debug.contains("gstatic"));
    }
}
