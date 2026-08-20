use super::accepted_nodes;
use crate::node_name::resolve_node_names;
use crate::policy::{
    CompiledGroupV1, CompiledPolicyV1, CompiledRuleV1, GroupStrategyV1, PolicyMemberV1,
    PolicyReportV1, RuleMatcherV1, compile_builtin_policy_v1,
};
use crate::render::{AdapterRenderError, MAX_OUTPUT_BYTES, render_builtin_singbox_v1};
use crate::singbox::render_singbox_from_policy_v1;
use crate::subscription_source::parse_subscription_sources;

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
    assert_eq!(output.diagnostics().capability_skips(), 0);
}

#[test]
fn vmess_tcp_and_grpc_are_kept() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let id = "01234567-89ab-cdef-0123-456789abcdef";
    let source = format!(
        "vmess://{}\nvmess://{}",
        STANDARD.encode(
            format!(
                r#"{{"ps":"Alpha","add":"EXAMPLE.COM","port":443,"id":"{id}","scy":"auto"}}"#
            )
            .as_bytes()
        ),
        STANDARD.encode(
            format!(
                r#"{{"ps":"Grpc","add":"example.com","port":443,"id":"{id}","scy":"zero","net":"grpc","path":"svc"}}"#
            )
            .as_bytes()
        )
    );
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid");
    let output = render_builtin_singbox_v1(parsed).expect("rendered");
    let text = std::str::from_utf8(output.config()).expect("utf8");
    assert!(text.contains("\"type\": \"vmess\""));
    assert!(text.contains("\"tag\": \"Alpha\""));
    assert!(text.contains("\"security\": \"auto\""));
    assert!(text.contains("\"alter_id\": 0"));
    assert!(text.contains("\"tag\": \"Grpc\""));
    assert!(text.contains("\"type\": \"grpc\""));
    assert!(!text.contains("packet_encoding"));
    assert!(!text.contains("multiplex"));
    assert_eq!(output.diagnostics().capability_skips(), 0);
}

#[test]
fn trojan_tcp_tls_and_grpc_are_kept() {
    let source = concat!(
        "trojan://password@EXAMPLE.COM:443#Alpha\n",
        "trojan://password@example.com:443?type=grpc&serviceName=svc&security=tls#Grpc\n",
    );
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid");
    let output = render_builtin_singbox_v1(parsed).expect("rendered");
    let text = std::str::from_utf8(output.config()).expect("utf8");
    assert!(text.contains("\"type\": \"trojan\""));
    assert!(text.contains("\"tag\": \"Alpha\""));
    assert!(text.contains("\"password\": \"password\""));
    assert!(text.contains("\"enabled\": true"));
    assert!(text.contains("\"server_name\": \"example.com\""));
    assert!(text.contains("\"fingerprint\": \"chrome\""));
    assert!(text.contains("\"tag\": \"Grpc\""));
    assert!(text.contains("\"type\": \"grpc\""));
    assert!(!text.contains("multiplex"));
    assert_eq!(output.diagnostics().capability_skips(), 0);
}

#[test]
fn hysteria2_salamander_and_hop_are_kept_gecko_and_pin_skipped() {
    const PIN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let source = format!(
        concat!(
            "hysteria2://password@EXAMPLE.COM:443/?sni=example.com&obfs=salamander&obfs-password=gawrgura#Plain\n",
            "hysteria2://password@example.com:123,5000-6000/#Hop\n",
            "hysteria2://password@example.com/?obfs=gecko&obfs-password=secret#Gecko\n",
            "hysteria2://password@example.com/?pinSHA256={PIN}#Pin\n",
        ),
        PIN = PIN
    );
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid");
    let output = render_builtin_singbox_v1(parsed).expect("rendered");
    let text = std::str::from_utf8(output.config()).expect("utf8");
    assert!(text.contains("\"type\": \"hysteria2\""));
    assert!(text.contains("\"tag\": \"Plain\""));
    assert!(text.contains("\"password\": \"password\""));
    assert!(text.contains("\"type\": \"salamander\""));
    assert!(text.contains("\"password\": \"gawrgura\""));
    assert!(text.contains("\"server_name\": \"example.com\""));
    assert!(text.contains("\"tag\": \"Hop\""));
    assert!(text.contains("\"123:123\""));
    assert!(text.contains("\"5000:6000\""));
    assert!(!text.contains("\"tag\": \"Gecko\""));
    assert!(!text.contains("\"tag\": \"Pin\""));
    assert!(!text.contains("certificate_public_key_sha256"));
    assert!(!text.contains("insecure"));
    assert_eq!(output.diagnostics().capability_skips(), 2);
}

#[test]
fn tuic_v5_defaults_and_options_are_kept() {
    const UUID: &str = "01234567-89ab-cdef-0123-456789abcdef";
    let source = format!(
        concat!(
            "tuic://{UUID}:pass@EXAMPLE.COM:443#Plain\n",
            "tuic://{UUID}:pass@example.com:8443/?sni=real.example&alpn=h3&congestion_control=bbr&udp_relay_mode=quic#Opts\n",
        ),
        UUID = UUID
    );
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid");
    let output = render_builtin_singbox_v1(parsed).expect("rendered");
    let text = std::str::from_utf8(output.config()).expect("utf8");
    assert!(text.contains("\"type\": \"tuic\""));
    assert!(text.contains("\"tag\": \"Plain\""));
    assert!(text.contains(&format!("\"uuid\": \"{UUID}\"")));
    assert!(text.contains("\"password\": \"pass\""));
    assert!(text.contains("\"enabled\": true"));
    assert!(!text.contains("\"congestion_control\": \"cubic\""));
    assert!(!text.contains("\"udp_relay_mode\": \"native\""));
    assert!(text.contains("\"tag\": \"Opts\""));
    assert!(text.contains("\"congestion_control\": \"bbr\""));
    assert!(text.contains("\"udp_relay_mode\": \"quic\""));
    assert!(text.contains("\"server_name\": \"real.example\""));
    assert!(text.contains("\"h3\""));
    assert!(!text.contains("insecure"));
    assert!(!text.contains("disable_sni"));
    assert!(!text.contains("udp_over_stream"));
    assert_eq!(output.diagnostics().capability_skips(), 0);
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
    let nodes = accepted_nodes(&named);
    assert_eq!(nodes.len(), 2);
    let policy = compile_builtin_policy_v1(&nodes);
    let output = render_singbox_from_policy_v1(&nodes, &policy, MAX_OUTPUT_BYTES).expect("ok");
    let text = std::str::from_utf8(&output.bytes).expect("utf8");
    assert!(text.contains("\"tag\": \"Alpha\""));
    assert!(!text.contains("\"server\": \"example.com\""));
}

#[test]
fn only_reserved_node_tags_are_no_valid_nodes() {
    let parsed = parse_subscription_sources(&[
        &b"vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#reject"[..],
    ])
    .expect("valid");
    let named = resolve_node_names(parsed, &["PROXY", "AUTO"]).expect("names");
    let nodes = accepted_nodes(&named);
    let policy = compile_builtin_policy_v1(&nodes);
    let error = render_singbox_from_policy_v1(&nodes, &policy, MAX_OUTPUT_BYTES)
        .expect_err("no valid nodes");
    assert!(matches!(error, AdapterRenderError::NoValidNodes { .. }));
}

#[test]
fn fallback_and_load_balance_are_normalized_and_geoip_cn_is_omitted() {
    let parsed = parse_subscription_sources(&[
        &b"vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha"[..],
    ])
    .expect("valid");
    let named = resolve_node_names(parsed, &["Fallback", "Hash"]).expect("names");
    let nodes = accepted_nodes(&named);
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
                RuleMatcherV1::UrlRegex("example\\.com/path".to_owned()),
                PolicyMemberV1::Direct,
            ),
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
    let output = render_singbox_from_policy_v1(&nodes, &policy, MAX_OUTPUT_BYTES).expect("ok");
    let text = std::str::from_utf8(&output.bytes).expect("utf8");
    assert!(text.contains("\"type\": \"urltest\""));
    assert!(text.contains("\"tag\": \"Fallback\""));
    assert!(text.contains("\"interval\": \"60s\""));
    assert!(text.contains("\"type\": \"selector\""));
    assert!(text.contains("\"tag\": \"Hash\""));
    assert!(!text.contains("geoip"));
    assert!(!text.contains("URL-REGEX"));
    assert!(!text.contains("example\\.com/path"));
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
    let nodes = accepted_nodes(&named);
    let policy = CompiledPolicyV1::new(
        vec![CompiledGroupV1::new(
            "direct".to_owned(),
            GroupStrategyV1::Select,
            vec![PolicyMemberV1::Node("Alpha".to_owned())],
        )],
        vec![],
        PolicyReportV1::default(),
    );
    let error = render_singbox_from_policy_v1(&nodes, &policy, MAX_OUTPUT_BYTES)
        .expect_err("reserved group");
    assert!(matches!(error, AdapterRenderError::Internal));
}
