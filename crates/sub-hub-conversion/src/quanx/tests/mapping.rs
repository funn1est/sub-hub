use super::accepted_nodes;
use crate::node_name::resolve_node_names;
use crate::policy::{
    CompiledGroupV1, CompiledPolicyV1, CompiledRuleV1, GroupStrategyV1, IpVersion, PolicyMemberV1,
    PolicyReportV1, RuleMatcherV1, compile_builtin_policy_v1,
};
use crate::quanx::render_quanx_from_policy_v1;
use crate::render::{MAX_OUTPUT_BYTES, render_builtin_quanx_v1};
use crate::subscription_source::parse_subscription_sources;

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
    assert_eq!(output.diagnostics().capability_skips(), 2);
}

#[test]
fn vmess_exact_ciphers_and_auto_grpc_skip() {
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
            r#"{{"ps":"Grpc","add":"example.com","port":443,"id":"{id}","scy":"none","net":"grpc","tls":"tls"}}"#
        )),
    ]
    .join("\n");
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid");
    let output = render_builtin_quanx_v1(parsed).expect("rendered");
    let text = std::str::from_utf8(output.config()).expect("utf8");
    assert!(text.contains(
        "vmess=example.com:443, method=aes-128-gcm, password=01234567-89ab-cdef-0123-456789abcdef"
    ));
    assert!(text.contains("tag=Aes"));
    assert!(!text.contains("tag=Auto"));
    assert!(!text.contains("tag=Grpc"));
    assert_eq!(output.diagnostics().capability_skips(), 2);
}

#[test]
fn trojan_exact_combos_and_grpc_skip() {
    let source = concat!(
        "trojan://password@EXAMPLE.COM:443#TcpTls\n",
        "trojan://password@example.com:443?security=reality&sni=apple.com&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0a1b#Reality\n",
        "trojan://password@example.com:443?type=ws&path=%2Fpath&host=example.com#Wss\n",
        "trojan://password@example.com:443?type=grpc&serviceName=svc#Grpc\n",
    );
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid");
    let output = render_builtin_quanx_v1(parsed).expect("rendered");
    let text = std::str::from_utf8(output.config()).expect("utf8");
    assert!(text.contains(
        "trojan=example.com:443, password=password, over-tls=true, tls-host=example.com, tls-verification=true, udp-relay=true, fast-open=false, tag=TcpTls"
    ));
    assert!(text.contains("tag=Reality"));
    assert!(text.contains("reality-base64-pubkey="));
    assert!(text.contains("obfs=wss"));
    assert!(text.contains("obfs-uri=/path"));
    assert!(text.contains("tag=Wss"));
    assert!(!text.contains("tag=Grpc"));
    assert!(!text.contains("grpc"));
    assert_eq!(output.diagnostics().capability_skips(), 1);
}

#[test]
fn hysteria2_is_skipped_on_every_combo() {
    let source = concat!(
        "hysteria2://password@EXAMPLE.COM:443#Plain\n",
        "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha\n",
    );
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid");
    let output = render_builtin_quanx_v1(parsed).expect("rendered");
    let text = std::str::from_utf8(output.config()).expect("utf8");
    assert!(text.contains("tag=Alpha"));
    assert!(!text.contains("tag=Plain"));
    assert!(!text.contains("hysteria"));
    assert_eq!(output.diagnostics().capability_skips(), 1);
}

#[test]
fn tuic_is_skipped_on_every_combo() {
    let source = concat!(
        "tuic://01234567-89ab-cdef-0123-456789abcdef:pass@EXAMPLE.COM:443#Plain\n",
        "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha\n",
    );
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid");
    let output = render_builtin_quanx_v1(parsed).expect("rendered");
    let text = std::str::from_utf8(output.config()).expect("utf8");
    assert!(text.contains("tag=Alpha"));
    assert!(!text.contains("tag=Plain"));
    assert!(!text.contains("tuic"));
    assert_eq!(output.diagnostics().capability_skips(), 1);
}

#[test]
fn websocket_tls_and_shadowsocks_project_supported_fields() {
    let source = concat!(
        "vless://01234567-89ab-cdef-0123-456789abcdef@EXAMPLE.COM:443?type=ws&path=%2Fws&host=cdn.example&security=tls&sni=edge.example#WS\n",
        "ss://aes-128-gcm:p%40ss%3Aword@example.com:8388#Classic\n",
    );
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid");
    let output = render_builtin_quanx_v1(parsed).expect("rendered");
    let text = std::str::from_utf8(output.config()).expect("utf8");
    assert!(text.contains("obfs=wss"));
    assert!(text.contains("obfs-host=cdn.example"));
    assert!(text.contains("obfs-uri=/ws"));
    assert!(text.contains("tag=WS"));
    assert!(text.contains(
        "shadowsocks=example.com:8388, method=aes-128-gcm, password=p@ss:word, udp-relay=true, fast-open=false, tag=Classic"
    ));
}

#[test]
fn reserved_node_tags_are_skipped() {
    let parsed = parse_subscription_sources(&[
        &b"vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#proxy\nvless://fedcba98-7654-3210-fedc-ba9876543210@example.net:8443#Alpha"[..],
    ])
    .expect("valid");
    let named = resolve_node_names(parsed, &["PROXY", "AUTO"]).expect("names");
    let nodes = accepted_nodes(&named);
    assert_eq!(nodes.len(), 2);
    let policy = compile_builtin_policy_v1(&nodes);
    let output = render_quanx_from_policy_v1(&nodes, &policy, MAX_OUTPUT_BYTES).expect("ok");
    let text = std::str::from_utf8(&output.bytes).expect("utf8");
    assert!(text.contains("tag=Alpha"));
    assert!(!text.contains("tag=proxy"));
    assert!(!text.contains("example.com"));
}

#[test]
fn process_name_is_omitted_and_fallback_load_balance_are_normalized() {
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
            CompiledRuleV1::new(
                RuleMatcherV1::ProcessName("Telegram.exe".to_owned()),
                PolicyMemberV1::Direct,
            ),
            CompiledRuleV1::new(
                RuleMatcherV1::UrlRegex("example\\.com/path".to_owned()),
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
    let output = render_quanx_from_policy_v1(&nodes, &policy, MAX_OUTPUT_BYTES).expect("ok");
    let text = std::str::from_utf8(&output.bytes).expect("utf8");
    assert!(text.contains("available = Fallback, Alpha"));
    assert!(text.contains("dest-hash = Hash, Alpha"));
    assert!(text.contains("ip-cidr, 10.0.0.0/8, direct"));
    assert!(text.contains("final, direct"));
    assert!(!text.contains("PROCESS"));
    assert!(!text.contains("Telegram"));
    assert!(!text.contains("URL-REGEX"));
    assert!(!text.contains("example\\.com/path"));
}

#[test]
fn empty_members_become_reject() {
    let parsed = parse_subscription_sources(&[
        &b"vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha"[..],
    ])
    .expect("valid");
    let named = resolve_node_names(parsed, &["Empty"]).expect("names");
    let nodes = accepted_nodes(&named);
    let policy = CompiledPolicyV1::new(
        vec![CompiledGroupV1::new(
            "Empty".to_owned(),
            GroupStrategyV1::Select,
            vec![],
        )],
        vec![],
        PolicyReportV1::default(),
    );
    let output = render_quanx_from_policy_v1(&nodes, &policy, MAX_OUTPUT_BYTES).expect("ok");
    let text = std::str::from_utf8(&output.bytes).expect("utf8");
    assert!(text.contains("static = Empty, reject"));
}
