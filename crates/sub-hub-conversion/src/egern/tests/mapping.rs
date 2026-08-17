use super::accepted_nodes;
use crate::egern::render_egern_from_policy_v1;
use crate::node_name::resolve_node_names;
use crate::policy::{
    CompiledGroupV1, CompiledPolicyV1, CompiledRuleV1, GroupStrategyV1, IpVersion, PolicyMemberV1,
    PolicyReportV1, RuleMatcherV1,
};
use crate::render::{MAX_OUTPUT_BYTES, render_builtin_egern_v1};
use crate::subscription_source::parse_subscription_sources;

#[test]
fn vmess_tcp_tls_is_exact_and_cleartext_grpc_is_skipped() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let id = "01234567-89ab-cdef-0123-456789abcdef";
    let encode = |json: &str| format!("vmess://{}", STANDARD.encode(json.as_bytes()));
    let source = [
        encode(&format!(
            r#"{{"ps":"TcpTls","add":"EXAMPLE.COM","port":443,"id":"{id}","scy":"auto","tls":"tls"}}"#
        )),
        encode(&format!(
            r#"{{"ps":"Grpc","add":"example.com","port":443,"id":"{id}","scy":"none","net":"grpc"}}"#
        )),
    ]
    .join("\n");
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid");
    let output = render_builtin_egern_v1(parsed).expect("rendered");
    let text = std::str::from_utf8(output.config()).expect("utf8");
    assert!(text.contains("name: TcpTls"));
    assert!(text.contains("user_id: 01234567-89ab-cdef-0123-456789abcdef"));
    assert!(text.contains("security: auto"));
    assert!(text.contains("legacy: false"));
    assert!(text.contains("skip_tls_verify: false"));
    assert!(!text.contains("name: Grpc"));
    assert_eq!(output.diagnostics().capability_skips(), 1);
}

#[test]
fn trojan_tcp_tls_is_exact_and_grpc_is_skipped() {
    let source = concat!(
        "trojan://password@EXAMPLE.COM:443#TcpTls\n",
        "trojan://password@example.com:443?type=ws&path=%2Fws&host=cdn.example&security=reality&sni=edge.example&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0a1b#WsReality\n",
        "trojan://password@example.com:443?type=grpc&serviceName=svc#Grpc\n",
    );
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid");
    let output = render_builtin_egern_v1(parsed).expect("rendered");
    let text = std::str::from_utf8(output.config()).expect("utf8");
    assert!(text.contains(concat!(
        "- trojan:\n",
        "    name: TcpTls\n",
        "    server: example.com\n",
        "    port: 443\n",
        "    password: password\n",
        "    sni: example.com\n",
        "    tfo: false\n",
        "    udp_relay: true\n",
        "    skip_tls_verify: false\n",
    )));
    assert!(text.contains("name: WsReality"));
    assert!(text.contains("websocket:"));
    assert!(text.contains("path: /ws"));
    assert!(text.contains("host: cdn.example"));
    assert!(text.contains("reality:"));
    assert!(text.contains("public_key:"));
    assert!(!text.contains("name: Grpc"));
    assert!(!text.contains("fingerprint"));
    assert_eq!(output.diagnostics().capability_skips(), 1);
}

#[test]
fn hysteria2_salamander_hop_and_pin_are_exact_gecko_is_skipped() {
    const PIN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let source = format!(
        concat!(
            "hysteria2://password@EXAMPLE.COM:443/?sni=example.com&obfs=salamander&obfs-password=gawrgura#Plain\n",
            "hysteria2://password@example.com:123,5000-6000/#Hop\n",
            "hysteria2://password@example.com/?pinSHA256={PIN}#Pin\n",
            "hysteria2://password@example.com/?obfs=gecko&obfs-password=secret#Gecko\n",
        ),
        PIN = PIN
    );
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid");
    let output = render_builtin_egern_v1(parsed).expect("rendered");
    let text = std::str::from_utf8(output.config()).expect("utf8");
    assert!(text.contains(concat!(
        "- hysteria2:\n",
        "    name: Plain\n",
        "    server: example.com\n",
        "    port: 443\n",
        "    auth: password\n",
        "    sni: example.com\n",
        "    obfs: salamander\n",
        "    obfs_password: gawrgura\n",
        "    skip_tls_verify: false\n",
    )));
    assert!(text.contains("name: Hop"));
    assert!(text.contains("port_hopping:"));
    assert!(text.contains("123,5000-6000"));
    assert!(text.contains("name: Pin"));
    assert!(text.contains("fingerprint_sha256:"));
    assert!(text.contains(PIN));
    assert!(!text.contains("name: Gecko"));
    assert_eq!(output.diagnostics().capability_skips(), 1);
}

#[test]
fn tuic_defaults_and_quic_are_exact_and_bbr_is_skipped() {
    const UUID: &str = "01234567-89ab-cdef-0123-456789abcdef";
    let source = format!(
        concat!(
            "tuic://{UUID}:pass@EXAMPLE.COM:443/?sni=example.com#Plain\n",
            "tuic://{UUID}:pass@example.com:443/?udp_relay_mode=quic#Quic\n",
            "tuic://{UUID}:pass@example.com:443/?congestion_control=bbr#Bbr\n",
        ),
        UUID = UUID
    );
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid");
    let output = render_builtin_egern_v1(parsed).expect("rendered");
    let text = std::str::from_utf8(output.config()).expect("utf8");
    assert!(text.contains(concat!(
        "- tuic:\n",
        "    name: Plain\n",
        "    server: example.com\n",
        "    port: 443\n",
        "    uuid: 01234567-89ab-cdef-0123-456789abcdef\n",
        "    password: pass\n",
        "    sni: example.com\n",
        "    skip_tls_verify: false\n",
    )));
    assert!(text.contains("name: Quic"));
    assert!(text.contains("udp_relay_mode: quic"));
    assert!(!text.contains("name: Bbr"));
    assert_eq!(output.diagnostics().capability_skips(), 1);
}

#[test]
fn websocket_reality_is_skipped_and_grpc_vision_are_kept() {
    let source = concat!(
        "vless://00000000-0000-4000-8000-000000000003@[2001:db8::1]:9443?type=grpc&serviceName=svc%2Fprod&security=reality&sni=reality.example&fp=safari&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&sid=0a1b#Grpc\n",
        "vless://00000000-0000-4000-8000-000000000004@vision.example:443?security=tls&flow=xtls-rprx-vision#Vision\n",
        "vless://00000000-0000-4000-8000-000000000005@ws.example:443?type=ws&path=%2Fws&security=reality&sni=edge.example&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8#WsReality\n",
    );
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid");
    let output = render_builtin_egern_v1(parsed).expect("rendered");
    let text = std::str::from_utf8(output.config()).expect("utf8");
    assert!(text.contains("name: Grpc"));
    assert!(text.contains("name: Vision"));
    assert!(text.contains("flow: xtls-rprx-vision"));
    assert!(text.contains("grpc:"));
    assert!(text.contains("service_name: svc/prod"));
    assert!(text.contains("server: 2001:db8::1"));
    assert!(!text.contains("name: WsReality"));
    assert!(!text.contains("fingerprint"));
    // WebSocket+Reality is already rejected by the share-URI parser, so it
    // surfaces as an upstream rejection, not an adapter capability skip.
    assert_eq!(output.diagnostics().rejections().len(), 1);
    assert_eq!(output.diagnostics().capability_skips(), 0);
}

#[test]
fn process_name_is_omitted_and_load_balance_uses_hash() {
    let parsed = parse_subscription_sources(&[
        &b"vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha"[..],
    ])
    .expect("valid");
    let named = resolve_node_names(parsed, &["Hash"]).expect("names");
    let nodes = accepted_nodes(&named);
    let policy = CompiledPolicyV1::new(
        vec![CompiledGroupV1::new(
            "Hash".to_owned(),
            GroupStrategyV1::LoadBalance {
                url: String::new(),
                interval: 30,
            },
            vec![PolicyMemberV1::Node("Alpha".to_owned())],
        )],
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
    let output = render_egern_from_policy_v1(&nodes, &policy, MAX_OUTPUT_BYTES).expect("ok");
    let text = std::str::from_utf8(&output.bytes).expect("utf8");
    assert!(text.contains("load_balance:"));
    assert!(text.contains("algorithm: hash"));
    assert!(text.contains("ip_cidr:"));
    assert!(text.contains("no_resolve: true"));
    assert!(text.contains("default:\n    policy: DIRECT"));
    assert!(!text.contains("Telegram"));
    assert!(!text.contains("process"));
}
