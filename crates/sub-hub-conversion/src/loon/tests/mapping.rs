use super::accepted_nodes;
use crate::loon::render_loon_from_policy_v1;
use crate::node_name::resolve_node_names;
use crate::policy::{
    CompiledGroupV1, CompiledPolicyV1, CompiledRuleV1, GroupStrategyV1, IpVersion, PolicyMemberV1,
    PolicyReportV1, RuleMatcherV1, compile_builtin_policy_v1,
};
use crate::render::{AdapterRenderError, MAX_OUTPUT_BYTES, render_builtin_loon_v1};
use crate::subscription_source::parse_subscription_sources;

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
fn hysteria2_salamander_is_exact_and_gecko_hop_pin_are_skipped() {
    const PIN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let source = format!(
        concat!(
            "hysteria2://password@EXAMPLE.COM:443/?sni=example.com&obfs=salamander&obfs-password=gawrgura#Plain\n",
            "hysteria2://password@example.com/?obfs=gecko&obfs-password=secret#Gecko\n",
            "hysteria2://password@example.com:123,5000-6000/#Hop\n",
            "hysteria2://password@example.com/?pinSHA256={PIN}#Pin\n",
        ),
        PIN = PIN
    );
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid");
    let output = render_builtin_loon_v1(parsed).expect("rendered");
    let text = std::str::from_utf8(output.config()).expect("utf8");
    assert!(text.contains(
        "Plain = Hysteria2,example.com,443,\"password\",sni=example.com,skip-cert-verify=false,salamander-password=\"gawrgura\",udp=true"
    ));
    assert!(!text.contains("Gecko ="));
    assert!(!text.contains("Hop ="));
    assert!(!text.contains("Pin ="));
    assert!(!text.contains("fast-open"));
    assert_eq!(output.diagnostics().capability_skips(), 3);
}

#[test]
fn tuic_is_skipped_on_every_combo() {
    let source = concat!(
        "tuic://01234567-89ab-cdef-0123-456789abcdef:pass@EXAMPLE.COM:443#Plain\n",
        "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha\n",
    );
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid");
    let output = render_builtin_loon_v1(parsed).expect("rendered");
    let text = std::str::from_utf8(output.config()).expect("utf8");
    assert!(text.contains("Alpha = VLESS"));
    assert!(!text.contains("Plain ="));
    assert!(!text.contains("tuic"));
    assert_eq!(output.diagnostics().capability_skips(), 1);
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
    assert!(text.contains(
        "Classic = Shadowsocks,example.com,8388,aes-128-gcm,\"p@ss:word\",fast-open=false,udp=true"
    ));
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
    let output = render_loon_from_policy_v1(&nodes, &policy, MAX_OUTPUT_BYTES).expect("ok");
    let text = std::str::from_utf8(&output.bytes).expect("utf8");
    assert!(text.contains(
        "Fallback = fallback,Alpha,url = https://www.gstatic.com/generate_204,interval = 60"
    ));
    assert!(text.contains(
        "Hash = load-balance,Alpha,url = https://www.gstatic.com/generate_204,interval = 30,algorithm = pcc"
    ));
    assert!(text.contains("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve"));
    assert!(text.contains("URL-REGEX,example\\.com/path,DIRECT"));
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
    let nodes = accepted_nodes(&named);
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
    let error =
        render_loon_from_policy_v1(&nodes, &policy, MAX_OUTPUT_BYTES).expect_err("reserved group");
    assert!(matches!(error, AdapterRenderError::Internal));
}
