use crate::OutputTarget;
use crate::SubscriptionSourceV1;
use crate::prepare_subscription_v1;
use crate::subscription_prepare::{render_acl4ssr_target, render_remote_builtin};

#[test]
fn grpc_and_vision_without_reality_are_skipped() {
    let source = concat!(
        "vless://00000000-0000-4000-8000-000000000003@[2001:db8::1]:9443?type=grpc&serviceName=svc%2Fprod&security=reality&sni=reality.example&fp=safari&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&sid=0a1b#Reality\n",
        "vless://00000000-0000-4000-8000-000000000004@vision.example:443?security=tls&flow=xtls-rprx-vision#Vision\n",
        "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha\n",
    );
    let output =
        render_remote_builtin(OutputTarget::Quanx, &[source.as_bytes()]).expect("rendered");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
    assert!(text.contains("tag=Alpha"));
    assert!(!text.contains("tag=Reality"));
    assert!(!text.contains("tag=Vision"));
    assert!(!text.contains("grpc"));
    assert_eq!(output.skip_counts().capability, 2);
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
    let output =
        render_remote_builtin(OutputTarget::Quanx, &[source.as_bytes()]).expect("rendered");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
    assert!(text.contains(
        "vmess=example.com:443, method=aes-128-gcm, password=01234567-89ab-cdef-0123-456789abcdef"
    ));
    assert!(text.contains("tag=Aes"));
    assert!(!text.contains("tag=Auto"));
    assert!(!text.contains("tag=Grpc"));
    assert_eq!(output.skip_counts().capability, 2);
}

#[test]
fn trojan_exact_combos_and_grpc_skip() {
    let source = concat!(
        "trojan://password@EXAMPLE.COM:443#TcpTls\n",
        "trojan://password@example.com:443?security=reality&sni=apple.com&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0a1b#Reality\n",
        "trojan://password@example.com:443?type=ws&path=%2Fpath&host=example.com#Wss\n",
        "trojan://password@example.com:443?type=grpc&serviceName=svc#Grpc\n",
    );
    let output =
        render_remote_builtin(OutputTarget::Quanx, &[source.as_bytes()]).expect("rendered");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
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
    assert_eq!(output.skip_counts().capability, 1);
}

#[test]
fn hysteria2_is_skipped_on_every_combo() {
    let source = concat!(
        "hysteria2://password@EXAMPLE.COM:443#Plain\n",
        "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha\n",
    );
    let output =
        render_remote_builtin(OutputTarget::Quanx, &[source.as_bytes()]).expect("rendered");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
    assert!(text.contains("tag=Alpha"));
    assert!(!text.contains("tag=Plain"));
    assert!(!text.contains("hysteria"));
    assert_eq!(output.skip_counts().capability, 1);
}

#[test]
fn tuic_is_skipped_on_every_combo() {
    let source = concat!(
        "tuic://01234567-89ab-cdef-0123-456789abcdef:pass@EXAMPLE.COM:443#Plain\n",
        "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha\n",
    );
    let output =
        render_remote_builtin(OutputTarget::Quanx, &[source.as_bytes()]).expect("rendered");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
    assert!(text.contains("tag=Alpha"));
    assert!(!text.contains("tag=Plain"));
    assert!(!text.contains("tuic"));
    assert_eq!(output.skip_counts().capability, 1);
}

#[test]
fn websocket_tls_and_shadowsocks_project_supported_fields() {
    let source = concat!(
        "vless://01234567-89ab-cdef-0123-456789abcdef@EXAMPLE.COM:443?type=ws&path=%2Fws&host=cdn.example&security=tls&sni=edge.example#WS\n",
        "ss://aes-128-gcm:p%40ss%3Aword@example.com:8388#Classic\n",
    );
    let output =
        render_remote_builtin(OutputTarget::Quanx, &[source.as_bytes()]).expect("rendered");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
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
    let output = prepare_subscription_v1(&[
        SubscriptionSourceV1::Direct(
            "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#proxy",
        ),
        SubscriptionSourceV1::Direct(
            "vless://fedcba98-7654-3210-fedc-ba9876543210@example.net:8443#Alpha",
        ),
    ])
    .expect("valid")
    .render_builtin_v1(OutputTarget::Quanx)
    .expect("ok");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
    assert!(text.contains("tag=Alpha"));
    assert!(!text.contains("tag=proxy"));
    assert!(!text.contains("example.com"));
    assert_eq!(output.skip_counts().name, 1);
}

#[test]
fn process_name_is_omitted_and_fallback_load_balance_are_normalized() {
    let config = concat!(
        "[custom]\n",
        "enable_rule_generator=true\n",
        "overwrite_original_rules=true\n",
        "custom_proxy_group=Fallback`fallback`.*`https://www.gstatic.com/generate_204`60\n",
        "custom_proxy_group=Hash`load-balance`.*`https://www.gstatic.com/generate_204`30\n",
        "ruleset=DIRECT,https://rules.example/rules.list\n",
        "ruleset=DIRECT,[]FINAL\n",
    );
    let output = render_acl4ssr_target(
        OutputTarget::Quanx,
        "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha",
        config.as_bytes(),
        &[b"PROCESS-NAME,Telegram.exe\nURL-REGEX,example.com/path\nIP-CIDR,10.0.0.0/8,no-resolve\n"],
    )
    .expect("ok");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
    assert!(text.contains("available = Fallback, Alpha"));
    assert!(text.contains("dest-hash = Hash, Alpha"));
    assert!(text.contains("ip-cidr, 10.0.0.0/8, direct"));
    assert!(text.contains("final, direct"));
    assert!(!text.contains("PROCESS"));
    assert!(!text.contains("Telegram"));
    assert!(!text.contains("URL-REGEX"));
    assert!(!text.contains("example.com/path"));
}

#[test]
fn empty_members_become_reject() {
    let config = concat!(
        "[custom]\n",
        "enable_rule_generator=true\n",
        "overwrite_original_rules=true\n",
        "custom_proxy_group=Empty`select`^nomatch$\n",
        "ruleset=Empty,[]FINAL\n",
    );
    let output = render_acl4ssr_target(
        OutputTarget::Quanx,
        "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha",
        config.as_bytes(),
        &[],
    )
    .expect("ok");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
    assert!(text.contains("static = Empty, reject"));
}
