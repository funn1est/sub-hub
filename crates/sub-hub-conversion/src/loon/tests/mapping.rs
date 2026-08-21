use crate::OutputTarget;
use crate::SubscriptionSourceV1;
use crate::direct_subscription::{render_acl4ssr_target, render_remote_builtin};
use crate::prepare_subscription_v1;

#[test]
fn unsupported_vless_combinations_are_skipped() {
    let source = concat!(
        "vless://00000000-0000-4000-8000-000000000003@[2001:db8::1]:9443?type=grpc&serviceName=svc%2Fprod&security=reality&sni=reality.example&fp=safari&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&sid=0a1b#Grpc\n",
        "vless://00000000-0000-4000-8000-000000000004@vision.example:443?security=tls&flow=xtls-rprx-vision#Vision\n",
        "vless://00000000-0000-4000-8000-000000000005@reality.example:443?security=reality&sni=reality.example&fp=chrome&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&sid=0a1b#BareReality\n",
        "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha\n",
    );
    let output = render_remote_builtin(OutputTarget::Loon, &[source.as_bytes()]).expect("rendered");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
    assert!(text.contains("Alpha = VLESS"));
    assert!(!text.contains("Grpc ="));
    assert!(!text.contains("Vision ="));
    assert!(!text.contains("BareReality ="));
    assert!(!text.contains("grpc"));
    assert_eq!(output.skip_counts().capability, 3);
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
    let output = render_remote_builtin(OutputTarget::Loon, &[source.as_bytes()]).expect("rendered");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
    assert!(text.contains(
        "Aes = vmess,example.com,443,aes-128-gcm,\"01234567-89ab-cdef-0123-456789abcdef\",transport=tcp,alterId=0,over-tls=false,udp=true"
    ));
    assert!(!text.contains("Auto ="));
    assert!(!text.contains("Grpc ="));
    assert_eq!(output.skip_counts().capability, 2);
}

#[test]
fn trojan_tcp_tls_is_exact_and_reality_grpc_are_skipped() {
    let source = concat!(
        "trojan://password@EXAMPLE.COM:443#TcpTls\n",
        "trojan://password@example.com:443?type=ws&path=%2Fws&host=cdn.example&fp=safari#Ws\n",
        "trojan://password@example.com:443?security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA#Reality\n",
        "trojan://password@example.com:443?type=grpc&serviceName=svc#Grpc\n",
    );
    let output = render_remote_builtin(OutputTarget::Loon, &[source.as_bytes()]).expect("rendered");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
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
    assert_eq!(output.skip_counts().capability, 2);
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
    let output = render_remote_builtin(OutputTarget::Loon, &[source.as_bytes()]).expect("rendered");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
    assert!(text.contains(
        "Plain = Hysteria2,example.com,443,\"password\",sni=example.com,skip-cert-verify=false,salamander-password=\"gawrgura\",udp=true"
    ));
    assert!(!text.contains("Gecko ="));
    assert!(!text.contains("Hop ="));
    assert!(!text.contains("Pin ="));
    assert!(!text.contains("fast-open"));
    assert_eq!(output.skip_counts().capability, 3);
}

#[test]
fn tuic_is_skipped_on_every_combo() {
    let source = concat!(
        "tuic://01234567-89ab-cdef-0123-456789abcdef:pass@EXAMPLE.COM:443#Plain\n",
        "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha\n",
    );
    let output = render_remote_builtin(OutputTarget::Loon, &[source.as_bytes()]).expect("rendered");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
    assert!(text.contains("Alpha = VLESS"));
    assert!(!text.contains("Plain ="));
    assert!(!text.contains("tuic"));
    assert_eq!(output.skip_counts().capability, 1);
}

#[test]
fn reality_vision_websocket_tls_and_shadowsocks_project_supported_fields() {
    let source = concat!(
        "vless://00000000-0000-4000-8000-000000000006@example.com:443?security=reality&flow=xtls-rprx-vision&sni=douyin.com&fp=safari&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&sid=0a1b#Reality\n",
        "vless://01234567-89ab-cdef-0123-456789abcdef@EXAMPLE.COM:443?type=ws&path=%2Fws&host=cdn.example&security=tls&sni=edge.example&alpn=h2&fp=firefox#WS\n",
        "ss://aes-128-gcm:p%40ss%3Aword@example.com:8388#Classic\n",
    );
    let output = render_remote_builtin(OutputTarget::Loon, &[source.as_bytes()]).expect("rendered");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
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
        OutputTarget::Loon,
        "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha",
        config.as_bytes(),
        &[b"PROCESS-NAME,Telegram.exe\nURL-REGEX,example.com/path\nIP-CIDR,10.0.0.0/8,no-resolve\n"],
    )
    .expect("ok");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
    assert!(text.contains(
        "Fallback = fallback,Alpha,url = https://www.gstatic.com/generate_204,interval = 60"
    ));
    assert!(text.contains(
        "Hash = load-balance,Alpha,url = https://www.gstatic.com/generate_204,interval = 30,algorithm = pcc"
    ));
    assert!(text.contains("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve"));
    assert!(text.contains("URL-REGEX,example.com/path,DIRECT"));
    assert!(text.contains("FINAL,DIRECT"));
    assert!(!text.contains("PROCESS"));
    assert!(!text.contains("Telegram"));
}

#[test]
fn reserved_node_tags_are_skipped() {
    let output = prepare_subscription_v1(&[
        SubscriptionSourceV1::Direct(
            "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#reject",
        ),
        SubscriptionSourceV1::Direct(
            "vless://fedcba98-7654-3210-fedc-ba9876543210@example.net:8443#Alpha",
        ),
    ])
    .expect("valid")
    .render_builtin_v1(OutputTarget::Loon)
    .expect("ok");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
    assert!(text.contains("Alpha = VLESS"));
    assert!(!text.contains("reject = VLESS"));
    assert!(!text.contains("example.com"));
    assert_eq!(output.skip_counts().name, 1);
}

#[test]
fn group_named_direct_is_internal() {
    let config = concat!(
        "[custom]\n",
        "enable_rule_generator=true\n",
        "overwrite_original_rules=true\n",
        "custom_proxy_group=direct`select`.*\n",
        "ruleset=direct,[]FINAL\n",
    );
    let error = render_acl4ssr_target(
        OutputTarget::Loon,
        "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha",
        config.as_bytes(),
        &[],
    )
    .expect_err("reserved group");
    assert_eq!(
        error.keep_pass(),
        Ok(crate::ConversionRenderError::Internal)
    );
}
