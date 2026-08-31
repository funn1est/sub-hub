use crate::OutputTarget;
use crate::SubscriptionSourceV1;
use crate::prepare_subscription_v1;
use crate::subscription_prepare::{render_acl4ssr_target, render_remote_builtin};

#[test]
fn vless_reality_with_spiderx_is_kept() {
    const UUID: &str = "01234567-89ab-cdef-0123-456789abcdef";
    const PBK: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let source = format!(
        concat!(
            "vless://{UUID}@example.com:443",
            "?security=reality&fp=chrome&pbk={PBK}&sid=0a1b&spx=%2F#WithSpx\n",
            "vless://{UUID}@example.com:443",
            "?security=reality&fp=chrome&pbk={PBK}&sid=0a1b&spiderx=%2F#WithSpiderx\n",
            "vless://{UUID}@example.com:443",
            "?security=reality&fp=chrome&pbk={PBK}&sid=0a1b#Plain\n",
        ),
        UUID = UUID,
        PBK = PBK
    );
    let output =
        render_remote_builtin(OutputTarget::Singbox, &[source.as_bytes()]).expect("rendered");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
    assert!(text.contains("\"tag\": \"WithSpx\""));
    assert!(text.contains("\"tag\": \"WithSpiderx\""));
    assert!(text.contains("\"tag\": \"Plain\""));
    assert_eq!(output.skip_counts().parse, 0);
    assert_eq!(output.skip_counts().capability, 0);
}

#[test]
fn vless_tls_default_client_flags_are_kept() {
    let source = concat!(
        "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443",
        "?security=tls&sni=cdn.example&fp=chrome&allowInsecure=0&insecure=0&udp=true#TlsFlags\n",
    );
    let output =
        render_remote_builtin(OutputTarget::Singbox, &[source.as_bytes()]).expect("rendered");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
    assert!(text.contains("\"tag\": \"TlsFlags\""));
    assert_eq!(output.skip_counts().parse, 0);
}

#[test]
fn grpc_and_vision_without_reality_are_kept() {
    let source = concat!(
        "vless://00000000-0000-4000-8000-000000000003@[2001:db8::1]:9443?type=grpc&serviceName=svc%2Fprod&security=reality&sni=reality.example&fp=safari&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&sid=0a1b#Reality\n",
        "vless://00000000-0000-4000-8000-000000000004@vision.example:443?security=tls&flow=xtls-rprx-vision#Vision\n",
    );
    let output =
        render_remote_builtin(OutputTarget::Singbox, &[source.as_bytes()]).expect("rendered");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
    assert!(text.contains("\"tag\": \"Reality\""));
    assert!(text.contains("\"type\": \"grpc\""));
    assert!(text.contains("\"service_name\": \"svc/prod\""));
    assert!(text.contains("\"server\": \"2001:db8::1\""));
    assert!(!text.contains("[2001:db8::1]"));
    assert!(text.contains("\"tag\": \"Vision\""));
    assert!(text.contains("\"flow\": \"xtls-rprx-vision\""));
    assert!(text.contains("\"fingerprint\": \"chrome\""));
    assert!(text.contains("\"fingerprint\": \"safari\""));
    assert_eq!(output.skip_counts().capability, 0);
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
    let output =
        render_remote_builtin(OutputTarget::Singbox, &[source.as_bytes()]).expect("rendered");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
    assert!(text.contains("\"type\": \"vmess\""));
    assert!(text.contains("\"tag\": \"Alpha\""));
    assert!(text.contains("\"security\": \"auto\""));
    assert!(text.contains("\"alter_id\": 0"));
    assert!(text.contains("\"tag\": \"Grpc\""));
    assert!(text.contains("\"type\": \"grpc\""));
    assert!(!text.contains("packet_encoding"));
    assert!(!text.contains("multiplex"));
    assert_eq!(output.skip_counts().capability, 0);
}

#[test]
fn trojan_tcp_tls_and_grpc_are_kept() {
    let source = concat!(
        "trojan://password@EXAMPLE.COM:443#Alpha\n",
        "trojan://password@example.com:443?type=grpc&serviceName=svc&security=tls#Grpc\n",
    );
    let output =
        render_remote_builtin(OutputTarget::Singbox, &[source.as_bytes()]).expect("rendered");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
    assert!(text.contains("\"type\": \"trojan\""));
    assert!(text.contains("\"tag\": \"Alpha\""));
    assert!(text.contains("\"password\": \"password\""));
    assert!(text.contains("\"enabled\": true"));
    assert!(text.contains("\"server_name\": \"example.com\""));
    assert!(text.contains("\"fingerprint\": \"chrome\""));
    assert!(text.contains("\"tag\": \"Grpc\""));
    assert!(text.contains("\"type\": \"grpc\""));
    assert!(!text.contains("multiplex"));
    assert_eq!(output.skip_counts().capability, 0);
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
    let output =
        render_remote_builtin(OutputTarget::Singbox, &[source.as_bytes()]).expect("rendered");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
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
    assert_eq!(output.skip_counts().capability, 2);
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
    let output =
        render_remote_builtin(OutputTarget::Singbox, &[source.as_bytes()]).expect("rendered");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
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
    assert_eq!(output.skip_counts().capability, 0);
}

#[test]
fn websocket_tls_and_shadowsocks_project_supported_fields() {
    let source = concat!(
        "vless://01234567-89ab-cdef-0123-456789abcdef@EXAMPLE.COM:443?type=ws&path=%2Fws&host=cdn.example&security=tls&sni=edge.example&alpn=h2%2Chttp%2F1.1&fp=firefox#WS\n",
        "ss://aes-128-gcm:p%40ss%3Aword@example.com:8388#Classic\n",
    );
    let output =
        render_remote_builtin(OutputTarget::Singbox, &[source.as_bytes()]).expect("rendered");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
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
    let output = prepare_subscription_v1(&[
        SubscriptionSourceV1::Direct(
            "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#direct",
        ),
        SubscriptionSourceV1::Direct(
            "vless://fedcba98-7654-3210-fedc-ba9876543210@example.net:8443#Alpha",
        ),
    ])
    .expect("valid")
    .render_builtin_v1(OutputTarget::Singbox)
    .expect("ok");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
    assert!(text.contains("\"tag\": \"Alpha\""));
    assert!(!text.contains("\"server\": \"example.com\""));
    assert_eq!(output.skip_counts().name, 1);
}

#[test]
fn only_reserved_node_tags_are_no_valid_nodes() {
    let error = prepare_subscription_v1(&[SubscriptionSourceV1::Direct(
        "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#reject",
    )])
    .expect("valid")
    .render_builtin_v1(OutputTarget::Singbox)
    .expect_err("no valid nodes");
    assert!(matches!(
        error,
        crate::ConversionRenderError::NoValidNodes { .. }
    ));
}

#[test]
fn fallback_and_load_balance_are_normalized_and_geoip_cn_is_omitted() {
    let config = concat!(
        "[custom]\n",
        "enable_rule_generator=true\n",
        "overwrite_original_rules=true\n",
        "custom_proxy_group=Fallback`fallback`.*`https://www.gstatic.com/generate_204`60\n",
        "custom_proxy_group=Hash`load-balance`.*`https://www.gstatic.com/generate_204`30\n",
        "ruleset=DIRECT,[]GEOIP,CN\n",
        "ruleset=Fallback,https://rules.example/rules.list\n",
        "ruleset=Fallback,[]FINAL\n",
    );
    let output = render_acl4ssr_target(
        OutputTarget::Singbox,
        "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha",
        config.as_bytes(),
        &[b"URL-REGEX,example.com/path\nDOMAIN-SUFFIX,example.com\n"],
    )
    .expect("ok");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
    assert!(text.contains("\"type\": \"urltest\""));
    assert!(text.contains("\"tag\": \"Fallback\""));
    assert!(text.contains("\"interval\": \"60s\""));
    assert!(text.contains("\"type\": \"selector\""));
    assert!(text.contains("\"tag\": \"Hash\""));
    assert!(!text.contains("geoip"));
    assert!(!text.contains("URL-REGEX"));
    assert!(!text.contains("example.com/path"));
    assert!(text.contains("\"domain_suffix\""));
    assert!(text.contains("example.com"));
    assert!(text.contains("\"final\": \"Fallback\""));
    assert!(!text.contains("\"outbound\": \"direct\""));
    assert_eq!(text.matches("\"outbound\":").count(), 1);
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
        OutputTarget::Singbox,
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
