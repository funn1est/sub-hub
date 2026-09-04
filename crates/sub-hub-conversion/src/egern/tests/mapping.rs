use crate::OutputTarget;
use crate::SubscriptionSourceV1;
use crate::prepare_subscription_v1;
use crate::subscription_prepare::{render_acl4ssr_target, render_remote_builtin};

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
    let output =
        render_remote_builtin(OutputTarget::Egern, &[source.as_bytes()]).expect("rendered");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
    assert!(text.contains("name: TcpTls"));
    assert!(text.contains("user_id: 01234567-89ab-cdef-0123-456789abcdef"));
    assert!(text.contains("security: auto"));
    assert!(text.contains("legacy: false"));
    assert!(text.contains("skip_tls_verify: false"));
    assert!(!text.contains("name: Grpc"));
    assert_eq!(output.skip_counts().capability, 1);
}

#[test]
fn trojan_tcp_tls_is_exact_and_grpc_is_skipped() {
    let source = concat!(
        "trojan://password@EXAMPLE.COM:443#TcpTls\n",
        "trojan://password@example.com:443?type=ws&path=%2Fws&host=cdn.example&security=reality&sni=edge.example&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0a1b#WsReality\n",
        "trojan://password@example.com:443?type=grpc&serviceName=svc#Grpc\n",
    );
    let output =
        render_remote_builtin(OutputTarget::Egern, &[source.as_bytes()]).expect("rendered");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
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
    assert_eq!(output.skip_counts().capability, 1);
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
    let output =
        render_remote_builtin(OutputTarget::Egern, &[source.as_bytes()]).expect("rendered");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
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
    assert_eq!(output.skip_counts().capability, 1);
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
    let output =
        render_remote_builtin(OutputTarget::Egern, &[source.as_bytes()]).expect("rendered");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
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
    assert_eq!(output.skip_counts().capability, 1);
}

#[test]
fn websocket_reality_is_skipped_and_grpc_vision_are_kept() {
    let source = concat!(
        "vless://00000000-0000-4000-8000-000000000003@[2001:db8::1]:9443?type=grpc&serviceName=svc%2Fprod&security=reality&sni=reality.example&fp=safari&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&sid=0a1b#Grpc\n",
        "vless://00000000-0000-4000-8000-000000000004@vision.example:443?security=tls&flow=xtls-rprx-vision#Vision\n",
        "vless://00000000-0000-4000-8000-000000000005@ws.example:443?type=ws&path=%2Fws&security=reality&sni=edge.example&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8#WsReality\n",
    );
    let output =
        render_remote_builtin(OutputTarget::Egern, &[source.as_bytes()]).expect("rendered");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
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
    assert_eq!(output.skip_counts().parse as usize, 1);
    assert_eq!(output.skip_counts().capability, 0);
}

#[test]
fn process_name_is_omitted_and_load_balance_uses_hash() {
    let config = concat!(
        "[custom]\n",
        "enable_rule_generator=true\n",
        "overwrite_original_rules=true\n",
        "custom_proxy_group=Hash`load-balance`.*`https://www.gstatic.com/generate_204`30\n",
        "ruleset=DIRECT,https://rules.example/rules.list\n",
        "ruleset=DIRECT,[]FINAL\n",
    );
    let output = render_acl4ssr_target(
        OutputTarget::Egern,
        "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha",
        config.as_bytes(),
        &[b"PROCESS-NAME,Telegram.exe\nURL-REGEX,example.com/path\nIP-CIDR,10.0.0.0/8,no-resolve\n"],
    )
    .expect("ok");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
    assert!(text.contains("load_balance:"));
    assert!(text.contains("algorithm: hash"));
    assert!(text.contains("ip_cidr:"));
    assert!(text.contains("no_resolve: true"));
    assert!(text.contains("default:\n    policy: DIRECT"));
    assert!(!text.contains("Telegram"));
    assert!(!text.contains("process"));
    assert!(!text.contains("URL-REGEX"));
    assert!(!text.contains("example.com/path"));
}

#[test]
fn shadowsocks_projects_classic_password() {
    let source = "ss://aes-128-gcm:p%40ss%3Aword@example.com:8388#Classic\n";
    let output =
        render_remote_builtin(OutputTarget::Egern, &[source.as_bytes()]).expect("rendered");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
    assert!(text.contains(concat!(
        "- shadowsocks:\n",
        "    name: Classic\n",
        "    method: aes-128-gcm\n",
        "    password: p@ss:word\n",
        "    server: example.com\n",
        "    port: 8388\n",
        "    tfo: false\n",
        "    udp_relay: true\n",
    )));
}

#[test]
fn simple_obfs_http_and_tls_are_exact() {
    let source = concat!(
        "ss://aes-128-gcm:password@example.com:8388?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dobfs.example#ObfsHttp\n",
        "ss://aes-128-gcm:password@example.com:8388?plugin=obfs-local%3Bobfs%3Dtls%3Bobfs-host%3Dobfs.example#ObfsTls\n",
        "ss://aes-128-gcm:password@example.com:8388#Classic\n",
    );
    let output =
        render_remote_builtin(OutputTarget::Egern, &[source.as_bytes()]).expect("rendered");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
    assert!(text.contains(concat!(
        "- shadowsocks:\n",
        "    name: ObfsHttp\n",
        "    method: aes-128-gcm\n",
        "    password: password\n",
        "    server: example.com\n",
        "    port: 8388\n",
        "    tfo: false\n",
        "    udp_relay: true\n",
        "    obfs: http\n",
        "    obfs_host: obfs.example\n",
    )));
    assert!(text.contains(concat!(
        "- shadowsocks:\n",
        "    name: ObfsTls\n",
        "    method: aes-128-gcm\n",
        "    password: password\n",
        "    server: example.com\n",
        "    port: 8388\n",
        "    tfo: false\n",
        "    udp_relay: true\n",
        "    obfs: tls\n",
        "    obfs_host: obfs.example\n",
    )));
    assert!(text.contains(concat!(
        "- shadowsocks:\n",
        "    name: Classic\n",
        "    method: aes-128-gcm\n",
        "    password: password\n",
        "    server: example.com\n",
        "    port: 8388\n",
        "    tfo: false\n",
        "    udp_relay: true\n",
        "policy_groups:\n",
    )));
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
    .render_builtin_v1(OutputTarget::Egern)
    .expect("ok");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
    assert!(text.contains("name: Alpha"));
    assert!(!text.contains("name: reject"));
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
        OutputTarget::Egern,
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
