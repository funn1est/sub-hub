use crate::render::render_builtin_quanx_v1;
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
