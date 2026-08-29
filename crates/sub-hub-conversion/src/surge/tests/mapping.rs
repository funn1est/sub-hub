use crate::OutputTarget;
use crate::SubscriptionSourceV1;
use crate::prepare_subscription_v1;
use crate::subscription_prepare::{render_acl4ssr_target, render_remote_builtin};

#[test]
fn simple_obfs_is_capability_skipped() {
    let source = concat!(
        "ss://aes-128-gcm:password@example.com:8388?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dbing.com#Obfs\n",
        "ss://aes-128-gcm:password@example.com:8388#Classic\n",
    );
    let output =
        render_remote_builtin(OutputTarget::Surge, &[source.as_bytes()]).expect("rendered");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
    assert!(text.contains("Classic = ss"));
    assert!(!text.contains("Obfs ="));
    assert_eq!(output.skip_counts().capability, 1);
}

#[test]
fn every_vless_node_is_capability_skipped() {
    let source = concat!(
        "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha\n",
        "ss://aes-128-gcm:password@example.com:8388#Classic\n",
    );
    let output =
        render_remote_builtin(OutputTarget::Surge, &[source.as_bytes()]).expect("rendered");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
    assert!(text.contains(
        "Classic = ss, example.com, 8388, encrypt-method=aes-128-gcm, password=password"
    ));
    assert!(!text.contains("Alpha ="));
    assert!(!text.contains("vless"));
    assert_eq!(output.skip_counts().capability, 1);
}

#[test]
fn vless_only_builtin_is_no_valid_nodes() {
    let error = render_remote_builtin(
        OutputTarget::Surge,
        &[&b"vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha"[..]],
    )
    .expect_err("vless skip-all");
    assert!(matches!(
        error,
        crate::ConversionRenderError::NoValidNodes { .. }
    ));
}

#[test]
fn vmess_aes_is_exact_and_other_ciphers_and_grpc_are_skipped() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let id = "01234567-89ab-cdef-0123-456789abcdef";
    let encode = |json: &str| format!("vmess://{}", STANDARD.encode(json.as_bytes()));
    let source = [
        encode(&format!(
            r#"{{"ps":"Aes","add":"example.com","port":443,"id":"{id}","scy":"aes-128-gcm"}}"#
        )),
        encode(&format!(
            r#"{{"ps":"Cha","add":"example.com","port":443,"id":"{id}","scy":"chacha20-poly1305"}}"#
        )),
        encode(&format!(
            r#"{{"ps":"Grpc","add":"example.com","port":443,"id":"{id}","scy":"aes-128-gcm","net":"grpc"}}"#
        )),
    ]
    .join("\n");
    let output =
        render_remote_builtin(OutputTarget::Surge, &[source.as_bytes()]).expect("rendered");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
    assert!(text.contains(
        "Aes = vmess, example.com, 443, username=01234567-89ab-cdef-0123-456789abcdef, encrypt-method=aes-128-gcm, tls=false"
    ));
    assert!(!text.contains("Cha ="));
    assert!(!text.contains("Grpc ="));
    assert_eq!(output.skip_counts().capability, 2);
}

#[test]
fn trojan_tcp_tls_is_exact_and_reality_grpc_are_skipped() {
    let source = concat!(
        "trojan://password@EXAMPLE.COM:443#TcpTls\n",
        "trojan://password@example.com:443?type=ws&path=%2Fws&host=cdn.example#Ws\n",
        "trojan://password@example.com:443?security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA#Reality\n",
        "trojan://password@example.com:443?type=grpc&serviceName=svc#Grpc\n",
    );
    let output =
        render_remote_builtin(OutputTarget::Surge, &[source.as_bytes()]).expect("rendered");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
    assert!(text.contains(
        "TcpTls = trojan, example.com, 443, password=password, sni=example.com, skip-cert-verify=false"
    ));
    assert!(text.contains("ws=true"));
    assert!(text.contains("ws-path=/ws"));
    assert!(text.contains("ws-headers=Host:cdn.example"));
    assert!(!text.contains("Reality ="));
    assert!(!text.contains("Grpc ="));
    assert_eq!(output.skip_counts().capability, 2);
}

#[test]
fn hysteria2_salamander_and_gecko_are_exact_and_hop_is_skipped() {
    const PIN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let source = format!(
        concat!(
            "hysteria2://password@EXAMPLE.COM:443/?sni=example.com&obfs=salamander&obfs-password=gawrgura#Plain\n",
            "hysteria2://password@example.com/?obfs=gecko&obfs-password=secret#Gecko\n",
            "hysteria2://password@example.com:123,5000-6000/#Hop\n",
            "hysteria2://password@example.com:443/?pinSHA256={PIN}#Pin\n",
        ),
        PIN = PIN
    );
    let output =
        render_remote_builtin(OutputTarget::Surge, &[source.as_bytes()]).expect("rendered");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
    assert!(text.contains("salamander-password=gawrgura"));
    assert!(text.contains("gecko-password=secret"));
    assert!(text.contains(&format!("server-cert-fingerprint-sha256={PIN}")));
    assert!(!text.contains("Hop ="));
    assert_eq!(output.skip_counts().capability, 1);
}

#[test]
fn default_tuic_is_exact_and_non_default_congestion_is_skipped() {
    let source = concat!(
        "tuic://01234567-89ab-cdef-0123-456789abcdef:pass@EXAMPLE.COM:443#Plain\n",
        "tuic://01234567-89ab-cdef-0123-456789abcdef:pass@example.com:443?congestion_control=bbr#Bbr\n",
        "ss://aes-128-gcm:password@example.com:8388#Classic\n",
    );
    let output =
        render_remote_builtin(OutputTarget::Surge, &[source.as_bytes()]).expect("rendered");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
    assert!(text.contains(
        "Plain = tuic-v5, example.com, 443, uuid=01234567-89ab-cdef-0123-456789abcdef, password=pass, skip-cert-verify=false"
    ));
    assert!(!text.contains("Bbr ="));
    assert_eq!(output.skip_counts().capability, 1);
}

#[test]
fn process_name_is_omitted_url_regex_emitted_and_load_balance_is_persistent() {
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
        OutputTarget::Surge,
        "ss://aes-128-gcm:password@example.com:8388#Alpha",
        config.as_bytes(),
        &[b"PROCESS-NAME,Telegram.exe\nURL-REGEX,example.com/path\nIP-CIDR,10.0.0.0/8,no-resolve\n"],
    )
    .expect("ok");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
    assert!(text.contains("Fallback = fallback, Alpha, interval=60"));
    assert!(text.contains("Hash = load-balance, Alpha, persistent=true, interval=30"));
    assert!(text.contains("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve"));
    assert!(text.contains("URL-REGEX,example.com/path,DIRECT"));
    assert!(text.contains("FINAL,DIRECT"));
    assert!(!text.contains("PROCESS"));
    assert!(!text.contains("Telegram"));
}

#[test]
fn reserved_node_tags_are_skipped() {
    let output = prepare_subscription_v1(&[
        SubscriptionSourceV1::Direct("ss://aes-128-gcm:password@example.com:8388#reject"),
        SubscriptionSourceV1::Direct("ss://aes-128-gcm:password@example.net:8388#Alpha"),
    ])
    .expect("valid")
    .render_builtin_v1(OutputTarget::Surge)
    .expect("ok");
    let text = std::str::from_utf8(output.as_bytes()).expect("utf8");
    assert!(text.contains("Alpha = ss"));
    assert!(!text.contains("reject = ss"));
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
        OutputTarget::Surge,
        "ss://aes-128-gcm:password@example.com:8388#Alpha",
        config.as_bytes(),
        &[],
    )
    .expect_err("reserved group");
    assert_eq!(
        error.keep_pass(),
        Ok(crate::ConversionRenderError::Internal)
    );
}
