use sub_hub_conversion::{
    DirectRenderError, SkipCountsV1, SubscriptionSourceV1, prepare_direct_subscription_v1,
    prepare_subscription_v1,
};

const VLESS: &str = "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha";
const ANYTLS: &str = "anytls://secret-canary.example:443#Canary";
const HYSTERIA2: &str = "hysteria2://password@example.com:443#Plain";
const RESERVED: &str = "vless://fedcba98-7654-3210-fedc-ba9876543210@example.net:8443#direct";

#[test]
fn mihomo_keeps_supported_nodes_and_counts_parse_skips() {
    let prepared = prepare_direct_subscription_v1(&[ANYTLS, VLESS]).expect("one valid node");
    let config = prepared
        .render_builtin_mihomo_v1()
        .expect("mihomo keeps vless");
    assert_eq!(
        config.skip_counts(),
        SkipCountsV1 {
            parse: 1,
            capability: 0,
            name: 0,
        }
    );
    assert!(
        std::str::from_utf8(config.as_bytes())
            .expect("utf8")
            .contains("name: Alpha")
    );
}

#[test]
fn quanx_counts_hysteria2_as_capability_and_reserved_name() {
    let prepared = prepare_direct_subscription_v1(&[HYSTERIA2, RESERVED, VLESS]).expect("mixed");
    let config = prepared.render_builtin_quanx_v1().expect("vless remains");
    assert_eq!(
        config.skip_counts(),
        SkipCountsV1 {
            parse: 0,
            capability: 1,
            name: 1,
        }
    );
    let text = std::str::from_utf8(config.as_bytes()).expect("utf8");
    assert!(text.contains("tag=Alpha"));
    assert!(!text.contains("tag=Plain"));
    assert!(!text.contains("tag=direct"));
}

#[test]
fn adapter_all_skipped_is_no_valid_nodes_with_counts() {
    let prepared = prepare_direct_subscription_v1(&[HYSTERIA2]).expect("parsed");
    let error = prepared
        .render_builtin_quanx_v1()
        .expect_err("qx drops hy2");
    assert_eq!(
        error,
        DirectRenderError::NoValidNodes {
            skips: SkipCountsV1 {
                parse: 0,
                capability: 1,
                name: 0,
            },
        }
    );
}

#[test]
fn inspect_matches_render_counts_without_emitting_config() {
    let prepared = prepare_direct_subscription_v1(&[ANYTLS, HYSTERIA2, VLESS]).expect("mixed");
    let inspected = prepared.inspect_builtin_quanx_v1().expect("one remains");
    let prepared = prepare_direct_subscription_v1(&[ANYTLS, HYSTERIA2, VLESS]).expect("mixed");
    let rendered = prepared.render_builtin_quanx_v1().expect("one remains");
    assert_eq!(inspected, rendered.skip_counts());
    assert_eq!(
        inspected,
        SkipCountsV1 {
            parse: 1,
            capability: 1,
            name: 0,
        }
    );
}

#[test]
fn inspect_all_skipped_is_no_valid_nodes() {
    let prepared = prepare_direct_subscription_v1(&[HYSTERIA2]).expect("parsed");
    let error = prepared
        .inspect_builtin_quanx_v1()
        .expect_err("none remain");
    assert_eq!(
        error,
        DirectRenderError::NoValidNodes {
            skips: SkipCountsV1 {
                parse: 0,
                capability: 1,
                name: 0,
            },
        }
    );
}

#[test]
fn skip_counts_debug_does_not_retain_canaries() {
    const UUID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const HOST: &str = "private-canary.example";
    const NAME: &str = "secret-canary-name";
    let source = format!("hysteria2://{UUID}@{HOST}:443#{NAME}");
    let prepared = prepare_subscription_v1(&[SubscriptionSourceV1::Direct(&source)]).expect("ok");
    let error = prepared.render_builtin_quanx_v1().expect_err("skipped");
    let debug = format!("{error:?}");
    for canary in [UUID, HOST, NAME] {
        assert!(!debug.contains(canary), "{debug}");
    }
    assert_eq!(error.to_string(), "no valid nodes");
}
