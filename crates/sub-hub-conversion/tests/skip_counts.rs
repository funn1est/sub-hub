use sub_hub_conversion::{
    ConversionRenderError, OutputTarget, SkipCountsV1, SubscriptionPreparationError,
    SubscriptionSourceV1, prepare_subscription_v1,
};

fn prepare_direct(
    uris: &[&str],
) -> Result<sub_hub_conversion::PreparedSubscriptionV1, SubscriptionPreparationError> {
    let sources: Vec<_> = uris
        .iter()
        .copied()
        .map(SubscriptionSourceV1::Direct)
        .collect();
    prepare_subscription_v1(&sources)
}

const VLESS: &str = "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha";
const ANYTLS: &str = "anytls://secret-canary.example:443#Canary";
const HYSTERIA2: &str = "hysteria2://password@example.com:443#Plain";
const RESERVED: &str = "vless://fedcba98-7654-3210-fedc-ba9876543210@example.net:8443#direct";

#[test]
fn builtin_facade_dispatches_every_released_target() {
    for target in [
        OutputTarget::Mihomo,
        OutputTarget::Quanx,
        OutputTarget::Singbox,
        OutputTarget::Loon,
        OutputTarget::Egern,
    ] {
        let rendered = prepare_direct(&[VLESS])
            .expect("valid")
            .render_builtin_v1(target)
            .expect("vless is kept on every released target");
        assert!(!rendered.as_bytes().is_empty());
        assert_eq!(rendered.omitted_url_regex(), 0);
        assert_eq!(
            rendered.skip_counts(),
            SkipCountsV1 {
                parse: 0,
                capability: 0,
                name: 0,
            }
        );
    }
}

#[test]
fn mihomo_keeps_supported_nodes_and_counts_parse_skips() {
    let prepared = prepare_direct(&[ANYTLS, VLESS]).expect("one valid node");
    let config = prepared
        .render_builtin_v1(OutputTarget::Mihomo)
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
    let prepared = prepare_direct(&[HYSTERIA2, RESERVED, VLESS]).expect("mixed");
    let config = prepared
        .render_builtin_v1(OutputTarget::Quanx)
        .expect("vless remains");
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
    let prepared = prepare_direct(&[HYSTERIA2]).expect("parsed");
    let error = prepared
        .render_builtin_v1(OutputTarget::Quanx)
        .expect_err("qx drops hy2");
    assert_eq!(
        error,
        ConversionRenderError::NoValidNodes {
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
    let error = prepared
        .render_builtin_v1(OutputTarget::Quanx)
        .expect_err("skipped");
    let debug = format!("{error:?}");
    for canary in [UUID, HOST, NAME] {
        assert!(!debug.contains(canary), "{debug}");
    }
    assert_eq!(error.to_string(), "no valid nodes");
}
