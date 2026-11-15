use sub_hub_conversion::{OutputTarget, SkipCountsV1, UniqueFlightFillFailure};

mod common;

const VLESS: &str = "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha";
const SS: &str = "ss://aes-128-gcm:password@example.com:8388#Alpha";
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
        let rendered = common::render_direct(&[VLESS], target)
            .expect("vless is kept on every released target except surge");
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

    let surge = common::render_direct(&[SS], OutputTarget::Surge).expect("ss is kept on surge");
    assert!(!surge.as_bytes().is_empty());
    assert_eq!(
        surge.skip_counts(),
        SkipCountsV1 {
            parse: 0,
            capability: 0,
            name: 0,
        }
    );
    let skipped = common::render_direct(&[VLESS, SS], OutputTarget::Surge).expect("ss survives");
    assert_eq!(
        skipped.skip_counts(),
        SkipCountsV1 {
            parse: 0,
            capability: 1,
            name: 0,
        }
    );
}

#[test]
fn reality_x25519mlkem768_is_kept_only_on_mihomo() {
    const NODE: &str = "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443?encryption=none&security=reality&sni=cdn.example&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0a1b&support-x25519mlkem768=true#Pq";

    let mihomo = common::render_direct(&[NODE], OutputTarget::Mihomo).expect("mihomo keeps it");
    let mihomo_text = std::str::from_utf8(mihomo.as_bytes()).expect("utf8");
    assert!(mihomo_text.contains("support-x25519mlkem768: true"));
    assert!(mihomo_text.contains("name: Pq"));
    assert_eq!(
        mihomo.skip_counts(),
        SkipCountsV1 {
            parse: 0,
            capability: 0,
            name: 0,
        }
    );

    for target in [
        OutputTarget::Quanx,
        OutputTarget::Singbox,
        OutputTarget::Loon,
        OutputTarget::Egern,
        OutputTarget::Surge,
    ] {
        let skipped = common::render_direct(&[NODE], target).expect_err("no spellable node");
        assert!(
            matches!(skipped, UniqueFlightFillFailure::NoValidNodes { .. }),
            "{target:?} produced {skipped:?}"
        );
    }

    let kept = common::render_direct(&[NODE, VLESS], OutputTarget::Singbox).expect("plain vless");
    assert_eq!(
        kept.skip_counts(),
        SkipCountsV1 {
            parse: 0,
            capability: 1,
            name: 0,
        }
    );
    let text = std::str::from_utf8(kept.as_bytes()).expect("utf8");
    assert!(!text.contains("support-x25519mlkem768"));
    assert!(text.contains("Alpha"));
}

#[test]
fn mihomo_keeps_supported_nodes_and_counts_parse_skips() {
    let config =
        common::render_direct(&[ANYTLS, VLESS], OutputTarget::Mihomo).expect("mihomo keeps vless");
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
    let config = common::render_direct(&[HYSTERIA2, RESERVED, VLESS], OutputTarget::Quanx)
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
    let error = common::render_direct(&[HYSTERIA2], OutputTarget::Quanx).expect_err("qx drops hy2");
    assert_eq!(
        error,
        UniqueFlightFillFailure::NoValidNodes {
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
    let error = common::render_direct(&[&source], OutputTarget::Quanx).expect_err("skipped");
    let debug = format!("{error:?}");
    for canary in [UUID, HOST, NAME] {
        assert!(!debug.contains(canary), "{debug}");
    }
    assert_eq!(error.to_string(), "no valid nodes");
}
