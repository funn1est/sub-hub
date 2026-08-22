use proptest::prelude::*;
use sub_hub_conversion::{OutputTarget, SkipCountsV1, UniqueFlightFillFailure};

mod common;

fn render_direct(
    uris: &[&str],
) -> Result<sub_hub_conversion::RenderedConfig, UniqueFlightFillFailure> {
    common::render_direct(uris, OutputTarget::Mihomo)
}

const VALID_DIRECT: &str = "vless://01234567-89ab-cdef-0123-456789abcdef@EXAMPLE.COM:443#Alpha";

#[test]
fn direct_application_prepares_and_renders_builtin_mihomo() {
    let config = render_direct(&[VALID_DIRECT]).expect("valid direct subscription");

    assert_eq!(
        config.as_bytes(),
        concat!(
            "mode: rule\n",
            "proxies:\n",
            "- name: Alpha\n",
            "  type: vless\n",
            "  server: example.com\n",
            "  port: 443\n",
            "  uuid: 01234567-89ab-cdef-0123-456789abcdef\n",
            "  udp: true\n",
            "  encryption: none\n",
            "  network: tcp\n",
            "proxy-groups:\n",
            "- name: PROXY\n",
            "  type: select\n",
            "  proxies:\n",
            "  - AUTO\n",
            "  - Alpha\n",
            "  - DIRECT\n",
            "- name: AUTO\n",
            "  type: url-test\n",
            "  proxies:\n",
            "  - Alpha\n",
            "  url: https://www.gstatic.com/generate_204\n",
            "  interval: 300\n",
            "rules:\n",
            "- MATCH,PROXY\n",
        )
        .as_bytes()
    );
}

#[test]
fn direct_preparation_enforces_occurrence_shape_and_count() {
    for invalid in [
        Vec::new(),
        vec![""],
        vec![" vless://example"],
        vec!["vless://example "],
        vec!["\tvless://example"],
        vec!["vless://example\t"],
        vec!["vless://example\nss://example"],
        vec!["vless://example\rss://example"],
    ] {
        assert_eq!(
            render_direct(&invalid).unwrap_err(),
            UniqueFlightFillFailure::InvalidInput
        );
    }

    assert!(render_direct(&[VALID_DIRECT; 5]).is_ok());
    assert_eq!(
        render_direct(&[VALID_DIRECT; 6]).unwrap_err(),
        UniqueFlightFillFailure::InvalidInput
    );
}

#[test]
fn unsupported_and_base64_inputs_are_node_local_rejections_not_containers() {
    assert_eq!(
        render_direct(&["anytls://example.com:443"]).unwrap_err(),
        UniqueFlightFillFailure::NoValidNodes {
            skips: SkipCountsV1 {
                parse: 1,
                capability: 0,
                name: 0,
            },
        }
    );

    let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, VALID_DIRECT);
    assert_eq!(
        render_direct(&[&encoded]).unwrap_err(),
        UniqueFlightFillFailure::NoValidNodes {
            skips: SkipCountsV1 {
                parse: 1,
                capability: 0,
                name: 0,
            },
        }
    );

    let config = render_direct(&["anytls://example.com:443", VALID_DIRECT])
        .expect("one accepted direct occurrence");
    assert_eq!(config.as_bytes(), SINGLE_VLESS_YAML);
}

#[test]
fn duplicate_direct_occurrences_are_retained_in_declaration_order() {
    let config = render_direct(&[VALID_DIRECT, VALID_DIRECT])
        .expect("duplicate direct occurrences remain valid");
    let yaml = std::str::from_utf8(config.as_bytes()).expect("UTF-8 Mihomo YAML");

    let first = yaml.find("- name: Alpha\n").expect("first duplicate");
    let second = yaml
        .find("- name: Alpha~00001\n")
        .expect("renamed second duplicate");
    assert!(first < second);
    assert_eq!(yaml.matches("  server: example.com\n").count(), 2);
}

#[test]
fn direct_render_maps_the_public_output_limit() {
    let long_path = "x".repeat(16 * 1024 * 1024);
    let source = format!(
        "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443?type=ws&path=/{long_path}#Alpha"
    );
    assert_eq!(
        render_direct(&[&source]).unwrap_err(),
        UniqueFlightFillFailure::ConversionLimit
    );
}

#[test]
fn direct_application_debug_and_errors_do_not_expose_input_or_config() {
    const SECRET_UUID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const SECRET_HOST: &str = "private-canary.example";
    const SECRET_NAME: &str = "secret-canary-name";
    let source = format!("vless://{SECRET_UUID}@{SECRET_HOST}:443#{SECRET_NAME}");

    let config = render_direct(&[&source]).expect("valid direct subscription");
    let config_debug = format!("{config:?}");
    for secret in [SECRET_UUID, SECRET_HOST, SECRET_NAME] {
        assert!(!config_debug.contains(secret));
    }

    let invalid = render_direct(&[" secret-canary "]).unwrap_err();
    assert_eq!(invalid.to_string(), "invalid unique-flight input");
    assert!(!format!("{invalid:?}").contains("secret-canary"));
}

const SINGLE_VLESS_YAML: &[u8] = concat!(
    "mode: rule\n",
    "proxies:\n",
    "- name: Alpha\n",
    "  type: vless\n",
    "  server: example.com\n",
    "  port: 443\n",
    "  uuid: 01234567-89ab-cdef-0123-456789abcdef\n",
    "  udp: true\n",
    "  encryption: none\n",
    "  network: tcp\n",
    "proxy-groups:\n",
    "- name: PROXY\n",
    "  type: select\n",
    "  proxies:\n",
    "  - AUTO\n",
    "  - Alpha\n",
    "  - DIRECT\n",
    "- name: AUTO\n",
    "  type: url-test\n",
    "  proxies:\n",
    "  - Alpha\n",
    "  url: https://www.gstatic.com/generate_204\n",
    "  interval: 300\n",
    "rules:\n",
    "- MATCH,PROXY\n",
)
.as_bytes();

proptest! {
    #[test]
    fn direct_facade_is_deterministic_and_never_panics(
        sources in prop::collection::vec(
            prop_oneof![Just(VALID_DIRECT.to_owned()), ".{0,128}"],
            0..7,
        ),
    ) {
        let refs = sources.iter().map(String::as_str).collect::<Vec<_>>();
        let first = render_direct(&refs);
        let second = render_direct(&refs);
        match (first, second) {
            (Err(first), Err(second)) => prop_assert_eq!(first, second),
            (Ok(first), Ok(second)) => prop_assert_eq!(first.as_bytes(), second.as_bytes()),
            _ => prop_assert!(false, "direct Unique-flight fill diverged"),
        }
    }
}
