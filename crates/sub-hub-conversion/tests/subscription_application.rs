use base64::{Engine as _, engine::general_purpose::STANDARD};
use sub_hub_conversion::{
    RemoteSourceFailureV1, SubscriptionPreparationError, SubscriptionSourceV1,
    prepare_subscription_v1,
};

const ALPHA: &str = "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha";
const BETA: &str = "vless://fedcba98-7654-3210-fedc-ba9876543210@example.net:8443#Beta";

fn render(sources: &[SubscriptionSourceV1<'_>]) -> Vec<u8> {
    prepare_subscription_v1(sources)
        .expect("valid subscription sources")
        .render_builtin_mihomo_v1()
        .expect("builtin Mihomo config")
        .into_bytes()
}

#[test]
fn remote_raw_and_base64_containers_share_the_public_seam() {
    let raw = format!("\t{ALPHA}\r\n\r\n{BETA} \n");
    let encoded = STANDARD.encode(&raw);

    let from_raw = render(&[SubscriptionSourceV1::Remote(raw.as_bytes())]);
    let from_base64 = render(&[SubscriptionSourceV1::Remote(encoded.as_bytes())]);

    assert_eq!(from_raw, from_base64);
    let yaml = std::str::from_utf8(&from_raw).expect("UTF-8 Mihomo YAML");
    assert!(yaml.find("- name: Alpha\n").unwrap() < yaml.find("- name: Beta\n").unwrap());
}

#[test]
fn mixed_sources_preserve_declaration_order_and_duplicate_occurrences() {
    let yaml = render(&[
        SubscriptionSourceV1::Remote(BETA.as_bytes()),
        SubscriptionSourceV1::Direct(ALPHA),
        SubscriptionSourceV1::Remote(ALPHA.as_bytes()),
    ]);
    let yaml = std::str::from_utf8(&yaml).expect("UTF-8 Mihomo YAML");

    let beta = yaml.find("- name: Beta\n").expect("remote occurrence");
    let alpha = yaml.find("- name: Alpha\n").expect("direct occurrence");
    let duplicate = yaml
        .find("- name: Alpha~00001\n")
        .expect("duplicate remote occurrence");
    assert!(beta < alpha && alpha < duplicate);
}

#[test]
fn remote_decoded_byte_accounting_is_aligned_with_source_order() {
    let encoded = STANDARD.encode(BETA);
    let prepared = prepare_subscription_v1(&[
        SubscriptionSourceV1::Direct(ALPHA),
        SubscriptionSourceV1::Remote(encoded.as_bytes()),
        SubscriptionSourceV1::Remote(ALPHA.as_bytes()),
        SubscriptionSourceV1::Remote(ALPHA.as_bytes()),
    ])
    .expect("valid mixed sources");

    assert_eq!(
        prepared.remote_decoded_bytes_by_source(),
        &[None, Some(BETA.len()), Some(ALPHA.len()), Some(ALPHA.len())]
    );
}

#[test]
fn source_count_and_direct_occurrence_framing_are_strict() {
    assert_eq!(
        prepare_subscription_v1(&[]).unwrap_err(),
        SubscriptionPreparationError::InvalidInput
    );

    let direct = SubscriptionSourceV1::Direct(ALPHA);
    assert!(prepare_subscription_v1(&[direct; 5]).is_ok());
    assert_eq!(
        prepare_subscription_v1(&[direct; 6]).unwrap_err(),
        SubscriptionPreparationError::InvalidInput
    );

    for invalid in [
        "",
        " vless://example",
        "vless://example ",
        "\tvless://example",
        "vless://example\t",
        "vless://example\nss://example",
        "vless://example\rss://example",
    ] {
        assert_eq!(
            prepare_subscription_v1(&[SubscriptionSourceV1::Direct(invalid)]).unwrap_err(),
            SubscriptionPreparationError::InvalidInput
        );
    }
}

#[test]
fn whole_remote_failures_retain_a_closed_reason_and_source_ordinal() {
    for (body, reason) in [
        (vec![0xff], RemoteSourceFailureV1::InvalidUtf8),
        (
            b"trojan://example\rnext".to_vec(),
            RemoteSourceFailureV1::InvalidLineEnding,
        ),
        (vec![b'a'; 2_796_207], RemoteSourceFailureV1::InputTooLarge),
    ] {
        assert_eq!(
            prepare_subscription_v1(&[
                SubscriptionSourceV1::Direct(ALPHA),
                SubscriptionSourceV1::Remote(&body),
            ])
            .unwrap_err(),
            SubscriptionPreparationError::RemoteFailure {
                source_index: 1,
                reason,
            }
        );
    }

    let decoded_too_large = vec![b'a'; 2 * 1024 * 1024 + 1];
    let encoded_too_large = STANDARD.encode(decoded_too_large);
    assert_eq!(
        prepare_subscription_v1(&[SubscriptionSourceV1::Remote(encoded_too_large.as_bytes(),)])
            .unwrap_err(),
        SubscriptionPreparationError::RemoteFailure {
            source_index: 0,
            reason: RemoteSourceFailureV1::DecodedTooLarge,
        }
    );
}

#[test]
fn occurrence_limit_is_request_wide_across_direct_and_remote_sources() {
    let first_remote = "bad\n".repeat(9_998);

    assert!(
        prepare_subscription_v1(&[
            SubscriptionSourceV1::Direct(ALPHA),
            SubscriptionSourceV1::Remote(first_remote.as_bytes()),
            SubscriptionSourceV1::Remote(b"bad"),
        ])
        .is_ok()
    );
    assert_eq!(
        prepare_subscription_v1(&[
            SubscriptionSourceV1::Direct(ALPHA),
            SubscriptionSourceV1::Remote(first_remote.as_bytes()),
            SubscriptionSourceV1::Remote(b"bad\nbad"),
        ])
        .unwrap_err(),
        SubscriptionPreparationError::ConversionLimit
    );
}

#[test]
fn zero_valid_nodes_and_error_formatting_are_closed_and_secret_safe() {
    assert_eq!(
        prepare_subscription_v1(&[
            SubscriptionSourceV1::Direct("hysteria2://secret-canary.example:443"),
            SubscriptionSourceV1::Remote(b"\t \r\n"),
        ])
        .unwrap_err(),
        SubscriptionPreparationError::NoValidNodes
    );

    let error = prepare_subscription_v1(&[SubscriptionSourceV1::Direct(" secret-canary.example ")])
        .unwrap_err();
    for formatted in [format!("{error:?}"), error.to_string()] {
        assert!(!formatted.contains("secret-canary"));
    }
}
