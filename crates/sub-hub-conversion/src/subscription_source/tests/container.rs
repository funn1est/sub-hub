use super::{NodeOccurrence, parse_subscription_sources};
use crate::share_uri::{InvalidNodeReason, NodeRejection};

#[test]
fn canonical_standard_and_url_safe_base64_containers_are_supported_with_or_without_padding() {
    const RAW: &str =
        "vless://11111111-1111-4111-8111-111111111111@example.com:443?encryption=none#ÿÿa";
    const STANDARD_PADDED: &str = "dmxlc3M6Ly8xMTExMTExMS0xMTExLTQxMTEtODExMS0xMTExMTExMTExMTFAZXhhbXBsZS5jb206NDQzP2VuY3J5cHRpb249bm9uZSPDv8O/YQ==";
    const STANDARD_UNPADDED: &str = "dmxlc3M6Ly8xMTExMTExMS0xMTExLTQxMTEtODExMS0xMTExMTExMTExMTFAZXhhbXBsZS5jb206NDQzP2VuY3J5cHRpb249bm9uZSPDv8O/YQ";
    const URL_SAFE_PADDED: &str = "dmxlc3M6Ly8xMTExMTExMS0xMTExLTQxMTEtODExMS0xMTExMTExMTExMTFAZXhhbXBsZS5jb206NDQzP2VuY3J5cHRpb249bm9uZSPDv8O_YQ==";
    const URL_SAFE_UNPADDED: &str = "dmxlc3M6Ly8xMTExMTExMS0xMTExLTQxMTEtODExMS0xMTExMTExMTExMTFAZXhhbXBsZS5jb206NDQzP2VuY3J5cHRpb249bm9uZSPDv8O_YQ";

    let expected = parse_subscription_sources(&[RAW.as_bytes()]).expect("raw reference source");

    for encoded in [
        STANDARD_PADDED,
        STANDARD_UNPADDED,
        URL_SAFE_PADDED,
        URL_SAFE_UNPADDED,
    ] {
        let parsed = parse_subscription_sources(&[encoded.as_bytes()])
            .expect("canonical Base64 subscription source");

        assert_eq!(parsed, expected);
        assert!(matches!(
            parsed.occurrences[0],
            NodeOccurrence::Accepted { .. }
        ));
    }
}

#[test]
fn noncanonical_base64_spellings_fall_back_to_one_raw_rejection() {
    const PARTIAL_PADDING: &str = "dmxlc3M6Ly8xMTExMTExMS0xMTExLTQxMTEtODExMS0xMTExMTExMTExMTFAZXhhbXBsZS5jb206NDQzP2VuY3J5cHRpb249bm9uZSPDv8O/YQ=";
    const NON_ZERO_PAD_BITS: &str = "dmxlc3M6Ly8xMTExMTExMS0xMTExLTQxMTEtODExMS0xMTExMTExMTExMTFAZXhhbXBsZS5jb206NDQzP2VuY3J5cHRpb249bm9uZSPDv8O/YR==";
    const NON_ZERO_PAD_BITS_UNPADDED: &str = "dmxlc3M6Ly8xMTExMTExMS0xMTExLTQxMTEtODExMS0xMTExMTExMTExMTFAZXhhbXBsZS5jb206NDQzP2VuY3J5cHRpb249bm9uZSPDv8O/YR";
    const NON_ZERO_TWO_PAD_BITS: &str = "dmxlc3M6Ly8wMTIzNDU2Ny04OWFiLWNkZWYtMDEyMy00NTY3ODlhYmNkZWZAZXhhbXBsZS5jb206NDQzI+mmmea4r8O/YWJ=";
    const NON_ZERO_TWO_PAD_BITS_UNPADDED: &str = "dmxlc3M6Ly8wMTIzNDU2Ny04OWFiLWNkZWYtMDEyMy00NTY3ODlhYmNkZWZAZXhhbXBsZS5jb206NDQzI+mmmea4r8O/YWJ";
    const MIXED_ALPHABETS: &str = "dmxlc3M6Ly8xMTExMTExMS0xMTExLTQxMTEtODExMS0xMTExMTExMTExMTFAZXhhbXBsZS5jb206NDQzP2VuY3J5cHRpb249bm9uZSPDv8O/_Q==";
    const INTERNAL_SPACE: &str =
        "dmxlc3M6Ly8xMTExMTEx MS0xMTExLTQxMTEtODExMS0xMTExMTExMTExMTFAZXhhbXBsZS5jb206NDQz";
    const INTERNAL_TAB: &str =
        "dmxlc3M6Ly8xMTExMTEx\tMS0xMTExLTQxMTEtODExMS0xMTExMTExMTExMTFAZXhhbXBsZS5jb206NDQz";

    for spelling in [
        PARTIAL_PADDING,
        NON_ZERO_PAD_BITS,
        NON_ZERO_PAD_BITS_UNPADDED,
        NON_ZERO_TWO_PAD_BITS,
        NON_ZERO_TWO_PAD_BITS_UNPADDED,
        MIXED_ALPHABETS,
        INTERNAL_SPACE,
        INTERNAL_TAB,
        "A",
        "YW=I",
        "YWI===",
    ] {
        assert_one_raw_uri_rejection(spelling.as_bytes());
    }
}

#[test]
fn a_base64_container_is_decoded_at_most_once() {
    const ONE_ENCODED_LINE_THEN_RAW_URI: &str = "ZG14bGMzTTZMeTh4TVRFeE1URXhNUzB4TVRFeExUUXhNVEV0T0RFeE1TMHhNVEV4TVRFeE1URXhNVEZBWlhoaGJYQnNaUzVqYjIwNk5EUXpQMlZ1WTNKNWNIUnBiMjQ5Ym05dVpRPT0Kdmxlc3M6Ly8xMTExMTExMS0xMTExLTQxMTEtODExMS0xMTExMTExMTExMTFAZXhhbXBsZS5jb206NDQzP2VuY3J5cHRpb249bm9uZQ==";

    let parsed = parse_subscription_sources(&[ONE_ENCODED_LINE_THEN_RAW_URI.as_bytes()])
        .expect("outer Base64 is decoded once");

    assert_eq!(parsed.occurrences.len(), 2);
    assert!(matches!(
        parsed.occurrences[0],
        NodeOccurrence::Rejected {
            rejection: NodeRejection::Invalid(InvalidNodeReason::Uri),
            ..
        }
    ));
    assert!(matches!(
        parsed.occurrences[1],
        NodeOccurrence::Accepted { .. }
    ));
}

#[test]
fn exactly_one_terminal_line_ending_is_ignored_for_base64_probe() {
    const ENCODED: &str = "dmxlc3M6Ly8xMTExMTExMS0xMTExLTQxMTEtODExMS0xMTExMTExMTExMTFAZXhhbXBsZS5jb206NDQzP2VuY3J5cHRpb249bm9uZQ==";

    for suffix in ["", "\n", "\r\n"] {
        let input = format!("{ENCODED}{suffix}");
        let parsed = parse_subscription_sources(&[input.as_bytes()])
            .expect("one optional terminal line ending");
        assert!(matches!(
            parsed.occurrences.as_slice(),
            [NodeOccurrence::Accepted { .. }]
        ));
    }

    let twice_terminated = format!("{ENCODED}\n\n");
    assert_one_raw_uri_rejection(twice_terminated.as_bytes());
}

#[test]
fn decoded_bytes_need_utf8_and_uri_evidence_before_base64_is_selected() {
    for encoded in ["dGVzdA==", "Oi8v_w"] {
        assert_one_raw_uri_rejection(encoded.as_bytes());
    }
}

#[test]
fn line_wrapped_base64_is_raw_record_text() {
    const WRAPPED: &str =
        "dmxlc3M6Ly8xMTExMTExMS0xMTExLTQxMTEtODEx\nMS0xMTExMTExMTExMTFAZXhhbXBsZS5jb206NDQz";

    let parsed = parse_subscription_sources(&[WRAPPED.as_bytes()]).expect("raw line records");

    assert_eq!(parsed.occurrences.len(), 2);
    assert!(parsed.occurrences.iter().all(|outcome| matches!(
        outcome,
        NodeOccurrence::Rejected {
            rejection: NodeRejection::Invalid(InvalidNodeReason::Uri),
            ..
        }
    )));
}

fn assert_one_raw_uri_rejection(input: &[u8]) {
    let parsed = parse_subscription_sources(&[input]).expect("raw fallback is a valid container");

    assert_eq!(parsed.occurrences.len(), 1);
    assert!(matches!(
        parsed.occurrences[0],
        NodeOccurrence::Rejected {
            rejection: NodeRejection::Invalid(InvalidNodeReason::Uri),
            ..
        }
    ));
}
