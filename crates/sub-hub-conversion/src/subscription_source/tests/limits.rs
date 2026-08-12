use super::{NodeOrigin, SubscriptionParseError, parse_subscription_sources};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};

const MAX_DECODED_SOURCE_BYTES: usize = 2 * 1024 * 1024;
const MAX_INPUT_BYTES: usize = 2_796_206;
const VALID_URI: &str =
    "vless://11111111-1111-4111-8111-111111111111@example.com:443?encryption=none";

#[test]
fn at_most_five_subscription_sources_are_accepted() {
    let five: [&[u8]; 5] = [b""; 5];
    let parsed =
        parse_subscription_sources(&five).expect("five sources are within the request cap");
    assert!(parsed.occurrences.is_empty());

    let six: [&[u8]; 6] = [b""; 6];
    let error = parse_subscription_sources(&six)
        .expect_err("source count is bounded even when every source is empty");
    assert_eq!(error, SubscriptionParseError::TooManySources);
}

#[test]
fn raw_source_over_the_decoded_byte_limit_is_fatal() {
    let oversized = vec![b'a'; MAX_DECODED_SOURCE_BYTES + 1];

    let error = parse_subscription_sources(&[&oversized])
        .expect_err("an oversized raw source must fail before node parsing");

    assert_eq!(
        error,
        SubscriptionParseError::DecodedSourceTooLarge { source_index: 0 }
    );
}

#[test]
fn source_over_the_encoded_input_guard_is_rejected_before_probing() {
    let oversized = vec![b'a'; MAX_INPUT_BYTES + 1];

    let error = parse_subscription_sources(&[&oversized])
        .expect_err("the encoded input guard must bound probe work");

    assert_eq!(
        error,
        SubscriptionParseError::InputTooLarge { source_index: 0 }
    );
}

#[test]
fn occurrence_limit_is_shared_across_sources_and_fails_at_the_next_origin() {
    let first = format!("{VALID_URI}\n{}", "bad\n".repeat(9_998));
    let second = format!("\n\nbad\n{VALID_URI}");

    let error = parse_subscription_sources(&[first.as_bytes(), second.as_bytes()])
        .expect_err("the 10,001st candidate must fail the whole batch");

    assert_eq!(
        error,
        SubscriptionParseError::TooManyOccurrences {
            at: NodeOrigin {
                source: 1,
                line: 3,
                occurrence: 1,
            }
        }
    );
}

#[test]
fn exactly_ten_thousand_occurrences_succeed_across_sources() {
    let first = format!("{VALID_URI}\n{}", "bad\n".repeat(9_998));
    let second = "\n\nbad";

    let parsed = parse_subscription_sources(&[first.as_bytes(), second.as_bytes()])
        .expect("the occurrence limit is inclusive");

    assert_eq!(parsed.occurrences.len(), 10_000);
    assert!(matches!(
        parsed.occurrences.last(),
        Some(super::NodeOccurrence::Rejected {
            origin: NodeOrigin {
                source: 1,
                line: 2,
                occurrence: 0,
            },
            ..
        })
    ));
}

#[test]
fn exact_decoded_and_encoded_byte_boundaries_are_enforced() {
    let exact_raw = vec![b' '; MAX_DECODED_SOURCE_BYTES];
    let parsed =
        parse_subscription_sources(&[&exact_raw]).expect("an exact-limit raw source is accepted");
    assert!(parsed.occurrences.is_empty());

    let mut decoded =
        b"vless://11111111-1111-4111-8111-111111111111@example.com:443?encryption=none#".to_vec();
    decoded.resize(MAX_DECODED_SOURCE_BYTES, b'a');

    let mut at_limit = STANDARD.encode(&decoded).into_bytes();
    assert_eq!(at_limit.len(), MAX_INPUT_BYTES - 2);
    at_limit.extend_from_slice(b"\r\n");
    let parsed = parse_subscription_sources(&[&at_limit]).expect("exact byte limits are accepted");
    assert_eq!(parsed.occurrences.len(), 1);

    decoded.push(b'a');
    let decoded_too_large = STANDARD.encode(&decoded);
    assert_eq!(decoded_too_large.len(), MAX_INPUT_BYTES - 2);
    let error = parse_subscription_sources(&[decoded_too_large.as_bytes()])
        .expect_err("decoded size is checked independently of encoded size");
    assert_eq!(
        error,
        SubscriptionParseError::DecodedSourceTooLarge { source_index: 0 }
    );

    decoded.push(b'a');
    let unpadded_at_input_guard = STANDARD_NO_PAD.encode(&decoded);
    assert_eq!(unpadded_at_input_guard.len(), MAX_INPUT_BYTES);
    let error = parse_subscription_sources(&[unpadded_at_input_guard.as_bytes()])
        .expect_err("the decoded estimate is enforced at the exact input guard");
    assert_eq!(
        error,
        SubscriptionParseError::DecodedSourceTooLarge { source_index: 0 }
    );
}
