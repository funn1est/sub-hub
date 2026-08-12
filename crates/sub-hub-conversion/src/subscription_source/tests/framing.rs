use super::{SubscriptionParseError, parse_subscription_sources};

const VALID_URI: &str =
    "vless://11111111-1111-4111-8111-111111111111@example.com:443?encryption=none";

#[test]
fn bare_carriage_return_is_source_fatal_and_discards_earlier_occurrences() {
    let malformed = format!("{VALID_URI}\r{VALID_URI}");

    let error = parse_subscription_sources(&[VALID_URI.as_bytes(), malformed.as_bytes()])
        .expect_err("bare carriage return must fail the whole batch");

    assert_eq!(
        error,
        SubscriptionParseError::InvalidLineEnding { source_index: 1 }
    );
}

#[test]
fn invalid_raw_utf8_is_source_fatal() {
    let error = parse_subscription_sources(&[VALID_URI.as_bytes(), &[0xff]])
        .expect_err("raw bytes must be valid UTF-8");

    assert_eq!(
        error,
        SubscriptionParseError::InvalidUtf8 { source_index: 1 }
    );
}

#[test]
fn invalid_utf8_with_raw_uri_evidence_is_source_fatal() {
    let raw = [b':', b'/', b'/', 0xff];

    let error = parse_subscription_sources(&[&raw]).expect_err("raw URI evidence wins the probe");

    assert_eq!(
        error,
        SubscriptionParseError::InvalidUtf8 { source_index: 0 }
    );
}

#[test]
fn the_earliest_source_fatal_error_wins_in_declaration_order() {
    let bare_carriage_return = format!("{VALID_URI}\r{VALID_URI}");
    let invalid_utf8 = [0xff];

    let line_error =
        parse_subscription_sources(&[bare_carriage_return.as_bytes(), invalid_utf8.as_slice()])
            .expect_err("the first fatal source must win");
    assert_eq!(
        line_error,
        SubscriptionParseError::InvalidLineEnding { source_index: 0 }
    );

    let utf8_error =
        parse_subscription_sources(&[invalid_utf8.as_slice(), bare_carriage_return.as_bytes()])
            .expect_err("reversing the sources must reverse the winning error");
    assert_eq!(
        utf8_error,
        SubscriptionParseError::InvalidUtf8 { source_index: 0 }
    );
}
