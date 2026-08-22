use super::{NodeOccurrence, NodeOrigin, SubscriptionParseError, parse_subscription_sources};

#[test]
fn source_error_codes_are_closed_and_low_cardinality() {
    let cases = [
        (
            SubscriptionParseError::InputTooLarge { source_index: 7 },
            "input_too_large",
        ),
        (
            SubscriptionParseError::DecodedSourceTooLarge { source_index: 7 },
            "decoded_source_too_large",
        ),
        (
            SubscriptionParseError::InvalidUtf8 { source_index: 7 },
            "invalid_utf8",
        ),
        (
            SubscriptionParseError::InvalidLineEnding { source_index: 7 },
            "invalid_line_ending",
        ),
        (
            SubscriptionParseError::TooManyOccurrences {
                at: NodeOrigin {
                    source: 7,
                    line: 11,
                    occurrence: 9,
                },
            },
            "too_many_occurrences",
        ),
    ];

    for (error, expected) in cases {
        assert_eq!(error.code(), expected);
    }
}

#[test]
fn errors_and_rejections_do_not_retain_source_secrets() {
    const CANARY: &str = "source-secret-canary.example";
    let rejected = format!("unknown://credential@{CANARY}:443?token=secret#{CANARY}");
    let parsed = parse_subscription_sources(&[rejected.as_bytes()]).expect("node-local rejection");

    let NodeOccurrence::Rejected { rejection, .. } = &parsed.occurrences[0] else {
        panic!("fixture must be rejected")
    };
    for rendered in [format!("{rejection:?}"), rejection.to_string()] {
        assert!(!rendered.contains(CANARY));
        assert!(!rendered.contains("credential"));
        assert!(!rendered.contains("secret"));
    }

    let mut invalid_utf8 = format!("unknown://credential@{CANARY}?token=secret").into_bytes();
    invalid_utf8.push(0xff);
    let source_error = parse_subscription_sources(&[&invalid_utf8])
        .expect_err("invalid UTF-8 with canaries is source-fatal");
    for rendered in [format!("{source_error:?}"), source_error.to_string()] {
        assert!(!rendered.contains(CANARY));
        assert!(!rendered.contains("credential"));
        assert!(!rendered.contains("secret"));
    }

    let accepted = format!(
        "vless://11111111-1111-4111-8111-111111111111@{CANARY}:443?encryption=none#{CANARY}"
    );
    let parsed =
        parse_subscription_sources(&[accepted.as_bytes()]).expect("accepted canary fixture");
    for rendered in [
        format!("{parsed:?}"),
        format!("{:?}", parsed.occurrences[0]),
    ] {
        assert!(!rendered.contains(CANARY));
    }
}
