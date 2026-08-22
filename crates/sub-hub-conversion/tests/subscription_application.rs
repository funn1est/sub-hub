use base64::{Engine as _, engine::general_purpose::STANDARD};
use sub_hub_conversion::{
    OutputTarget, SkipCountsV1, UniqueFlightDrive, UniqueFlightFillFailure, UniqueFlightSessionV1,
};

mod common;

const ALPHA: &str = "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha";
const BETA: &str = "vless://fedcba98-7654-3210-fedc-ba9876543210@example.net:8443#Beta";
const REMOTE: &str = "https://upstream.example/sub";
const REMOTE_BETA: &str = "https://upstream.example/beta";
const REMOTE_ALPHA: &str = "https://upstream.example/alpha";
const REMOTE_FIRST: &str = "https://upstream.example/first";
const REMOTE_SECOND: &str = "https://upstream.example/second";

fn render_remote(url: &str, body: &[u8]) -> Vec<u8> {
    common::drive_session(
        common::start_occurrences(&[url.to_owned()], [Some(url)], None, OutputTarget::Mihomo),
        |_| body.to_vec(),
    )
    .expect("valid remote subscription")
    .document
    .into_bytes()
}

fn yaml(bytes: &[u8]) -> &str {
    std::str::from_utf8(bytes).expect("UTF-8 Mihomo YAML")
}

#[test]
fn remote_raw_and_base64_containers_share_the_public_seam() {
    let raw = format!("\t{ALPHA}\r\n\r\n{BETA} \n");
    let encoded = STANDARD.encode(&raw);

    let from_raw = render_remote(REMOTE, raw.as_bytes());
    let from_base64 = render_remote(REMOTE, encoded.as_bytes());

    assert_eq!(from_raw, from_base64);
    let text = yaml(&from_raw);
    assert!(text.find("- name: Alpha\n").unwrap() < text.find("- name: Beta\n").unwrap());
}

#[test]
fn mixed_sources_preserve_declaration_order_and_duplicate_occurrences() {
    let sources = vec![
        REMOTE_BETA.to_owned(),
        ALPHA.to_owned(),
        REMOTE_ALPHA.to_owned(),
    ];
    let bytes = common::drive_session(
        common::start_occurrences(
            &sources,
            [Some(REMOTE_BETA), None, Some(REMOTE_ALPHA)],
            None,
            OutputTarget::Mihomo,
        ),
        |url| match url {
            REMOTE_BETA => BETA.as_bytes().to_vec(),
            REMOTE_ALPHA => ALPHA.as_bytes().to_vec(),
            other => panic!("unexpected unique URL {other}"),
        },
    )
    .expect("valid mixed sources")
    .document
    .into_bytes();
    let text = yaml(&bytes);

    let beta = text.find("- name: Beta\n").expect("remote occurrence");
    let alpha = text.find("- name: Alpha\n").expect("direct occurrence");
    let duplicate = text
        .find("- name: Alpha~00001\n")
        .expect("duplicate remote occurrence");
    assert!(beta < alpha && alpha < duplicate);
}

#[test]
fn occurrence_limit_is_request_wide_across_direct_and_remote_sources() {
    let first_remote = "bad\n".repeat(9_998);
    let sources = vec![
        ALPHA.to_owned(),
        REMOTE_FIRST.to_owned(),
        REMOTE_SECOND.to_owned(),
    ];
    let start = || {
        common::start_occurrences(
            &sources,
            [None, Some(REMOTE_FIRST), Some(REMOTE_SECOND)],
            None,
            OutputTarget::Mihomo,
        )
    };

    common::drive_session(start(), |url| match url {
        REMOTE_FIRST => first_remote.as_bytes().to_vec(),
        REMOTE_SECOND => b"bad".to_vec(),
        other => panic!("unexpected unique URL {other}"),
    })
    .expect("10,000 occurrences stay within the request cap");

    assert_eq!(
        common::drive_session(start(), |url| match url {
            REMOTE_FIRST => first_remote.as_bytes().to_vec(),
            REMOTE_SECOND => b"bad\nbad".to_vec(),
            other => panic!("unexpected unique URL {other}"),
        })
        .unwrap_err(),
        UniqueFlightFillFailure::ConversionLimit
    );
}

#[test]
fn zero_valid_nodes_and_error_formatting_are_closed_and_secret_safe() {
    assert_eq!(
        common::drive_session(
            common::start_occurrences(
                &[
                    "anytls://secret-canary.example:443".to_owned(),
                    REMOTE.to_owned(),
                ],
                [None, Some(REMOTE)],
                None,
                OutputTarget::Mihomo,
            ),
            |_| b"\t \r\n".to_vec(),
        )
        .unwrap_err(),
        UniqueFlightFillFailure::NoValidNodes {
            skips: SkipCountsV1 {
                parse: 1,
                capability: 0,
                name: 0,
            },
        }
    );

    let failure = match UniqueFlightSessionV1::start(
        &[" secret-canary.example ".to_owned()],
        [None],
        None,
        OutputTarget::Mihomo,
        common::DECODED_CAP,
        false,
    ) {
        UniqueFlightDrive::Ended(Err(failure)) => failure,
        UniqueFlightDrive::Ended(Ok(_)) => {
            panic!("leading ASCII space is invalid unique-flight input")
        }
        UniqueFlightDrive::Need(need) => panic!("expected Ended, got {need:?}"),
    };
    assert_eq!(failure, UniqueFlightFillFailure::InvalidInput);
    for formatted in [format!("{failure:?}"), failure.to_string()] {
        assert!(!formatted.contains("secret-canary"));
    }
}
