use super::{NodeOccurrence, parse_subscription_sources};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn arbitrary_bounded_bytes_are_deterministic_and_never_panic(
        sources in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..=2_048), 0..=8),
    ) {
        let bodies = sources.iter().map(Vec::as_slice).collect::<Vec<_>>();

        let first = parse_subscription_sources(&bodies);
        let second = parse_subscription_sources(&bodies);

        prop_assert_eq!(first, second);
    }
}

#[test]
fn raw_and_base64_forms_have_identical_typed_outcomes() {
    const RAW: &str =
        "vless://11111111-1111-4111-8111-111111111111@example.com:443?encryption=none\nbad";
    const BASE64: &str = "dmxlc3M6Ly8xMTExMTExMS0xMTExLTQxMTEtODExMS0xMTExMTExMTExMTFAZXhhbXBsZS5jb206NDQzP2VuY3J5cHRpb249bm9uZQpiYWQ=";

    let raw = parse_subscription_sources(&[RAW.as_bytes()]).expect("raw source");
    let encoded = parse_subscription_sources(&[BASE64.as_bytes()]).expect("Base64 source");

    assert_eq!(raw, encoded);
    assert!(matches!(
        raw.occurrences[0],
        NodeOccurrence::Accepted { .. }
    ));
    assert!(matches!(
        raw.occurrences[1],
        NodeOccurrence::Rejected { .. }
    ));
}
