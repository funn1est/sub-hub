use super::{NodeOccurrence, NodeOrigin, SubscriptionParseError, parse_subscription_sources};

mod container;
mod framing;
mod limits;
mod ordering;
mod privacy;
mod properties;

#[test]
fn raw_single_line_source_is_parsed_at_the_batch_seam() {
    let source = b"vless://11111111-1111-4111-8111-111111111111@example.com:443?encryption=none";

    let parsed = parse_subscription_sources(&[source.as_slice()]).expect("valid raw source");

    assert_eq!(parsed.occurrences.len(), 1);
    assert!(matches!(
        &parsed.occurrences[0],
        NodeOccurrence::Accepted {
            origin: NodeOrigin {
                source: 0,
                line: 0,
                occurrence: 0,
            },
            ..
        }
    ));
}
