use super::{NodeOccurrence, NodeOrigin, parse_subscription_sources};
use crate::node::{InvalidNodeReason, NodeRejection};

const VLESS: &str = "vless://11111111-1111-4111-8111-111111111111@example.com:443?encryption=none";
const SHADOWSOCKS: &str = "ss://aes-128-gcm:password@example.net:8388#SS";

#[test]
fn outcomes_preserve_source_physical_line_and_compact_occurrence_order() {
    let first = format!("\t \r\n  {VLESS}\t\nbad\r\n\n\t{SHADOWSOCKS} \r\n");
    let second = format!("\u{feff}{VLESS}\n{VLESS}");

    let parsed = parse_subscription_sources(&[first.as_bytes(), second.as_bytes()])
        .expect("mixed valid and rejected records are locally recoverable");

    assert_eq!(parsed.occurrences.len(), 5);
    assert!(matches!(
        parsed.occurrences[0],
        NodeOccurrence::Accepted {
            origin: NodeOrigin {
                source: 0,
                line: 1,
                occurrence: 0,
            },
            ..
        }
    ));
    assert!(matches!(
        parsed.occurrences[1],
        NodeOccurrence::Rejected {
            origin: NodeOrigin {
                source: 0,
                line: 2,
                occurrence: 1,
            },
            rejection: NodeRejection::Invalid(InvalidNodeReason::Uri),
        }
    ));
    assert!(matches!(
        parsed.occurrences[2],
        NodeOccurrence::Accepted {
            origin: NodeOrigin {
                source: 0,
                line: 4,
                occurrence: 2,
            },
            ..
        }
    ));
    assert!(matches!(
        parsed.occurrences[3],
        NodeOccurrence::Rejected {
            origin: NodeOrigin {
                source: 1,
                line: 0,
                occurrence: 0,
            },
            rejection: NodeRejection::Invalid(InvalidNodeReason::Uri),
        }
    ));
    assert!(matches!(
        parsed.occurrences[4],
        NodeOccurrence::Accepted {
            origin: NodeOrigin {
                source: 1,
                line: 1,
                occurrence: 1,
            },
            ..
        }
    ));
}

#[test]
fn duplicate_valid_uri_occurrences_are_preserved() {
    let source = format!("{VLESS}\n{VLESS}");

    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("duplicate occurrences");

    assert_eq!(parsed.occurrences.len(), 2);
    assert!(
        parsed
            .occurrences
            .iter()
            .all(|outcome| matches!(outcome, NodeOccurrence::Accepted { .. }))
    );
}

#[test]
fn non_ascii_and_control_whitespace_is_not_trimmed() {
    let prefixes = [
        "\u{00a0}", "\u{3000}", "\u{000b}", "\u{000c}", "\u{feff}", "\0",
    ];
    let source = prefixes
        .iter()
        .map(|prefix| format!("{prefix}{VLESS}"))
        .collect::<Vec<_>>()
        .join("\n");

    let parsed = parse_subscription_sources(&[source.as_bytes()])
        .expect("retained whitespace is a node-local concern");

    assert_eq!(parsed.occurrences.len(), prefixes.len());
    assert!(parsed.occurrences.iter().all(|outcome| matches!(
        outcome,
        NodeOccurrence::Rejected {
            rejection: NodeRejection::Invalid(InvalidNodeReason::Uri),
            ..
        }
    )));
}
