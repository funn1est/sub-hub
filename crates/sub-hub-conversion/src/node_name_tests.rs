use crate::{
    node_name::{
        GroupNameError, NamedNodeOccurrence, NamedSubscriptionSources, NodeNameDiagnosticKind,
        NodeNameError, resolve_node_names,
    },
    subscription_source::parse_subscription_sources,
};
use std::fmt::Write as _;

const VLESS_PREFIX: &str =
    "vless://11111111-1111-4111-8111-111111111111@example.com:443?encryption=none";
const SHADOWSOCKS_PREFIX: &str = "ss://aes-128-gcm:password@example.net:8388";
const ACL4SSR_VS16_GROUPS: [&str; 4] = ["♻️ 自动选择", "Ⓜ️ 微软Bing", "Ⓜ️ 微软云盘", "Ⓜ️ 微软服务"];

#[wasm_bindgen_test::wasm_bindgen_test(unsupported = test)]
fn node_name_v1_golden_vectors_are_byte_stable() {
    let tagged_flag = "\u{1f3f4}\u{e0067}\u{e0062}\u{e007f}";
    let source = format!(
        "{VLESS_PREFIX}#%2B\n\
         {VLESS_PREFIX}#+\n\
         {VLESS_PREFIX}#%20Alpha%C2%A0Beta%20\n\
         {VLESS_PREFIX}#e%CC%81\n\
         {VLESS_PREFIX}#%E2%80%8BHidden\n\
         {VLESS_PREFIX}#%F0%9F%91%A9%E2%80%8D%F0%9F%92%BB\n\
         {VLESS_PREFIX}#{tagged_flag}\n\
         {VLESS_PREFIX}#X\u{e0067}Y\n\
         {VLESS_PREFIX}#♻️ 自动选择\n\
         {VLESS_PREFIX}#DIRECT"
    );
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("golden source");

    let named = resolve_node_names(parsed, &ACL4SSR_VS16_GROUPS).expect("golden namespace");
    let actual = accepted_names(&named)
        .into_iter()
        .map(str::as_bytes)
        .collect::<Vec<_>>();
    let expected: [&[u8]; 10] = [
        b"+",
        b"+~00001",
        b"Alpha Beta",
        "é".as_bytes(),
        b"Hidden",
        "👩‍💻".as_bytes(),
        tagged_flag.as_bytes(),
        b"XY",
        "♻️ 自动选择~00001".as_bytes(),
        b"DIRECT~00001",
    ];

    assert_eq!(actual, expected);
    assert_eq!(unicode_normalization::UNICODE_VERSION, (17, 0, 0));
    assert_eq!(unicode_properties::UNICODE_VERSION, (17, 0, 0));
    assert_eq!(unicode_segmentation::UNICODE_VERSION, (17, 0, 0));
}

#[test]
fn empty_query_fragment_is_the_node_name() {
    let with_empty_query = format!("{SHADOWSOCKS_PREFIX}?#Alpha");
    let fragment_only = format!("{SHADOWSOCKS_PREFIX}#Alpha");
    let named_empty = resolve_node_names(
        parse_subscription_sources(&[with_empty_query.as_bytes()]).expect("empty query source"),
        &[],
    )
    .expect("empty query names");
    let named_fragment = resolve_node_names(
        parse_subscription_sources(&[fragment_only.as_bytes()]).expect("fragment source"),
        &[],
    )
    .expect("fragment names");

    assert_eq!(accepted_names(&named_empty), ["Alpha"]);
    assert_eq!(accepted_names(&named_fragment), ["Alpha"]);
}

#[test]
fn canonicalizes_unicode_whitespace_at_the_resolver_seam() {
    let source = format!("{VLESS_PREFIX}#%20%20Alpha%C2%A0Beta%20%20");
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid source");

    let named = resolve_node_names(parsed, &[]).expect("valid names");

    let NamedNodeOccurrence::Accepted { node, .. } = &named.occurrences()[0] else {
        panic!("fixture must be accepted")
    };
    assert_eq!(node.name().as_str(), "Alpha Beta");
}

#[test]
fn maps_every_unicode_17_white_space_scalar_to_ascii_space() {
    let white_space = [
        '\u{0009}', '\u{000a}', '\u{000b}', '\u{000c}', '\u{000d}', '\u{0020}', '\u{0085}',
        '\u{00a0}', '\u{1680}', '\u{2000}', '\u{2001}', '\u{2002}', '\u{2003}', '\u{2004}',
        '\u{2005}', '\u{2006}', '\u{2007}', '\u{2008}', '\u{2009}', '\u{200a}', '\u{2028}',
        '\u{2029}', '\u{202f}', '\u{205f}', '\u{3000}',
    ];
    let source = white_space
        .iter()
        .enumerate()
        .map(|(index, whitespace)| {
            let remark = format!("A{whitespace}B{index}");
            format!("{VLESS_PREFIX}#{}", percent_encode(&remark))
        })
        .collect::<Vec<_>>()
        .join("\n");
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid source");

    let named = resolve_node_names(parsed, &[]).expect("valid names");

    for (index, name) in accepted_names(&named).into_iter().enumerate() {
        assert_eq!(name, format!("A B{index}"));
    }
    assert_eq!(
        named
            .diagnostics()
            .count(NodeNameDiagnosticKind::WhitespaceCanonicalized),
        u32::try_from(white_space.len() - 1).expect("small fixture without canonical ASCII space")
    );
}

#[test]
fn invalid_remarks_fall_back_to_protocol_and_canonical_endpoint() {
    let oversized = "x".repeat(1_025);
    let ipv6 = format!(
        "vless://11111111-1111-4111-8111-111111111111@[2001:db8::1]:8443?encryption=none#{oversized}"
    );
    let source = format!("{VLESS_PREFIX}\n{SHADOWSOCKS_PREFIX}#\n{ipv6}");
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid source");

    let named = resolve_node_names(parsed, &[]).expect("fallbacks are recoverable");

    assert_eq!(
        accepted_names(&named),
        [
            "VLESS example.com:443",
            "SS example.net:8388",
            "VLESS [2001:db8::1]:8443",
        ]
    );
    assert_eq!(
        named
            .diagnostics()
            .count(NodeNameDiagnosticKind::MissingFallback),
        1
    );
    assert_eq!(
        named
            .diagnostics()
            .count(NodeNameDiagnosticKind::EmptyFallback),
        1
    );
    assert_eq!(
        named
            .diagnostics()
            .count(NodeNameDiagnosticKind::OversizedFallback),
        1
    );
}

#[test]
fn exactly_one_thousand_twenty_four_remark_bytes_are_not_oversized() {
    let remark = "x".repeat(1_024);
    let source = format!("{VLESS_PREFIX}#{remark}");
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid source");

    let named = resolve_node_names(parsed, &[]).expect("valid name");

    assert_eq!(accepted_names(&named), ["x".repeat(128)]);
    assert_eq!(
        named
            .diagnostics()
            .count(NodeNameDiagnosticKind::OversizedFallback),
        0
    );
    assert_eq!(
        named
            .diagnostics()
            .count(NodeNameDiagnosticKind::GraphemeTruncated),
        1
    );
}

#[test]
fn removes_unsafe_codepoints_before_nfc_and_keeps_approved_exceptions() {
    let woman_technologist = "\u{1f469}\u{200d}\u{1f4bb}";
    let tagged_flag = "\u{1f3f4}\u{e0067}\u{e0062}\u{e007f}";
    let source = format!(
        "{VLESS_PREFIX}#a\u{034f}\u{0301}\u{200b}\u{202e}\u{0001}\n\
         {VLESS_PREFIX}#{woman_technologist}\u{fe0f}\n\
         {VLESS_PREFIX}#{tagged_flag}\n\
         {VLESS_PREFIX}#X\u{e0067}Y\n\
         {VLESS_PREFIX}#\u{e000}\u{fffd}"
    );
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid Unicode source");

    let named = resolve_node_names(parsed, &[]).expect("valid names");

    assert_eq!(
        accepted_names(&named),
        [
            "\u{00e1}",
            "\u{1f469}\u{200d}\u{1f4bb}\u{fe0f}",
            tagged_flag,
            "XY",
            "\u{e000}\u{fffd}",
        ]
    );
    assert_eq!(
        named
            .diagnostics()
            .count(NodeNameDiagnosticKind::UnsafeCodepointsRemoved),
        2
    );
    assert_eq!(
        named
            .diagnostics()
            .count(NodeNameDiagnosticKind::NfcNormalized),
        1
    );
}

#[test]
fn preserves_join_controls_and_all_variation_selector_ranges() {
    let remarks = [
        "A\u{200c}B",
        "A\u{200d}B",
        "A\u{180b}B",
        "A\u{180f}B",
        "A\u{fe00}B",
        "A\u{fe0f}B",
        "A\u{e0100}B",
        "A\u{e01ef}B",
    ];
    let source = remarks
        .iter()
        .map(|remark| format!("{VLESS_PREFIX}#{}", percent_encode(remark)))
        .collect::<Vec<_>>()
        .join("\n");
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid source");

    let named = resolve_node_names(parsed, &[]).expect("valid names");

    assert_eq!(accepted_names(&named), remarks);
    assert_eq!(
        named
            .diagnostics()
            .count(NodeNameDiagnosticKind::UnsafeCodepointsRemoved),
        0
    );
}

#[test]
fn emoji_tag_sequences_obey_well_formedness_and_thirty_two_scalar_limit() {
    let valid_31_scalars = format!("*{}\u{e007f}", "\u{e0061}".repeat(29));
    let valid_32_scalars = format!("*{}\u{e007f}", "\u{e0061}".repeat(30));
    let over_limit = format!("*{}\u{e007f}", "\u{e0061}".repeat(31));
    let empty_tag_spec = "*\u{e007f}";
    let source = [
        valid_31_scalars.as_str(),
        valid_32_scalars.as_str(),
        over_limit.as_str(),
        empty_tag_spec,
    ]
    .iter()
    .map(|remark| format!("{VLESS_PREFIX}#{}", percent_encode(remark)))
    .collect::<Vec<_>>()
    .join("\n");
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid source");

    let named = resolve_node_names(parsed, &[]).expect("valid names");

    assert_eq!(
        accepted_names(&named),
        [
            valid_31_scalars.as_str(),
            "VLESS example.com:443",
            "*",
            "*~00001",
        ]
    );
    assert_eq!(
        named
            .diagnostics()
            .count(NodeNameDiagnosticKind::OversizedSingleGraphemeFallback),
        1
    );
    assert_eq!(
        named
            .diagnostics()
            .count(NodeNameDiagnosticKind::UnsafeCodepointsRemoved),
        2
    );
}

#[test]
fn emoji_tag_sequence_requires_a_valid_unicode_17_presentation_sequence() {
    let tags = "\u{e0061}\u{e007f}";
    let invalid_presentation_base = format!("😀\u{fe0f}{tags}");
    let valid_presentation_base = format!("♻\u{fe0f}{tags}");
    let source = [
        invalid_presentation_base.as_str(),
        valid_presentation_base.as_str(),
    ]
    .iter()
    .map(|remark| format!("{VLESS_PREFIX}#{}", percent_encode(remark)))
    .collect::<Vec<_>>()
    .join("\n");
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid source");

    let named = resolve_node_names(parsed, &[]).expect("valid names");

    assert_eq!(
        accepted_names(&named),
        ["😀\u{fe0f}", valid_presentation_base.as_str()]
    );
    assert_eq!(
        named
            .diagnostics()
            .count(NodeNameDiagnosticKind::UnsafeCodepointsRemoved),
        1
    );
}

#[test]
fn unassigned_noncharacter_and_clean_empty_remarks_use_fallback() {
    let source = format!(
        "{VLESS_PREFIX}#A\u{0378}\n{VLESS_PREFIX}#A\u{fdd0}\n{VLESS_PREFIX}#\u{200b}\u{202e}"
    );
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid source encoding");

    let named = resolve_node_names(parsed, &[]).expect("fallbacks are recoverable");

    assert_eq!(
        accepted_names(&named),
        [
            "VLESS example.com:443",
            "VLESS example.com:443~00001",
            "VLESS example.com:443~00002",
        ]
    );
    assert_eq!(
        named
            .diagnostics()
            .count(NodeNameDiagnosticKind::UnassignedOrNoncharacterFallback),
        2
    );
    assert_eq!(
        named
            .diagnostics()
            .count(NodeNameDiagnosticKind::EmptyAfterCleaningFallback),
        1
    );
}

#[test]
fn validates_the_complete_group_namespace_before_allocating_nodes() {
    let oversized = "x".repeat(129);
    let cases: [(&[&str], NodeNameError); 6] = [
        (
            &[""],
            NodeNameError::Group {
                group_index: 0,
                reason: GroupNameError::Empty,
            },
        ),
        (
            &[oversized.as_str()],
            NodeNameError::Group {
                group_index: 0,
                reason: GroupNameError::TooLong,
            },
        ),
        (
            &[" Group"],
            NodeNameError::Group {
                group_index: 0,
                reason: GroupNameError::NonCanonical,
            },
        ),
        (
            &["Group,Other"],
            NodeNameError::Group {
                group_index: 0,
                reason: GroupNameError::ContainsComma,
            },
        ),
        (
            &["DIRECT"],
            NodeNameError::Group {
                group_index: 0,
                reason: GroupNameError::Reserved,
            },
        ),
        (
            &["Group", "Group"],
            NodeNameError::Group {
                group_index: 1,
                reason: GroupNameError::Duplicate {
                    first_group_index: 0,
                },
            },
        ),
    ];

    for (groups, expected) in cases {
        let parsed = parse_subscription_sources(&[b"".as_slice()]).expect("empty source");
        assert_eq!(resolve_node_names(parsed, groups), Err(expected));
    }

    let parsed = parse_subscription_sources(&[b"".as_slice()]).expect("empty source");
    assert!(resolve_node_names(parsed, &ACL4SSR_VS16_GROUPS).is_ok());
}

#[test]
fn frozen_symbol_set_is_limited_to_ten_thousand_unique_names() {
    let groups = (0..9_998)
        .map(|index| format!("Group {index}"))
        .collect::<Vec<_>>();
    let group_refs = groups.iter().map(String::as_str).collect::<Vec<_>>();
    let parsed = parse_subscription_sources(&[b"".as_slice()]).expect("empty source");
    assert!(resolve_node_names(parsed, &group_refs).is_ok());

    let groups = (0..9_999)
        .map(|index| format!("Group {index}"))
        .collect::<Vec<_>>();
    let group_refs = groups.iter().map(String::as_str).collect::<Vec<_>>();
    let parsed = parse_subscription_sources(&[b"".as_slice()]).expect("empty source");
    assert_eq!(
        resolve_node_names(parsed, &group_refs),
        Err(NodeNameError::TooManySymbols)
    );
}

#[test]
fn allocator_respects_reserved_group_and_suffix_occupancy_in_origin_order() {
    let fragments = ["DIRECT", "Group", "X", "X", "X~00001"];
    let source = fragments
        .iter()
        .map(|fragment| format!("{VLESS_PREFIX}#{fragment}"))
        .collect::<Vec<_>>()
        .join("\n");
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid source");

    let named = resolve_node_names(parsed, &["Group"]).expect("valid namespace");

    assert_eq!(
        accepted_names(&named),
        [
            "DIRECT~00001",
            "Group~00001",
            "X",
            "X~00001",
            "X~00001~00001",
        ]
    );
    assert_eq!(
        named
            .diagnostics()
            .count(NodeNameDiagnosticKind::CollisionSuffixed),
        4
    );

    let source = ["X~00001", "X", "X"]
        .iter()
        .map(|fragment| format!("{VLESS_PREFIX}#{fragment}"))
        .collect::<Vec<_>>()
        .join("\n");
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid source");
    let named = resolve_node_names(parsed, &[]).expect("valid namespace");
    assert_eq!(accepted_names(&named), ["X~00001", "X", "X~00002"]);
}

#[test]
fn canonical_equivalents_collide_and_suffix_counter_crosses_decimal_width() {
    let mut fragments = vec!["é".to_owned(), "e\u{0301}".to_owned()];
    fragments.extend(std::iter::repeat_n("Counter".to_owned(), 11));
    let source = fragments
        .iter()
        .map(|fragment| format!("{VLESS_PREFIX}#{fragment}"))
        .collect::<Vec<_>>()
        .join("\n");
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid source");

    let named = resolve_node_names(parsed, &[]).expect("valid names");
    let allocated = accepted_names(&named);

    assert_eq!(&allocated[..2], ["é", "é~00001"]);
    assert_eq!(allocated.last(), Some(&"Counter~00010"));
    assert_eq!(
        named
            .diagnostics()
            .count(NodeNameDiagnosticKind::NfcNormalized),
        1
    );
    assert_eq!(
        named
            .diagnostics()
            .count(NodeNameDiagnosticKind::CollisionSuffixed),
        11
    );
}

#[test]
fn truncation_and_single_grapheme_fallback_obey_128_and_122_byte_budgets() {
    let long_ascii = "a".repeat(129);
    let cluster_122 = format!("q{}\u{20dd}", "\u{0301}".repeat(59));
    let cluster_123 = format!("q{}", "\u{0301}".repeat(61));
    assert_eq!(cluster_122.len(), 122);
    assert_eq!(cluster_123.len(), 123);
    let fragments = [
        long_ascii.as_str(),
        long_ascii.as_str(),
        cluster_122.as_str(),
        cluster_122.as_str(),
        cluster_123.as_str(),
    ];
    let source = fragments
        .iter()
        .map(|fragment| format!("{VLESS_PREFIX}#{fragment}"))
        .collect::<Vec<_>>()
        .join("\n");
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid source");

    let named = resolve_node_names(parsed, &[]).expect("valid names");
    let allocated = accepted_names(&named);

    assert_eq!(allocated[0], "a".repeat(128));
    assert_eq!(allocated[1], format!("{}~00001", "a".repeat(122)));
    assert_eq!(allocated[2], cluster_122);
    assert_eq!(allocated[3], format!("{cluster_122}~00001"));
    assert_eq!(allocated[4], "VLESS example.com:443");
    assert_eq!(
        named
            .diagnostics()
            .count(NodeNameDiagnosticKind::GraphemeTruncated),
        2
    );
    assert_eq!(
        named
            .diagnostics()
            .count(NodeNameDiagnosticKind::OversizedSingleGraphemeFallback),
        1
    );
}

#[test]
fn truncation_never_splits_a_zwj_emoji_cluster() {
    let remark = format!("{}👩‍💻", "a".repeat(120));
    let source = format!("{VLESS_PREFIX}#{}", percent_encode(&remark));
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid source");

    let named = resolve_node_names(parsed, &[]).expect("valid name");

    assert_eq!(accepted_names(&named), ["a".repeat(120)]);
    assert_eq!(
        named
            .diagnostics()
            .count(NodeNameDiagnosticKind::GraphemeTruncated),
        1
    );
}

#[test]
fn rejected_occurrences_remain_in_place_and_do_not_occupy_names() {
    let source = format!("{VLESS_PREFIX}#X\nunknown://secret@example.invalid#X\n{VLESS_PREFIX}#X");
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("mixed source");

    let named = resolve_node_names(parsed, &[]).expect("valid names");

    assert_eq!(named.occurrences().len(), 3);
    assert!(matches!(
        named.occurrences()[1],
        NamedNodeOccurrence::Rejected { .. }
    ));
    assert_eq!(accepted_names(&named), ["X", "X~00001"]);
}

#[test]
fn accepted_duplicates_from_multiple_sources_are_named_in_declaration_order() {
    let first = format!("{VLESS_PREFIX}#Same\n{VLESS_PREFIX}#Same");
    let second = format!("{VLESS_PREFIX}#Same");
    let parsed = parse_subscription_sources(&[first.as_bytes(), second.as_bytes()])
        .expect("ordered duplicate sources");

    let named = resolve_node_names(parsed, &[]).expect("valid names");

    assert_eq!(accepted_names(&named), ["Same", "Same~00001", "Same~00002"]);
}

#[test]
fn naming_debug_output_does_not_retain_raw_names_groups_or_credentials() {
    const CANARY: &str = "naming-secret-canary";
    let source = format!("ss://aes-128-gcm:{CANARY}@example.net:8388#{CANARY}");
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("valid source");
    let named = resolve_node_names(parsed, &[]).expect("valid name");

    let rendered = format!("{named:?}");
    assert!(!rendered.contains(CANARY));
    assert!(!rendered.contains("password"));

    let parsed = parse_subscription_sources(&[b"".as_slice()]).expect("empty source");
    let error = resolve_node_names(parsed, &[CANARY, CANARY]).expect_err("duplicate group");
    assert!(!format!("{error:?}").contains(CANARY));
}

#[cfg(not(target_family = "wasm"))]
#[test]
fn ten_thousand_duplicate_occurrences_terminate_with_five_digit_suffixes() {
    let line = format!("{VLESS_PREFIX}#Scale");
    let source = std::iter::repeat_n(line.as_str(), 10_000)
        .collect::<Vec<_>>()
        .join("\n");
    let parsed = parse_subscription_sources(&[source.as_bytes()]).expect("maximum occurrences");

    let named = resolve_node_names(parsed, &[]).expect("allocator terminates");
    let allocated = accepted_names(&named);

    assert_eq!(allocated.len(), 10_000);
    assert_eq!(allocated[0], "Scale");
    assert_eq!(allocated[9_999], "Scale~09999");
    assert_eq!(
        named
            .diagnostics()
            .count(NodeNameDiagnosticKind::CollisionSuffixed),
        9_999
    );
}

#[cfg(not(target_family = "wasm"))]
mod properties {
    use std::collections::BTreeSet;

    use proptest::prelude::*;

    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn arbitrary_unicode_is_deterministic_bounded_unique_and_never_panics(
            characters in prop::collection::vec(any::<char>(), 0..=300),
        ) {
            let remark: String = characters.into_iter().collect();
            let encoded = super::percent_encode(&remark);
            let source = format!("{VLESS_PREFIX}#{encoded}");
            let first_parsed = parse_subscription_sources(&[source.as_bytes()])
                .expect("bounded percent-encoded source");
            let second_parsed = parse_subscription_sources(&[source.as_bytes()])
                .expect("bounded percent-encoded source");

            let first = resolve_node_names(first_parsed, &["Group"]);
            let second = resolve_node_names(second_parsed, &["Group"]);

            prop_assert_eq!(&first, &second);
            let named = first.expect("valid fixed namespace");
            let names = accepted_names(&named);
            prop_assert_eq!(names.len(), 1);
            prop_assert!(!names[0].is_empty());
            prop_assert!(names[0].len() <= 128);
            prop_assert_ne!(names[0], "Group");
            prop_assert!(!["DIRECT", "REJECT", "REJECT-DROP", "COMPATIBLE", "PASS", "PASS-RULE", "GLOBAL"]
                .contains(&names[0]));
            prop_assert_eq!(names.iter().copied().collect::<BTreeSet<_>>().len(), names.len());
        }
    }
}

fn percent_encode(input: &str) -> String {
    let mut encoded = String::with_capacity(input.len() * 3);
    for byte in input.bytes() {
        write!(&mut encoded, "%{byte:02X}").expect("writing to a String cannot fail");
    }
    encoded
}

fn accepted_names(named: &NamedSubscriptionSources) -> Vec<&str> {
    named
        .occurrences()
        .iter()
        .filter_map(|occurrence| match occurrence {
            NamedNodeOccurrence::Accepted { node, .. } => Some(node.name().as_str()),
            NamedNodeOccurrence::Rejected { .. } => None,
        })
        .collect()
}
