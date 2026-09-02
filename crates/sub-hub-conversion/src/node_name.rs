use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use unicode_normalization::UnicodeNormalization;
use unicode_properties::{EmojiStatus, GeneralCategory, UnicodeEmoji, UnicodeGeneralCategory};
use unicode_segmentation::UnicodeSegmentation;

use crate::{
    node::{Host, NodeNameInput, NodeProtocol, ProxyNode, ProxyNodeDraft},
    subscription_source::{NodeOccurrence, ParsedSubscriptionSources},
};

mod unicode_17;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct NodeNameV1(String);

impl NodeNameV1 {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for NodeNameV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NodeNameV1([REDACTED])")
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct NamedSubscriptionSources {
    occurrences: Vec<NamedNodeOccurrence>,
    #[cfg(test)]
    diagnostics: NodeNameDiagnostics,
    unexpanded_https: Vec<String>,
}

impl NamedSubscriptionSources {
    pub(crate) fn occurrences(&self) -> &[NamedNodeOccurrence] {
        &self.occurrences
    }

    #[cfg(test)]
    pub(crate) const fn diagnostics(&self) -> &NodeNameDiagnostics {
        &self.diagnostics
    }

    pub(crate) fn parse_skip_count(&self) -> u32 {
        NodeOccurrence::rejected_count(&self.occurrences)
    }
}

pub(crate) type NamedNodeOccurrence = NodeOccurrence<ProxyNode>;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NodeNameError {
    Group {
        group_index: usize,
        reason: GroupNameError,
    },
    TooManySymbols,
    AllocatorExhausted,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum GroupNameError {
    Empty,
    TooLong,
    NonCanonical,
    ContainsComma,
    Reserved,
    Duplicate { first_group_index: usize },
}

#[cfg(test)]
const NODE_NAME_DIAGNOSTIC_KIND_COUNT: usize = 11;

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NodeNameDiagnosticKind {
    MissingFallback,
    EmptyFallback,
    OversizedFallback,
    UnassignedOrNoncharacterFallback,
    EmptyAfterCleaningFallback,
    OversizedSingleGraphemeFallback,
    WhitespaceCanonicalized,
    UnsafeCodepointsRemoved,
    NfcNormalized,
    GraphemeTruncated,
    CollisionSuffixed,
}

#[cfg(test)]
impl NodeNameDiagnosticKind {
    const fn index(self) -> usize {
        match self {
            Self::MissingFallback => 0,
            Self::EmptyFallback => 1,
            Self::OversizedFallback => 2,
            Self::UnassignedOrNoncharacterFallback => 3,
            Self::EmptyAfterCleaningFallback => 4,
            Self::OversizedSingleGraphemeFallback => 5,
            Self::WhitespaceCanonicalized => 6,
            Self::UnsafeCodepointsRemoved => 7,
            Self::NfcNormalized => 8,
            Self::GraphemeTruncated => 9,
            Self::CollisionSuffixed => 10,
        }
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct NodeNameDiagnostics {
    counts: [u32; NODE_NAME_DIAGNOSTIC_KIND_COUNT],
}

#[cfg(test)]
impl NodeNameDiagnostics {
    pub(crate) const fn count(&self, kind: NodeNameDiagnosticKind) -> u32 {
        self.counts[kind.index()]
    }

    fn increment(&mut self, kind: NodeNameDiagnosticKind) {
        self.counts[kind.index()] += 1;
    }
}

#[cfg_attr(
    not(test),
    expect(dead_code, reason = "crate tests call the two-argument form")
)]
pub(crate) fn resolve_node_names(
    parsed: ParsedSubscriptionSources,
    final_group_names: &[&str],
) -> Result<NamedSubscriptionSources, NodeNameError> {
    resolve_node_names_reserving(parsed, final_group_names, &[])
}

pub(crate) fn resolve_node_names_reserving(
    parsed: ParsedSubscriptionSources,
    final_group_names: &[&str],
    reserved_extra: &[&str],
) -> Result<NamedSubscriptionSources, NodeNameError> {
    #[cfg(test)]
    let mut diagnostics = NodeNameDiagnostics::default();
    let mut allocator = NameAllocator::new(final_group_names, reserved_extra)?;
    let unexpanded_https = parsed.unexpanded_https;
    let occurrences = parsed
        .occurrences
        .into_iter()
        .map(|occurrence| match occurrence {
            NodeOccurrence::Accepted { origin, node } => {
                let canonical_base = match &node.name_input {
                    NodeNameInput::Missing => {
                        #[cfg(test)]
                        diagnostics.increment(NodeNameDiagnosticKind::MissingFallback);
                        fallback_name(&node)
                    }
                    NodeNameInput::Decoded(input) if input.is_empty() => {
                        #[cfg(test)]
                        diagnostics.increment(NodeNameDiagnosticKind::EmptyFallback);
                        fallback_name(&node)
                    }
                    NodeNameInput::Decoded(input) if input.len() > 1_024 => {
                        #[cfg(test)]
                        diagnostics.increment(NodeNameDiagnosticKind::OversizedFallback);
                        fallback_name(&node)
                    }
                    NodeNameInput::Decoded(input)
                        if input.chars().any(|character| {
                            character.general_category() == GeneralCategory::Unassigned
                        }) =>
                    {
                        #[cfg(test)]
                        diagnostics
                            .increment(NodeNameDiagnosticKind::UnassignedOrNoncharacterFallback);
                        fallback_name(&node)
                    }
                    NodeNameInput::Decoded(input) => {
                        let canonicalized = canonicalize(input);
                        if canonicalized.whitespace_changed {
                            #[cfg(test)]
                            diagnostics.increment(NodeNameDiagnosticKind::WhitespaceCanonicalized);
                        }
                        if canonicalized.unsafe_codepoints_removed {
                            #[cfg(test)]
                            diagnostics.increment(NodeNameDiagnosticKind::UnsafeCodepointsRemoved);
                        }
                        if canonicalized.nfc_normalized {
                            #[cfg(test)]
                            diagnostics.increment(NodeNameDiagnosticKind::NfcNormalized);
                        }
                        if canonicalized.text.is_empty() {
                            #[cfg(test)]
                            diagnostics
                                .increment(NodeNameDiagnosticKind::EmptyAfterCleaningFallback);
                            fallback_name(&node)
                        } else if canonicalized
                            .text
                            .graphemes(true)
                            .any(|grapheme| grapheme.len() > 122)
                        {
                            #[cfg(test)]
                            diagnostics
                                .increment(NodeNameDiagnosticKind::OversizedSingleGraphemeFallback);
                            fallback_name(&node)
                        } else {
                            canonicalized.text
                        }
                    }
                };
                let (name, collision_suffixed, grapheme_truncated) =
                    allocator.allocate(&canonical_base)?;
                if collision_suffixed {
                    #[cfg(test)]
                    diagnostics.increment(NodeNameDiagnosticKind::CollisionSuffixed);
                }
                if grapheme_truncated {
                    #[cfg(test)]
                    diagnostics.increment(NodeNameDiagnosticKind::GraphemeTruncated);
                }
                Ok(NodeOccurrence::Accepted {
                    origin,
                    node: Box::new(node.into_named(NodeNameV1(name))),
                })
            }
            NodeOccurrence::Rejected { origin, rejection } => {
                Ok(NodeOccurrence::Rejected { origin, rejection })
            }
        })
        .collect::<Result<Vec<_>, NodeNameError>>()?;

    Ok(NamedSubscriptionSources {
        occurrences,
        #[cfg(test)]
        diagnostics,
        unexpanded_https,
    })
}

/// Portable policy tokens occupied during naming so allocated node names do not
/// collide with Direct/Reject. Client-reserved tags live in Keep-pass.
const POLICY_TOKENS: [&str; 2] = ["DIRECT", "REJECT"];

pub(crate) fn is_policy_token(value: &str) -> bool {
    POLICY_TOKENS.contains(&value)
}
const MAX_FROZEN_SYMBOLS: usize = 10_000;

struct NameAllocator {
    occupied: BTreeSet<String>,
    next_counters: BTreeMap<String, u32>,
}

impl NameAllocator {
    fn new(final_group_names: &[&str], reserved_extra: &[&str]) -> Result<Self, NodeNameError> {
        let mut occupied = POLICY_TOKENS
            .into_iter()
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        let mut group_indices = BTreeMap::new();

        for (group_index, group_name) in final_group_names.iter().copied().enumerate() {
            let reason = validate_group_name(group_name).or_else(|| {
                if is_policy_token(group_name) {
                    Some(GroupNameError::Reserved)
                } else {
                    group_indices
                        .get(group_name)
                        .copied()
                        .map(|first_group_index| GroupNameError::Duplicate { first_group_index })
                }
            });
            if let Some(reason) = reason {
                return Err(NodeNameError::Group {
                    group_index,
                    reason,
                });
            }
            if occupied.len() == MAX_FROZEN_SYMBOLS {
                return Err(NodeNameError::TooManySymbols);
            }
            occupied.insert(group_name.to_owned());
            group_indices.insert(group_name, group_index);
        }

        for extra in reserved_extra {
            if extra.is_empty() {
                continue;
            }
            if occupied.len() == MAX_FROZEN_SYMBOLS {
                return Err(NodeNameError::TooManySymbols);
            }
            occupied.insert((*extra).to_owned());
        }

        Ok(Self {
            occupied,
            next_counters: BTreeMap::new(),
        })
    }

    fn allocate(&mut self, canonical_base: &str) -> Result<(String, bool, bool), NodeNameError> {
        let bare = grapheme_prefix(canonical_base, 128);
        if self.occupied.insert(bare.clone()) {
            let truncated = bare.len() < canonical_base.len();
            return Ok((bare, false, truncated));
        }

        let root = grapheme_prefix(canonical_base, 122);
        let truncated = root.len() < canonical_base.len();
        let first_counter = self.next_counters.get(&root).copied().unwrap_or(1);
        for counter in first_counter..=99_999_u32 {
            let candidate = format!("{root}~{counter:05}");
            if self.occupied.insert(candidate.clone()) {
                self.next_counters.insert(root, counter + 1);
                return Ok((candidate, true, truncated));
            }
        }
        Err(NodeNameError::AllocatorExhausted)
    }
}

pub(crate) fn validate_group_name(group_name: &str) -> Option<GroupNameError> {
    if group_name.is_empty() {
        Some(GroupNameError::Empty)
    } else if group_name.len() > 128 {
        Some(GroupNameError::TooLong)
    } else if group_name
        .chars()
        .any(|character| character.general_category() == GeneralCategory::Unassigned)
        || canonicalize(group_name).text != group_name
    {
        Some(GroupNameError::NonCanonical)
    } else if group_name.contains(',') {
        Some(GroupNameError::ContainsComma)
    } else {
        None
    }
}

fn grapheme_prefix(input: &str, byte_budget: usize) -> String {
    let mut end = 0;
    for grapheme in input.graphemes(true) {
        let candidate_end = end + grapheme.len();
        if candidate_end > byte_budget {
            break;
        }
        end = candidate_end;
    }
    input[..end].to_owned()
}

fn fallback_name(node: &ProxyNodeDraft) -> String {
    let protocol = match &node.protocol {
        NodeProtocol::Vless(_) => "VLESS",
        NodeProtocol::Shadowsocks(_) => "SS",
        NodeProtocol::Trojan(_) => "Trojan",
        NodeProtocol::Vmess(_) => "VMess",
        NodeProtocol::Hysteria2(_) => "Hysteria2",
        NodeProtocol::Tuic(_) => "TUIC",
    };
    let host = match node.endpoint.host() {
        Host::Domain(domain) => domain.clone(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => format!("[{address}]"),
    };
    format!("{protocol} {host}:{}", node.endpoint.port())
}

struct CanonicalizedName {
    text: String,
    whitespace_changed: bool,
    unsafe_codepoints_removed: bool,
    nfc_normalized: bool,
}

fn canonicalize(input: &str) -> CanonicalizedName {
    let whitespace_canonicalized = canonicalize_whitespace(input);
    let whitespace_changed = whitespace_canonicalized != input;
    let (cleaned, unsafe_codepoints_removed) = remove_unsafe_codepoints(&whitespace_canonicalized);
    let normalized: String = cleaned.nfc().collect();
    let nfc_normalized = normalized != cleaned;

    CanonicalizedName {
        text: normalized,
        whitespace_changed,
        unsafe_codepoints_removed,
        nfc_normalized,
    }
}

fn canonicalize_whitespace(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut pending_space = false;

    for character in input.chars() {
        if unicode_17::is_white_space(character) {
            pending_space = !output.is_empty();
        } else {
            if pending_space {
                output.push(' ');
                pending_space = false;
            }
            output.push(character);
        }
    }

    output
}

fn remove_unsafe_codepoints(input: &str) -> (String, bool) {
    let characters: Vec<char> = input.chars().collect();
    let mut output = String::with_capacity(input.len());
    let mut removed = false;
    let mut index = 0;

    while index < characters.len() {
        if let Some(end) = emoji_tag_sequence_end(&characters, index) {
            output.extend(characters[index..end].iter());
            index = end;
            continue;
        }

        let character = characters[index];
        let must_remove = unicode_17::is_bidi_control(character)
            || (!unicode_17::is_join_control(character)
                && !unicode_17::is_variation_selector(character)
                && (matches!(
                    character.general_category(),
                    GeneralCategory::Control | GeneralCategory::Format
                ) || unicode_17::is_default_ignorable(character)));
        if must_remove {
            removed = true;
        } else {
            output.push(character);
        }
        index += 1;
    }

    (output, removed)
}

fn emoji_tag_sequence_end(characters: &[char], start: usize) -> Option<usize> {
    let first = *characters.get(start)?;
    if !first.is_emoji_char() {
        return None;
    }

    let mut tag_spec_start = start + 1;
    if let Some(next) = characters.get(tag_spec_start)
        && (is_emoji_modifier_base(first) && is_emoji_modifier(*next)
            || *next == '\u{fe0f}' && unicode_17::is_emoji_presentation_sequence_base(first))
    {
        tag_spec_start += 1;
    }
    let mut end = tag_spec_start;
    while matches!(characters.get(end), Some('\u{e0020}'..='\u{e007e}')) {
        end += 1;
    }
    if end == tag_spec_start || characters.get(end) != Some(&'\u{e007f}') {
        return None;
    }
    end += 1;
    (end - start <= 32).then_some(end)
}

fn is_emoji_modifier_base(character: char) -> bool {
    matches!(
        character.emoji_status(),
        EmojiStatus::EmojiModifierBase | EmojiStatus::EmojiPresentationAndModifierBase
    )
}

fn is_emoji_modifier(character: char) -> bool {
    matches!(
        character.emoji_status(),
        EmojiStatus::EmojiPresentationAndModifierAndEmojiComponent
    )
}
