mod error;

use std::{borrow::Cow, fmt};

use crate::{
    MAX_SUBSCRIPTION_INPUT_BYTES, MAX_SUBSCRIPTION_SOURCES,
    node::{ProxyNodeDraft, parse_share_uri},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD},
};

const MAX_DECODED_SOURCE_BYTES: usize = 2 * 1024 * 1024;
const MAX_INPUT_BYTES: usize = MAX_SUBSCRIPTION_INPUT_BYTES;
const MAX_NODE_OCCURRENCES: usize = 10_000;

pub(crate) use error::SubscriptionParseError;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ParsedSubscriptionSources {
    pub(crate) occurrences: Vec<NodeOccurrence>,
    pub(crate) remote_decoded_bytes: Vec<Option<usize>>,
}

impl ParsedSubscriptionSources {
    pub(crate) fn parse_skip_count(&self) -> u32 {
        NodeOccurrence::rejected_count(&self.occurrences)
    }
}

#[derive(Clone, Copy)]
pub(crate) enum SubscriptionSourceV1<'a> {
    Direct(&'a str),
    Remote(&'a [u8]),
}

impl fmt::Debug for SubscriptionSourceV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Direct(_) => "Direct([REDACTED])",
            Self::Remote(_) => "Remote([REDACTED])",
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NodeOccurrence<N = ProxyNodeDraft> {
    Accepted {
        origin: NodeOrigin,
        node: Box<N>,
    },
    Rejected {
        origin: NodeOrigin,
        rejection: crate::node::NodeRejection,
    },
}

impl<N> NodeOccurrence<N> {
    pub(crate) fn rejected_count(occurrences: &[Self]) -> u32 {
        u32::try_from(
            occurrences
                .iter()
                .filter(|occurrence| matches!(occurrence, Self::Rejected { .. }))
                .count(),
        )
        .unwrap_or(u32::MAX)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct NodeOrigin {
    pub(crate) source: usize,
    pub(crate) line: usize,
    pub(crate) occurrence: usize,
}

#[cfg(test)]
pub(crate) fn parse_subscription_sources(
    bodies_in_declaration_order: &[&[u8]],
) -> Result<ParsedSubscriptionSources, SubscriptionParseError> {
    let sources = bodies_in_declaration_order
        .iter()
        .copied()
        .map(SubscriptionSourceV1::Remote)
        .collect::<Vec<_>>();
    parse_subscription_source_inputs(&sources)
}

pub(crate) fn parse_subscription_source_inputs(
    sources_in_declaration_order: &[SubscriptionSourceV1<'_>],
) -> Result<ParsedSubscriptionSources, SubscriptionParseError> {
    if sources_in_declaration_order.len() > MAX_SUBSCRIPTION_SOURCES {
        return Err(SubscriptionParseError::TooManySources);
    }

    let mut occurrences = Vec::new();
    let mut remote_decoded_bytes = Vec::with_capacity(sources_in_declaration_order.len());
    let mut total_occurrences = 0;

    for (source_index, source) in sources_in_declaration_order.iter().enumerate() {
        match source {
            SubscriptionSourceV1::Direct(source) => {
                remote_decoded_bytes.push(None);
                let origin = NodeOrigin {
                    source: source_index,
                    line: 0,
                    occurrence: 0,
                };
                push_occurrence(source, origin, &mut occurrences, &mut total_occurrences)?;
            }
            SubscriptionSourceV1::Remote(body) => {
                if body.len() > MAX_INPUT_BYTES {
                    return Err(SubscriptionParseError::InputTooLarge { source_index });
                }
                let selected = select_container(body).map_err(|error| match error {
                    ContainerSelectionError::DecodedTooLarge => {
                        SubscriptionParseError::DecodedSourceTooLarge { source_index }
                    }
                })?;
                if selected.len() > MAX_DECODED_SOURCE_BYTES {
                    return Err(SubscriptionParseError::DecodedSourceTooLarge { source_index });
                }
                remote_decoded_bytes.push(Some(selected.len()));
                let source = std::str::from_utf8(&selected)
                    .map_err(|_| SubscriptionParseError::InvalidUtf8 { source_index })?;
                if has_bare_carriage_return(source.as_bytes()) {
                    return Err(SubscriptionParseError::InvalidLineEnding { source_index });
                }
                let mut occurrence_index = 0;

                for (line_index, line) in source.lines().enumerate() {
                    let line = line.trim_matches([' ', '\t']);
                    if line.is_empty() {
                        continue;
                    }

                    let origin = NodeOrigin {
                        source: source_index,
                        line: line_index,
                        occurrence: occurrence_index,
                    };
                    push_occurrence(line, origin, &mut occurrences, &mut total_occurrences)?;
                    occurrence_index += 1;
                }
            }
        }
    }

    Ok(ParsedSubscriptionSources {
        occurrences,
        remote_decoded_bytes,
    })
}

fn push_occurrence(
    source: &str,
    origin: NodeOrigin,
    occurrences: &mut Vec<NodeOccurrence>,
    total_occurrences: &mut usize,
) -> Result<(), SubscriptionParseError> {
    if *total_occurrences == MAX_NODE_OCCURRENCES {
        return Err(SubscriptionParseError::TooManyOccurrences { at: origin });
    }
    *total_occurrences += 1;
    let occurrence = match parse_share_uri(source) {
        Ok(node) => NodeOccurrence::Accepted {
            origin,
            node: Box::new(node),
        },
        Err(rejection) => NodeOccurrence::Rejected { origin, rejection },
    };
    occurrences.push(occurrence);
    Ok(())
}

#[derive(Clone, Copy)]
enum Base64Alphabet {
    Standard,
    UrlSafe,
}

#[derive(Clone, Copy)]
enum Base64Padding {
    Padded { bytes: usize },
    Unpadded,
}

enum ContainerSelectionError {
    DecodedTooLarge,
}

fn select_container(input: &[u8]) -> Result<Cow<'_, [u8]>, ContainerSelectionError> {
    let probe = strip_one_terminal_line_ending(input);
    if contains_bytes(probe, b"://") || probe.contains(&b'\n') || probe.contains(&b'\r') {
        return Ok(Cow::Borrowed(input));
    }

    let Some((alphabet, padding)) = classify_base64(probe) else {
        return Ok(Cow::Borrowed(input));
    };
    let decoded_len =
        decoded_base64_len(probe.len(), padding).ok_or(ContainerSelectionError::DecodedTooLarge)?;
    if decoded_len > MAX_DECODED_SOURCE_BYTES {
        return Err(ContainerSelectionError::DecodedTooLarge);
    }
    let decoded = match (alphabet, padding) {
        (Base64Alphabet::Standard, Base64Padding::Padded { .. }) => STANDARD.decode(probe),
        (Base64Alphabet::Standard, Base64Padding::Unpadded) => STANDARD_NO_PAD.decode(probe),
        (Base64Alphabet::UrlSafe, Base64Padding::Padded { .. }) => URL_SAFE.decode(probe),
        (Base64Alphabet::UrlSafe, Base64Padding::Unpadded) => URL_SAFE_NO_PAD.decode(probe),
    };

    match decoded {
        Ok(decoded)
            if std::str::from_utf8(&decoded).is_ok() && contains_bytes(&decoded, b"://") =>
        {
            Ok(Cow::Owned(decoded))
        }
        Ok(_) | Err(_) => Ok(Cow::Borrowed(input)),
    }
}

fn strip_one_terminal_line_ending(input: &[u8]) -> &[u8] {
    input
        .strip_suffix(b"\r\n")
        .or_else(|| input.strip_suffix(b"\n"))
        .unwrap_or(input)
}

fn classify_base64(input: &[u8]) -> Option<(Base64Alphabet, Base64Padding)> {
    if input.is_empty() {
        return None;
    }

    let first_padding = input
        .iter()
        .position(|byte| *byte == b'=')
        .unwrap_or(input.len());
    let (data, padding) = input.split_at(first_padding);
    let padding = if padding.is_empty() {
        if data.len() % 4 == 1 {
            return None;
        }
        Base64Padding::Unpadded
    } else {
        let padding_is_canonical = padding.len() <= 2
            && padding.iter().all(|byte| *byte == b'=')
            && input.len().is_multiple_of(4)
            && matches!((data.len() % 4, padding.len()), (2, 2) | (3, 1));
        if !padding_is_canonical {
            return None;
        }
        Base64Padding::Padded {
            bytes: padding.len(),
        }
    };

    let mut has_standard_symbol = false;
    let mut has_url_safe_symbol = false;
    for byte in data {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' => {}
            b'+' | b'/' => has_standard_symbol = true,
            b'-' | b'_' => has_url_safe_symbol = true,
            _ => return None,
        }
    }
    if data.is_empty()
        || (has_standard_symbol && has_url_safe_symbol)
        || !has_canonical_trailing_bits(data)
    {
        return None;
    }

    let alphabet = if has_url_safe_symbol {
        Base64Alphabet::UrlSafe
    } else {
        Base64Alphabet::Standard
    };
    Some((alphabet, padding))
}

fn decoded_base64_len(encoded_len: usize, padding: Base64Padding) -> Option<usize> {
    match padding {
        Base64Padding::Padded { bytes } => encoded_len
            .checked_div(4)?
            .checked_mul(3)?
            .checked_sub(bytes),
        Base64Padding::Unpadded => {
            encoded_len
                .checked_div(4)?
                .checked_mul(3)?
                .checked_add(match encoded_len % 4 {
                    0 => 0,
                    2 => 1,
                    3 => 2,
                    _ => return None,
                })
        }
    }
}

fn has_canonical_trailing_bits(data: &[u8]) -> bool {
    let unused_bit_mask = match data.len() % 4 {
        0 => return true,
        2 => 0b1111,
        3 => 0b11,
        _ => return false,
    };
    let Some(last) = data.last() else {
        return false;
    };
    base64_sextet(*last).is_some_and(|sextet| sextet & unused_bit_mask == 0)
}

fn base64_sextet(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn has_bare_carriage_return(input: &[u8]) -> bool {
    input
        .iter()
        .enumerate()
        .any(|(index, byte)| *byte == b'\r' && input.get(index + 1) != Some(&b'\n'))
}

#[cfg(test)]
mod tests;
