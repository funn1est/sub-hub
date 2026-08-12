use std::fmt;

use crate::{
    mihomo::{BuiltinMihomoError, render_builtin_mihomo_v1},
    share_uri::parse_share_uri,
    subscription_source::{NodeOccurrence, NodeOrigin, ParsedSubscriptionSources},
};

const MAX_DIRECT_SOURCES: usize = 5;

pub struct PreparedDirectSubscriptionV1 {
    parsed: ParsedSubscriptionSources,
}

impl PreparedDirectSubscriptionV1 {
    /// Consumes the prepared direct subscription and renders the builtin Mihomo v1 document.
    ///
    /// # Errors
    ///
    /// Returns [`DirectRenderError::ConversionLimit`] when the bounded output exceeds its fixed
    /// limit, or [`DirectRenderError::Internal`] when naming or serialization cannot complete.
    pub fn render_builtin_mihomo_v1(self) -> Result<MihomoConfig, DirectRenderError> {
        match render_builtin_mihomo_v1(self.parsed) {
            Ok(output) => Ok(MihomoConfig {
                bytes: output.config().to_vec(),
            }),
            Err(BuiltinMihomoError::OutputTooLarge { .. }) => {
                Err(DirectRenderError::ConversionLimit)
            }
            Err(
                BuiltinMihomoError::NodeNaming(_)
                | BuiltinMihomoError::NoValidNodes { .. }
                | BuiltinMihomoError::Serialization,
            ) => Err(DirectRenderError::Internal),
        }
    }
}

impl fmt::Debug for PreparedDirectSubscriptionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedDirectSubscriptionV1")
            .field("parsed", &"[REDACTED]")
            .finish()
    }
}

pub struct MihomoConfig {
    bytes: Vec<u8>,
}

impl MihomoConfig {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl fmt::Debug for MihomoConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MihomoConfig")
            .field("bytes", &"[REDACTED]")
            .field("bytes_len", &self.bytes.len())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectPreparationError {
    InvalidInput,
    NoValidNodes,
}

impl fmt::Display for DirectPreparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput => formatter.write_str("invalid direct subscription input"),
            Self::NoValidNodes => formatter.write_str("no valid nodes"),
        }
    }
}

impl std::error::Error for DirectPreparationError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectRenderError {
    ConversionLimit,
    Internal,
}

impl fmt::Display for DirectRenderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConversionLimit => formatter.write_str("conversion resource limit exceeded"),
            Self::Internal => formatter.write_str("internal conversion error"),
        }
    }
}

impl std::error::Error for DirectRenderError {}

/// Parses one to five already-framed direct share URI occurrences in declaration order.
///
/// Each input is one occurrence. This interface performs no trimming, line framing, whole-source
/// Base64 probing, or remote loading. Unsupported individual URI schemes are local rejections as
/// long as at least one occurrence is valid.
///
/// # Errors
///
/// Returns [`DirectPreparationError::InvalidInput`] when the occurrence count or framing is
/// invalid, and [`DirectPreparationError::NoValidNodes`] when every occurrence is rejected.
pub fn prepare_direct_subscription_v1(
    sources_in_declaration_order: &[&str],
) -> Result<PreparedDirectSubscriptionV1, DirectPreparationError> {
    if sources_in_declaration_order.is_empty()
        || sources_in_declaration_order.len() > MAX_DIRECT_SOURCES
        || sources_in_declaration_order.iter().any(|source| {
            source.is_empty()
                || source.starts_with([' ', '\t'])
                || source.ends_with([' ', '\t'])
                || source.contains(['\r', '\n'])
        })
    {
        return Err(DirectPreparationError::InvalidInput);
    }

    let mut has_valid_node = false;
    let occurrences = sources_in_declaration_order
        .iter()
        .enumerate()
        .map(|(source_index, source)| {
            let origin = NodeOrigin {
                source: source_index,
                line: 0,
                occurrence: 0,
            };
            match parse_share_uri(source) {
                Ok(node) => {
                    has_valid_node = true;
                    NodeOccurrence::Accepted {
                        origin,
                        node: Box::new(node),
                    }
                }
                Err(rejection) => NodeOccurrence::Rejected { origin, rejection },
            }
        })
        .collect();

    if !has_valid_node {
        return Err(DirectPreparationError::NoValidNodes);
    }

    Ok(PreparedDirectSubscriptionV1 {
        parsed: ParsedSubscriptionSources { occurrences },
    })
}
