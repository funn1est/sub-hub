use std::fmt;

use crate::{
    MAX_SUBSCRIPTION_SOURCES, OutputTarget,
    render::{BuiltinRenderError, render_builtin_v1},
    skip::SkipCountsV1,
    subscription_source::{
        NodeOccurrence, ParsedSubscriptionSources, SubscriptionParseError, SubscriptionSourceInput,
        parse_subscription_source_inputs,
    },
};

pub struct PreparedSubscriptionV1 {
    parsed: ParsedSubscriptionSources,
}

impl PreparedSubscriptionV1 {
    /// Consumes the parsed subscription and prepares a strict ACL4SSR v1 config.
    ///
    /// The returned value contains an ordered, opaque Rule Set fetch plan. This method performs no
    /// network I/O.
    ///
    /// # Errors
    ///
    /// Returns a closed error when the config is malformed, unsupported, or exceeds a fixed limit.
    pub fn prepare_acl4ssr_config_v1(
        self,
        config: &[u8],
    ) -> Result<crate::PreparedAcl4SsrV1, crate::Acl4SsrPreparationError> {
        crate::acl4ssr::prepare(self.parsed, config)
    }

    /// Returns selected/decoded remote bytes aligned with source declaration order.
    ///
    /// Direct occurrences are `None`. Remote sources are `Some(bytes)`, where `bytes` is the raw
    /// source length or the decoded whole-source Base64 length. Duplicate resource occurrences are
    /// deliberately retained; a broker that performed single-flight loading must deduplicate these
    /// values by its own resource identity before aggregate accounting.
    #[must_use]
    pub fn remote_decoded_bytes_by_source(&self) -> &[Option<usize>] {
        &self.parsed.remote_decoded_bytes
    }

    /// Consumes the prepared subscription and renders the builtin document for `target`.
    ///
    /// # Errors
    ///
    /// Returns [`ConversionRenderError::ConversionLimit`] when the bounded output exceeds its fixed
    /// limit, [`ConversionRenderError::NoValidNodes`] when every node is dropped, or
    /// [`ConversionRenderError::Internal`] when naming or serialization cannot complete.
    pub fn render_builtin_v1(
        self,
        target: OutputTarget,
    ) -> Result<RenderedConfig, ConversionRenderError> {
        match render_builtin_v1(self.parsed, target) {
            Ok(output) => {
                let (bytes, skips) = output.into_rendered();
                Ok(RenderedConfig { bytes, skips })
            }
            Err(error) => Err(map_builtin_error(error)),
        }
    }
}

fn map_builtin_error(error: BuiltinRenderError) -> ConversionRenderError {
    match error {
        BuiltinRenderError::OutputTooLarge { .. } => ConversionRenderError::ConversionLimit,
        BuiltinRenderError::NoValidNodes { diagnostics } => ConversionRenderError::NoValidNodes {
            skips: diagnostics.skip_counts(),
        },
        BuiltinRenderError::NodeNaming(_) | BuiltinRenderError::Serialization => {
            ConversionRenderError::Internal
        }
    }
}

impl fmt::Debug for PreparedSubscriptionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedSubscriptionV1")
            .field("parsed", &"[REDACTED]")
            .finish()
    }
}

/// Bounded rendered document for the selected client target.
pub struct RenderedConfig {
    bytes: Vec<u8>,
    skips: SkipCountsV1,
}

impl RenderedConfig {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    #[must_use]
    pub const fn skip_counts(&self) -> SkipCountsV1 {
        self.skips
    }
}

impl fmt::Debug for RenderedConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenderedConfig")
            .field("bytes", &"[REDACTED]")
            .field("bytes_len", &self.bytes.len())
            .field("skips", &self.skips)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteSourceFailureV1 {
    InputTooLarge,
    DecodedTooLarge,
    InvalidUtf8,
    InvalidLineEnding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubscriptionPreparationError {
    InvalidInput,
    RemoteFailure {
        source_index: usize,
        reason: RemoteSourceFailureV1,
    },
    ConversionLimit,
    NoValidNodes {
        skips: SkipCountsV1,
    },
}

impl fmt::Display for SubscriptionPreparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput => formatter.write_str("invalid subscription input"),
            Self::RemoteFailure { .. } => formatter.write_str("remote subscription is invalid"),
            Self::ConversionLimit => formatter.write_str("conversion resource limit exceeded"),
            Self::NoValidNodes { .. } => formatter.write_str("no valid nodes"),
        }
    }
}

impl std::error::Error for SubscriptionPreparationError {}

#[derive(Clone, Copy)]
pub enum SubscriptionSourceV1<'a> {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConversionRenderError {
    ConversionLimit,
    NoValidNodes { skips: SkipCountsV1 },
    Internal,
}

impl fmt::Display for ConversionRenderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConversionLimit => formatter.write_str("conversion resource limit exceeded"),
            Self::NoValidNodes { .. } => formatter.write_str("no valid nodes"),
            Self::Internal => formatter.write_str("internal conversion error"),
        }
    }
}

impl std::error::Error for ConversionRenderError {}

/// Parses one to five direct occurrences or already-loaded remote bodies in declaration order.
///
/// A direct source is exactly one occurrence: it is nonempty and has no CR/LF or outer ASCII
/// SP/HTAB. A remote source uses the frozen raw/Base64 multiline container grammar. Bad individual
/// share URIs remain local rejections as long as the request has at least one valid occurrence.
///
/// # Errors
///
/// Returns a closed, secret-safe error for invalid request/direct framing, a whole-remote failure,
/// the request-wide 10,000-occurrence limit, or an all-empty/all-rejected request.
pub fn prepare_subscription_v1(
    sources_in_declaration_order: &[SubscriptionSourceV1<'_>],
) -> Result<PreparedSubscriptionV1, SubscriptionPreparationError> {
    if sources_in_declaration_order.is_empty()
        || sources_in_declaration_order.len() > MAX_SUBSCRIPTION_SOURCES
        || sources_in_declaration_order.iter().any(|source| {
            matches!(
                source,
                SubscriptionSourceV1::Direct(value)
                    if value.is_empty()
                        || value.starts_with([' ', '\t'])
                        || value.ends_with([' ', '\t'])
                        || value.contains(['\r', '\n'])
            )
        })
    {
        return Err(SubscriptionPreparationError::InvalidInput);
    }

    let sources = sources_in_declaration_order
        .iter()
        .map(|source| match source {
            SubscriptionSourceV1::Direct(value) => SubscriptionSourceInput::Direct(value),
            SubscriptionSourceV1::Remote(body) => SubscriptionSourceInput::Remote(body),
        })
        .collect::<Vec<_>>();
    let parsed = parse_subscription_source_inputs(&sources).map_err(|error| match error {
        SubscriptionParseError::TooManySources => SubscriptionPreparationError::InvalidInput,
        SubscriptionParseError::TooManyOccurrences { .. } => {
            SubscriptionPreparationError::ConversionLimit
        }
        SubscriptionParseError::InputTooLarge { source_index } => {
            SubscriptionPreparationError::RemoteFailure {
                source_index,
                reason: RemoteSourceFailureV1::InputTooLarge,
            }
        }
        SubscriptionParseError::DecodedSourceTooLarge { source_index } => {
            SubscriptionPreparationError::RemoteFailure {
                source_index,
                reason: RemoteSourceFailureV1::DecodedTooLarge,
            }
        }
        SubscriptionParseError::InvalidUtf8 { source_index } => {
            SubscriptionPreparationError::RemoteFailure {
                source_index,
                reason: RemoteSourceFailureV1::InvalidUtf8,
            }
        }
        SubscriptionParseError::InvalidLineEnding { source_index } => {
            SubscriptionPreparationError::RemoteFailure {
                source_index,
                reason: RemoteSourceFailureV1::InvalidLineEnding,
            }
        }
    })?;
    if !parsed
        .occurrences
        .iter()
        .any(|occurrence| matches!(occurrence, NodeOccurrence::Accepted { .. }))
    {
        return Err(SubscriptionPreparationError::NoValidNodes {
            skips: SkipCountsV1::parse_only(parsed.parse_skip_count()),
        });
    }

    Ok(PreparedSubscriptionV1 { parsed })
}

/// Error already visible on a declaration prefix before a later Unique-flight failure.
///
/// An empty prefix, a successful prefix, and [`SubscriptionPreparationError::NoValidNodes`]
/// do not beat the later failure: later sources may still supply nodes.
#[must_use]
pub fn prefix_preparation_error_v1(
    prefix: &[SubscriptionSourceV1<'_>],
) -> Option<SubscriptionPreparationError> {
    if prefix.is_empty() {
        return None;
    }
    match prepare_subscription_v1(prefix) {
        Ok(_) | Err(SubscriptionPreparationError::NoValidNodes { .. }) => None,
        Err(error) => Some(error),
    }
}
