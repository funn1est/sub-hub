use std::fmt;

use crate::{
    MAX_SUBSCRIPTION_SOURCES, OutputTarget,
    flight::UniqueFlightsV1,
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
    /// deliberately retained; Unique-flight accounting keeps first-seen sizes only.
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
                let (bytes, skips, omitted_url_regex) = output.into_rendered();
                Ok(RenderedConfig {
                    bytes,
                    skips,
                    omitted_url_regex,
                })
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
    omitted_url_regex: u8,
}

impl RenderedConfig {
    pub(crate) const fn from_parts(
        bytes: Vec<u8>,
        skips: SkipCountsV1,
        omitted_url_regex: u8,
    ) -> Self {
        Self {
            bytes,
            skips,
            omitted_url_regex,
        }
    }

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

    /// URL-REGEX matchers omitted by Keep-pass. No remote config is always 0.
    #[must_use]
    pub const fn omitted_url_regex(&self) -> u8 {
        self.omitted_url_regex
    }
}

impl fmt::Debug for RenderedConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenderedConfig")
            .field("bytes", &"[REDACTED]")
            .field("bytes_len", &self.bytes.len())
            .field("skips", &self.skips)
            .field("omitted_url_regex", &self.omitted_url_regex)
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

impl UniqueFlightsV1 {
    /// Declaration-order Direct/Remote plan from unique bodies in first-seen order.
    #[must_use]
    pub(crate) fn subscription_sources<'a>(
        &self,
        sources: &'a [String],
        unique_bodies: &'a [Vec<u8>],
    ) -> Option<Vec<SubscriptionSourceV1<'a>>> {
        if sources.len() != self.occurrence_count() || unique_bodies.len() != self.flight_count() {
            return None;
        }
        (0..sources.len())
            .map(|occurrence| match self.flight_of(occurrence) {
                None => Some(SubscriptionSourceV1::Direct(sources[occurrence].as_str())),
                Some(index) => unique_bodies
                    .get(index)
                    .map(|body| SubscriptionSourceV1::Remote(body.as_slice())),
            })
            .collect()
    }

    /// Unique bodies in first-seen order, zipped back onto declaration sources and prepared.
    ///
    /// `None` is Unique-flight alignment failure (caller bug).
    #[must_use]
    pub fn prepare_subscription(
        &self,
        sources: &[String],
        unique_bodies: &[Vec<u8>],
    ) -> Option<Result<PreparedSubscriptionV1, SubscriptionPreparationError>> {
        Some(prepare_subscription_v1(
            &self.subscription_sources(sources, unique_bodies)?,
        ))
    }

    /// First-occurrence decoded sizes to account, as `(unique_index, bytes)`.
    #[must_use]
    pub fn unique_decoded_accounts(
        &self,
        prepared: &PreparedSubscriptionV1,
    ) -> Option<Vec<(usize, usize)>> {
        self.accounts_for_occurrence_decoded(prepared.remote_decoded_bytes_by_source())
    }

    /// Error already visible on the declaration prefix before `failed_unique_index`.
    pub fn prefix_error_before_unique_failure(
        &self,
        sources: &[String],
        loaded: &[Option<impl AsRef<[u8]>>],
        failed_unique_index: usize,
    ) -> Option<Option<SubscriptionPreparationError>> {
        let failed_source_index = self.first_occurrence_of_flight(failed_unique_index)?;
        if failed_source_index == 0 {
            return Some(None);
        }
        if failed_source_index > sources.len() {
            return None;
        }
        let mut source_plan = Vec::with_capacity(failed_source_index);
        for (occurrence, source) in sources.iter().enumerate().take(failed_source_index) {
            match self.flight_of(occurrence) {
                None => {
                    source_plan.push(SubscriptionSourceV1::Direct(source.as_str()));
                }
                Some(unique_index) => {
                    let body = loaded.get(unique_index)?.as_ref()?.as_ref();
                    source_plan.push(SubscriptionSourceV1::Remote(body));
                }
            }
        }
        Some(prefix_preparation_error_v1(&source_plan))
    }
}
