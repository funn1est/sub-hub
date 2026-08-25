//! Subscription prepare: Direct and Remote sources share one Keep-pass entry.
//!
//! Unique-flight fill consumes [`PreparedSubscriptionV1`]. Prefix adjudication
//! for a later unique failure lives here so the Unique-flight table can zip
//! bodies without owning parse grammar.

use std::fmt;

use crate::{
    OutputTarget,
    render::{ConversionRenderError, RenderedConfig, render_builtin_v1},
    skip::SkipCountsV1,
    subscription_source::{
        NodeOccurrence, ParsedSubscriptionSources, SubscriptionParseError,
        parse_subscription_source_inputs,
    },
};

pub(crate) use crate::subscription_source::SubscriptionSourceV1;

pub(crate) struct PreparedSubscriptionV1 {
    parsed: ParsedSubscriptionSources,
}

impl PreparedSubscriptionV1 {
    /// Names, compiles builtin policy, and renders with an explicit byte limit.
    #[cfg(test)]
    pub(crate) fn render_builtin_with_limit(
        self,
        render: crate::render::RenderFromPolicyFn,
        limit_bytes: usize,
    ) -> Result<RenderedConfig, ConversionRenderError> {
        crate::render::render_builtin_with_limit(self.parsed, render, limit_bytes)
    }

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
        render_builtin_v1(self.parsed, target)
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RemoteSourceFailureV1 {
    InputTooLarge,
    DecodedTooLarge,
    InvalidUtf8,
    InvalidLineEnding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SubscriptionPreparationError {
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

/// Parses one or more direct occurrences or already-loaded remote bodies in declaration order.
///
/// A direct source is exactly one occurrence: it is nonempty and has no CR/LF or outer ASCII
/// SP/HTAB. A remote source uses the frozen raw/Base64 multiline container grammar. Bad individual
/// share URIs remain local rejections as long as the request has at least one valid occurrence.
///
/// # Errors
///
/// Returns a closed, secret-safe error for invalid request/direct framing, a whole-remote failure,
/// the request-wide 10,000-occurrence limit, or an all-empty/all-rejected request.
pub(crate) fn prepare_subscription_v1(
    sources_in_declaration_order: &[SubscriptionSourceV1<'_>],
) -> Result<PreparedSubscriptionV1, SubscriptionPreparationError> {
    if sources_in_declaration_order.is_empty()
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

    let parsed = parse_subscription_source_inputs(sources_in_declaration_order).map_err(
        |error| match error {
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
        },
    )?;
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

#[cfg(test)]
fn test_source(body: &[u8]) -> SubscriptionSourceV1<'_> {
    match std::str::from_utf8(body) {
        Ok(text)
            if !text.is_empty()
                && !text.starts_with([' ', '\t'])
                && !text.ends_with([' ', '\t'])
                && !text.contains(['\r', '\n']) =>
        {
            SubscriptionSourceV1::Direct(text)
        }
        _ => SubscriptionSourceV1::Remote(body),
    }
}

#[cfg(test)]
pub(crate) fn prepare_remote_sources(
    bodies: &[&[u8]],
) -> Result<PreparedSubscriptionV1, SubscriptionPreparationError> {
    let sources: Vec<_> = bodies.iter().copied().map(test_source).collect();
    prepare_subscription_v1(&sources)
}

#[cfg(test)]
pub(crate) fn render_remote_builtin(
    target: OutputTarget,
    bodies: &[&[u8]],
) -> Result<RenderedConfig, ConversionRenderError> {
    match prepare_remote_sources(bodies) {
        Ok(prepared) => prepared.render_builtin_v1(target),
        Err(SubscriptionPreparationError::NoValidNodes { skips }) => {
            Err(ConversionRenderError::NoValidNodes { skips })
        }
        Err(SubscriptionPreparationError::ConversionLimit) => {
            Err(ConversionRenderError::ConversionLimit)
        }
        Err(error) => panic!("subscription sources prepare: {error}"),
    }
}

#[cfg(test)]
pub(crate) fn render_acl4ssr_target(
    target: OutputTarget,
    direct: &str,
    config: &[u8],
    unique_rule_set_bodies: &[&[u8]],
) -> Result<crate::RenderedConfig, crate::Acl4SsrRenderError> {
    let prepared = prepare_subscription_v1(&[SubscriptionSourceV1::Direct(direct)])
        .expect("direct")
        .prepare_acl4ssr_config_v1(config)
        .expect("acl4ssr config");
    let urls = prepared
        .rule_set_requests()
        .iter()
        .map(|request| request.url().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(urls.len(), unique_rule_set_bodies.len());
    let refs = urls.iter().map(String::as_str).collect::<Vec<_>>();
    prepared
        .bind_rule_sets(&refs)
        .expect("aligned")
        .render_v1(target, unique_rule_set_bodies)
}

/// Error already visible on a declaration prefix before a later Unique-flight failure.
///
/// An empty prefix, a successful prefix, and [`SubscriptionPreparationError::NoValidNodes`]
/// do not beat the later failure: later sources may still supply nodes.
#[must_use]
pub(crate) fn prefix_preparation_error_v1(
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

#[cfg(test)]
mod tests {
    use super::{
        RemoteSourceFailureV1, SubscriptionPreparationError, SubscriptionSourceV1,
        prepare_subscription_v1,
    };

    #[test]
    fn prepared_debug_redacts_direct_source_secrets() {
        const UUID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
        const HOST: &str = "private-canary.example";
        const NAME: &str = "secret-canary-name";
        let source = format!("vless://{UUID}@{HOST}:443#{NAME}");
        let prepared = prepare_subscription_v1(&[SubscriptionSourceV1::Direct(&source)])
            .expect("valid direct subscription");
        let debug = format!("{prepared:?}");
        for secret in [UUID, HOST, NAME] {
            assert!(!debug.contains(secret), "{debug}");
        }
    }

    #[test]
    fn remote_decoded_byte_accounting_is_aligned_with_source_order() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};

        const ALPHA: &str = "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha";
        const BETA: &str = "vless://fedcba98-7654-3210-fedc-ba9876543210@example.net:8443#Beta";
        let encoded = STANDARD.encode(BETA);
        let prepared = prepare_subscription_v1(&[
            SubscriptionSourceV1::Direct(ALPHA),
            SubscriptionSourceV1::Remote(encoded.as_bytes()),
            SubscriptionSourceV1::Remote(ALPHA.as_bytes()),
            SubscriptionSourceV1::Remote(ALPHA.as_bytes()),
        ])
        .expect("valid mixed sources");

        assert_eq!(
            prepared.remote_decoded_bytes_by_source(),
            &[None, Some(BETA.len()), Some(ALPHA.len()), Some(ALPHA.len())]
        );
    }

    #[test]
    fn six_direct_sources_prepare_without_a_source_count_cap() {
        const ALPHA: &str = "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha";
        let sources = [SubscriptionSourceV1::Direct(ALPHA); 6];
        let prepared = prepare_subscription_v1(&sources).expect("six direct sources");
        assert_eq!(prepared.remote_decoded_bytes_by_source(), &[None; 6]);
    }

    #[test]
    fn whole_remote_failures_retain_a_closed_reason_and_source_ordinal() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};

        const ALPHA: &str = "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha";
        for (body, reason) in [
            (vec![0xff], RemoteSourceFailureV1::InvalidUtf8),
            (
                b"trojan://example\rnext".to_vec(),
                RemoteSourceFailureV1::InvalidLineEnding,
            ),
            (vec![b'a'; 2_796_207], RemoteSourceFailureV1::InputTooLarge),
        ] {
            assert_eq!(
                prepare_subscription_v1(&[
                    SubscriptionSourceV1::Direct(ALPHA),
                    SubscriptionSourceV1::Remote(&body),
                ])
                .unwrap_err(),
                SubscriptionPreparationError::RemoteFailure {
                    source_index: 1,
                    reason,
                }
            );
        }

        let decoded_too_large = vec![b'a'; 2 * 1024 * 1024 + 1];
        let encoded_too_large = STANDARD.encode(decoded_too_large);
        assert_eq!(
            prepare_subscription_v1(&[SubscriptionSourceV1::Remote(encoded_too_large.as_bytes())])
                .unwrap_err(),
            SubscriptionPreparationError::RemoteFailure {
                source_index: 0,
                reason: RemoteSourceFailureV1::DecodedTooLarge,
            }
        );
    }

    #[test]
    fn preparation_errors_are_secret_safe() {
        let error =
            prepare_subscription_v1(&[SubscriptionSourceV1::Direct(" secret-canary.example ")])
                .unwrap_err();
        assert_eq!(error, SubscriptionPreparationError::InvalidInput);
        for formatted in [format!("{error:?}"), error.to_string()] {
            assert!(!formatted.contains("secret-canary"));
        }
    }
}
