//! ACL4SSR INI frontend: public prepare/render façade.
//!
//! The pipeline stages live in submodules — [`ini`] (parsing and reference
//! resolution) and [`policy_compile`] (Rule Set materialization and policy
//! compilation). This root module owns the public staged types and closed
//! error enums. Target dispatch and the named-node render tail live in
//! [`crate::render`].

mod ini;
mod policy_compile;

use std::fmt;

use ini::{Config, Directive, RuleSource};
use policy_compile::{RuleEntry, compile_acl4ssr_policy};

use crate::{
    OutputTarget, UniqueFlightsV1,
    node_name::resolve_node_names,
    render::{MAX_OUTPUT_BYTES, NamedPolicyError, render_named_policy},
    skip::SkipCountsV1,
    subscription_source::ParsedSubscriptionSources,
};

pub struct PreparedAcl4SsrV1 {
    parsed_subscription: ParsedSubscriptionSources,
    config: Config,
    requests: Vec<Acl4SsrRuleSetRequestV1>,
}

impl PreparedAcl4SsrV1 {
    #[must_use]
    pub fn rule_set_requests(&self) -> &[Acl4SsrRuleSetRequestV1] {
        &self.requests
    }

    /// Binds Rule Set occurrences by first-seen canonical URL identity.
    ///
    /// `canonical_urls` is declaration-aligned with [`Self::rule_set_requests`]. Conversion owns
    /// the unique-flight table; the host fetches unique URLs and returns bodies in first-seen
    /// order.
    ///
    /// # Errors
    ///
    /// Returns a closed alignment error when the URL list is not declaration-aligned.
    pub fn bind_canonical_urls_v1(
        self,
        canonical_urls: &[String],
    ) -> Result<PreparedAcl4SsrRuleSetsV1, Acl4SsrRenderError> {
        if canonical_urls.len() != self.requests.len() {
            return Err(Acl4SsrRenderError::RuleSetAlignment);
        }
        let flights = UniqueFlightsV1::bind(canonical_urls);
        let flight_count = flights.flight_count();
        Ok(PreparedAcl4SsrRuleSetsV1 {
            prepared: self,
            flights,
            parsed_rule_sets: (0..flight_count).map(|_| None).collect(),
        })
    }
}

pub struct PreparedAcl4SsrRuleSetsV1 {
    prepared: PreparedAcl4SsrV1,
    flights: UniqueFlightsV1,
    parsed_rule_sets: Vec<Option<Vec<RuleEntry>>>,
}

impl PreparedAcl4SsrRuleSetsV1 {
    /// Consumes the bound stages and renders the document for `target`.
    ///
    /// `unique_rule_set_bodies` must contain one body per first-seen broker flight. Parsed typed
    /// entries are cached per flight and replayed at every declaration occurrence.
    ///
    /// # Errors
    ///
    /// Returns a closed error for alignment, Rule Set grammar/capability, resource-limit, naming,
    /// or serialization failures. No partial document is returned.
    pub fn render_v1(
        self,
        target: OutputTarget,
        unique_rule_set_bodies: &[&[u8]],
    ) -> Result<Acl4SsrOutputV1, Acl4SsrRenderError> {
        if unique_rule_set_bodies.len() != self.flights.flight_count() {
            return Err(Acl4SsrRenderError::RuleSetAlignment);
        }
        render(self, unique_rule_set_bodies, target)
    }

    fn validate_occurrence_prefix_v1(
        &mut self,
        unique_rule_set_bodies: &[&[u8]],
        occurrence_exclusive: usize,
    ) -> Result<(), Acl4SsrRenderError> {
        policy_compile::consume_rule_sets(
            &self.prepared.config,
            unique_rule_set_bodies,
            &self.flights,
            &mut self.parsed_rule_sets,
            occurrence_exclusive,
            false,
        )?;
        Ok(())
    }

    /// How many declaration occurrences are covered by the first `unique_loaded` flights.
    #[must_use]
    pub fn covered_occurrence_count(&self, unique_loaded: usize) -> usize {
        self.flights.covered_occurrence_count(unique_loaded)
    }

    /// Canonical URLs in declaration order.
    #[must_use]
    pub fn occurrence_urls(&self) -> Vec<String> {
        self.flights.occurrence_urls()
    }

    /// First declaration occurrence of a unique Rule Set flight.
    #[must_use]
    pub fn first_occurrence_of_flight(&self, flight: usize) -> Option<usize> {
        self.flights.first_occurrence_of_flight(flight)
    }

    /// Unique-flight table bound for these Rule Set occurrences.
    #[must_use]
    pub fn flights(&self) -> &UniqueFlightsV1 {
        &self.flights
    }

    /// First-seen unique canonical URLs, aligned with unique Rule Set bodies.
    #[must_use]
    pub fn unique_canonical_urls(&self) -> &[String] {
        self.flights.unique_urls()
    }

    /// Grammar and budget check for a loaded unique prefix.
    ///
    /// When `decoded_crossing_occurrence` is `Some`, the host has already hit its
    /// decoded-byte cap at that declaration; this method still reports an earlier
    /// Rule Set grammar error if one exists in the prefix.
    ///
    /// # Errors
    ///
    /// Same closed Rule Set grammar and budget errors as final rendering would
    /// observe in this prefix, or [`Acl4SsrRenderError::ConversionLimit`] when
    /// the host reported a decoded-byte crossing.
    pub fn check_loaded_prefix(
        &mut self,
        unique_rule_set_bodies: &[&[u8]],
        decoded_crossing_occurrence: Option<usize>,
    ) -> Result<(), Acl4SsrRenderError> {
        if let Some(crossing) = decoded_crossing_occurrence {
            self.validate_occurrence_prefix_v1(unique_rule_set_bodies, crossing)?;
            return Err(Acl4SsrRenderError::ConversionLimit);
        }
        self.validate_loaded_unique_prefix_v1(unique_rule_set_bodies)
    }

    fn validate_loaded_unique_prefix_v1(
        &mut self,
        unique_rule_set_bodies: &[&[u8]],
    ) -> Result<(), Acl4SsrRenderError> {
        let occurrence_exclusive = self.covered_occurrence_count(unique_rule_set_bodies.len());
        self.validate_occurrence_prefix_v1(unique_rule_set_bodies, occurrence_exclusive)
    }
}

impl fmt::Debug for PreparedAcl4SsrRuleSetsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedAcl4SsrRuleSetsV1")
            .field("prepared", &"[REDACTED]")
            .field(
                "rule_set_occurrence_count",
                &self.flights.occurrence_count(),
            )
            .field("rule_set_flight_count", &self.flights.flight_count())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for PreparedAcl4SsrV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedAcl4SsrV1")
            .field("parsed_subscription", &"[REDACTED]")
            .field("config", &"[REDACTED]")
            .field("rule_set_request_count", &self.requests.len())
            .finish_non_exhaustive()
    }
}

pub struct Acl4SsrRuleSetRequestV1 {
    url: String,
}

impl Acl4SsrRuleSetRequestV1 {
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }
}

impl fmt::Debug for Acl4SsrRuleSetRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Acl4SsrRuleSetRequestV1")
            .field("url", &"[REDACTED]")
            .finish()
    }
}

pub struct Acl4SsrOutputV1 {
    bytes: Vec<u8>,
    report: Acl4SsrConversionReportV1,
    skips: SkipCountsV1,
}

impl Acl4SsrOutputV1 {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    #[must_use]
    pub const fn report(&self) -> &Acl4SsrConversionReportV1 {
        &self.report
    }

    #[must_use]
    pub const fn skip_counts(&self) -> SkipCountsV1 {
        self.skips
    }
}

impl fmt::Debug for Acl4SsrOutputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Acl4SsrOutputV1")
            .field("bytes", &"[REDACTED]")
            .field("bytes_len", &self.bytes.len())
            .field("report", &self.report)
            .field("skips", &self.skips)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Acl4SsrConversionReportV1 {
    omitted_url_regex: u8,
    empty_groups: u8,
    ignored_legacy_probe_hints: u8,
}

impl Acl4SsrConversionReportV1 {
    #[must_use]
    pub const fn omitted_url_regex_count(&self) -> u8 {
        self.omitted_url_regex
    }

    #[must_use]
    pub const fn empty_group_count(&self) -> u8 {
        self.empty_groups
    }

    #[must_use]
    pub const fn ignored_legacy_probe_hint_count(&self) -> u8 {
        self.ignored_legacy_probe_hints
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Acl4SsrPreparationError {
    InvalidConfig,
    ConversionLimit,
    Internal,
}

impl fmt::Display for Acl4SsrPreparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfig => "ACL4SSR config is invalid",
            Self::ConversionLimit => "conversion resource limit exceeded",
            Self::Internal => "internal conversion error",
        })
    }
}

impl std::error::Error for Acl4SsrPreparationError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Acl4SsrRenderError {
    RuleSetAlignment,
    InvalidRuleSet,
    ConversionLimit,
    NoValidNodes { skips: SkipCountsV1 },
    Internal,
}

impl fmt::Display for Acl4SsrRenderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RuleSetAlignment => "Rule Set responses are not aligned",
            Self::InvalidRuleSet => "ACL4SSR Rule Set is invalid",
            Self::ConversionLimit => "conversion resource limit exceeded",
            Self::NoValidNodes { .. } => "no valid nodes",
            Self::Internal => "internal conversion error",
        })
    }
}

impl std::error::Error for Acl4SsrRenderError {}

pub(crate) fn prepare(
    parsed_subscription: ParsedSubscriptionSources,
    bytes: &[u8],
) -> Result<PreparedAcl4SsrV1, Acl4SsrPreparationError> {
    let config = Config::parse(bytes)?;
    let requests = config
        .directives
        .iter()
        .filter_map(|directive| match directive {
            Directive::Ruleset {
                source: RuleSource::Remote(url),
                ..
            } => Some(Acl4SsrRuleSetRequestV1 {
                url: url.declared.clone(),
            }),
            _ => None,
        })
        .collect();
    Ok(PreparedAcl4SsrV1 {
        parsed_subscription,
        config,
        requests,
    })
}

fn render(
    mut bound: PreparedAcl4SsrRuleSetsV1,
    unique_bodies: &[&[u8]],
    target: OutputTarget,
) -> Result<Acl4SsrOutputV1, Acl4SsrRenderError> {
    let occurrence_count = bound.flights.occurrence_count();
    let rules = policy_compile::consume_rule_sets(
        &bound.prepared.config,
        unique_bodies,
        &bound.flights,
        &mut bound.parsed_rule_sets,
        occurrence_count,
        true,
    )?;
    let prepared = bound.prepared;

    let group_names = prepared
        .config
        .groups
        .iter()
        .map(|group| group.name.as_str())
        .collect::<Vec<_>>();
    let named = resolve_node_names(prepared.parsed_subscription, &group_names)
        .map_err(|_| Acl4SsrRenderError::Internal)?;
    let nodes = crate::render::accepted_nodes(&named);
    let node_names = nodes
        .iter()
        .map(|node| node.name().as_str())
        .collect::<Vec<_>>();

    let policy = compile_acl4ssr_policy(&prepared.config.groups, &node_names, rules)?;
    match render_named_policy(&named, &policy, target, MAX_OUTPUT_BYTES) {
        Ok(document) => Ok(Acl4SsrOutputV1 {
            bytes: document.bytes,
            report: Acl4SsrConversionReportV1 {
                omitted_url_regex: document.omitted_url_regex,
                empty_groups: policy.report().empty_groups,
                ignored_legacy_probe_hints: policy.report().ignored_legacy_probe_hints,
            },
            skips: document.skips,
        }),
        Err(error) => Err(Acl4SsrRenderError::from(error)),
    }
}

impl From<NamedPolicyError> for Acl4SsrRenderError {
    fn from(error: NamedPolicyError) -> Self {
        match error {
            NamedPolicyError::NoValidNodes { skips } => Self::NoValidNodes { skips },
            NamedPolicyError::OutputTooLarge { .. } => Self::ConversionLimit,
            NamedPolicyError::Internal => Self::Internal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Acl4SsrRenderError, PreparedAcl4SsrV1};
    use crate::{SubscriptionSourceV1, prepare_subscription_v1};

    const VALID: &str = "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#Alpha";

    fn two_remote_rule_sets() -> PreparedAcl4SsrV1 {
        let config = concat!(
            "[custom]\n",
            "ruleset=PROXY,https://rules.example/first.list\n",
            "ruleset=PROXY,https://rules.example/second.list\n",
            "enable_rule_generator=true\n",
            "custom_proxy_group=PROXY`select`.*\n",
            "ruleset=PROXY,[]FINAL\n",
            "overwrite_original_rules=true\n",
        );
        prepare_subscription_v1(&[SubscriptionSourceV1::Direct(VALID)])
            .unwrap()
            .prepare_acl4ssr_config_v1(config.as_bytes())
            .unwrap()
    }

    #[test]
    fn canonical_url_bind_holds_one_unique_flight_table() {
        let urls = [
            "https://rules.example/first.list".to_owned(),
            "https://rules.example/first.list".to_owned(),
        ];
        let bound = two_remote_rule_sets()
            .bind_canonical_urls_v1(&urls)
            .unwrap();
        assert_eq!(bound.unique_canonical_urls().len(), 1);
        assert_eq!(bound.covered_occurrence_count(1), 2);
        assert_eq!(bound.occurrence_urls().as_slice(), urls.as_slice());

        let distinct = [
            "https://rules.example/first.list".to_owned(),
            "https://rules.example/second.list".to_owned(),
        ];
        let bound = two_remote_rule_sets()
            .bind_canonical_urls_v1(&distinct)
            .unwrap();
        assert_eq!(bound.unique_canonical_urls().len(), 2);
        assert_eq!(bound.covered_occurrence_count(1), 1);
        assert_eq!(
            two_remote_rule_sets()
                .bind_canonical_urls_v1(&[])
                .unwrap_err(),
            Acl4SsrRenderError::RuleSetAlignment
        );
    }
}
