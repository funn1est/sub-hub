//! ACL4SSR INI frontend: staged prepare/render behind Unique-flight session.
//!
//! The pipeline stages live in submodules — [`ini`] (parsing and reference
//! resolution) and [`policy_compile`] (Rule Set materialization and policy
//! compilation). This root module owns the staged types and closed error
//! enums. Target dispatch and the named-node render tail live in
//! [`crate::render`].

mod ini;
mod policy_compile;

use std::fmt;

use ini::{Config, Directive, RuleSource};
use policy_compile::{RuleEntry, compile_acl4ssr_policy};

use crate::{
    OutputTarget, UniqueFlightFillV1,
    node_name::resolve_node_names,
    render::{ConversionRenderError, MAX_OUTPUT_BYTES, render_named_policy},
    subscription_source::ParsedSubscriptionSources,
    unique_fill::DecodedBudget,
};

pub(crate) struct PreparedAcl4SsrV1 {
    parsed_subscription: ParsedSubscriptionSources,
    config: Config,
    requests: Vec<Acl4SsrRuleSetRequestV1>,
}

impl PreparedAcl4SsrV1 {
    #[must_use]
    pub fn rule_set_requests(&self) -> &[Acl4SsrRuleSetRequestV1] {
        &self.requests
    }

    /// Next Rule Set occurrence URL still waiting for Outbound accept.
    #[must_use]
    pub(crate) fn next_rule_set_url(&self, pushed: usize) -> Option<&str> {
        self.requests.get(pushed).map(Acl4SsrRuleSetRequestV1::url)
    }

    /// Batch bind for crate tests. Session pushes incrementally, then
    /// [`Self::finish_rule_sets`].
    ///
    /// # Errors
    ///
    /// Returns [`Acl4SsrRenderError::RuleSetAlignment`] when `canonical_urls`
    /// is not declaration-aligned.
    #[cfg(test)]
    pub fn bind_rule_sets(
        self,
        canonical_urls: &[&str],
    ) -> Result<PreparedAcl4SsrRuleSetsV1, Acl4SsrRenderError> {
        self.finish_rule_sets(UniqueFlightFillV1::bind_remote(
            canonical_urls.iter().copied(),
        ))
    }

    /// Completes Rule Set bind once `fill` is declaration-aligned.
    ///
    /// # Errors
    ///
    /// Returns [`Acl4SsrRenderError::RuleSetAlignment`] when the pushed count
    /// is not declaration-aligned.
    pub(crate) fn finish_rule_sets(
        self,
        fill: UniqueFlightFillV1,
    ) -> Result<PreparedAcl4SsrRuleSetsV1, Acl4SsrRenderError> {
        if fill.occurrence_count() != self.requests.len() {
            return Err(Acl4SsrRenderError::RuleSetAlignment);
        }
        let flight_count = fill.flight_count();
        Ok(PreparedAcl4SsrRuleSetsV1 {
            prepared: self,
            fill,
            parsed_rule_sets: (0..flight_count).map(|_| None).collect(),
        })
    }
}

pub(crate) struct PreparedAcl4SsrRuleSetsV1 {
    prepared: PreparedAcl4SsrV1,
    fill: UniqueFlightFillV1,
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
    ) -> Result<crate::RenderedConfig, Acl4SsrRenderError> {
        if unique_rule_set_bodies.len() != self.fill.flight_count() {
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
            &self.fill,
            &mut self.parsed_rule_sets,
            occurrence_exclusive,
            false,
        )?;
        Ok(())
    }

    /// How many declaration occurrences are covered by the first `unique_loaded` flights.
    #[must_use]
    pub(crate) fn covered_occurrence_count(&self, unique_loaded: usize) -> usize {
        self.fill.covered_occurrence_count(unique_loaded)
    }

    /// Canonical URLs in declaration order.
    #[must_use]
    #[cfg(test)]
    pub(crate) fn occurrence_urls(&self) -> Vec<String> {
        self.fill.occurrence_urls()
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

    /// Grammar check plus Conversion Service decoded-byte budget for a loaded unique prefix.
    ///
    /// `already_accounted_unique` is the first-seen unique prefix already included in
    /// `already_decoded_bytes`. Fill loads Unique flights in that same first-seen order.
    ///
    /// # Errors
    ///
    /// Same closed errors as [`Self::check_loaded_prefix`], or
    /// [`Acl4SsrRenderError::ConversionLimit`] when the decoded-byte cap is crossed
    /// or saturates.
    pub fn check_loaded_prefix_with_decoded_budget(
        &mut self,
        unique_rule_set_bodies: &[&[u8]],
        already_accounted_unique: usize,
        already_decoded_bytes: usize,
        decoded_byte_cap: usize,
    ) -> Result<(), Acl4SsrRenderError> {
        let lengths = unique_rule_set_bodies
            .iter()
            .map(|body| body.len())
            .collect::<Vec<_>>();
        match self.fill.decoded_budget(
            &lengths,
            already_accounted_unique,
            already_decoded_bytes,
            decoded_byte_cap,
        ) {
            Err(()) => Err(Acl4SsrRenderError::Internal),
            Ok(DecodedBudget::Overflow) => Err(Acl4SsrRenderError::ConversionLimit),
            Ok(DecodedBudget::Within) => self.check_loaded_prefix(unique_rule_set_bodies, None),
            Ok(DecodedBudget::Crossing(occurrence)) => {
                self.check_loaded_prefix(unique_rule_set_bodies, Some(occurrence))
            }
        }
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
            .field("rule_set_occurrence_count", &self.fill.occurrence_count())
            .field("rule_set_flight_count", &self.fill.flight_count())
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

pub(crate) struct Acl4SsrRuleSetRequestV1 {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Acl4SsrPreparationError {
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
pub(crate) enum Acl4SsrRenderError {
    RuleSetAlignment,
    InvalidRuleSet,
    ConversionLimit,
    KeepPass(ConversionRenderError),
    Internal,
}

impl fmt::Display for Acl4SsrRenderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuleSetAlignment => formatter.write_str("Rule Set responses are not aligned"),
            Self::InvalidRuleSet => formatter.write_str("ACL4SSR Rule Set is invalid"),
            Self::ConversionLimit => formatter.write_str("conversion resource limit exceeded"),
            Self::KeepPass(error) => error.fmt(formatter),
            Self::Internal => formatter.write_str("internal conversion error"),
        }
    }
}

impl std::error::Error for Acl4SsrRenderError {}

impl Acl4SsrRenderError {
    /// Keep-pass closed failure. Other variants stay Rule Set stage errors.
    ///
    /// # Errors
    ///
    /// Returns `Err(self)` when this error is a Rule Set stage failure.
    #[cfg(test)]
    pub const fn keep_pass(self) -> Result<ConversionRenderError, Self> {
        match self {
            Self::KeepPass(error) => Ok(error),
            other => Err(other),
        }
    }
}

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
) -> Result<crate::RenderedConfig, Acl4SsrRenderError> {
    let occurrence_count = bound.fill.occurrence_count();
    let rules = policy_compile::consume_rule_sets(
        &bound.prepared.config,
        unique_bodies,
        &bound.fill,
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
        Ok(document) => Ok(document),
        Err(error) => Err(Acl4SsrRenderError::from(error)),
    }
}

impl From<ConversionRenderError> for Acl4SsrRenderError {
    fn from(error: ConversionRenderError) -> Self {
        Self::KeepPass(error)
    }
}

#[cfg(test)]
mod application;

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

    fn bind_urls(
        prepared: PreparedAcl4SsrV1,
        urls: &[&str],
    ) -> Result<super::PreparedAcl4SsrRuleSetsV1, Acl4SsrRenderError> {
        prepared.bind_rule_sets(urls)
    }

    #[test]
    fn canonical_url_bind_holds_one_unique_flight_table() {
        let urls = [
            "https://rules.example/first.list",
            "https://rules.example/first.list",
        ];
        assert_eq!(
            crate::UniqueFlightFillV1::bind_remote(urls).unique_urls(),
            &["https://rules.example/first.list".to_owned()]
        );
        let bound = bind_urls(two_remote_rule_sets(), &urls).unwrap();
        assert_eq!(bound.covered_occurrence_count(1), 2);
        assert_eq!(
            bound.occurrence_urls(),
            urls.iter().map(|url| (*url).to_owned()).collect::<Vec<_>>()
        );

        let distinct = [
            "https://rules.example/first.list",
            "https://rules.example/second.list",
        ];
        assert_eq!(
            crate::UniqueFlightFillV1::bind_remote(distinct)
                .unique_urls()
                .len(),
            2
        );
        let bound = bind_urls(two_remote_rule_sets(), &distinct).unwrap();
        assert_eq!(bound.covered_occurrence_count(1), 1);
        assert_eq!(
            bind_urls(two_remote_rule_sets(), &[]).unwrap_err(),
            Acl4SsrRenderError::RuleSetAlignment
        );
    }

    #[test]
    fn keep_pass_unwraps_the_closed_keep_pass_set() {
        use crate::{ConversionRenderError, SkipCountsV1};

        let skips = SkipCountsV1::default();
        assert_eq!(
            Acl4SsrRenderError::from(ConversionRenderError::NoValidNodes { skips }).keep_pass(),
            Ok(ConversionRenderError::NoValidNodes { skips })
        );
        assert_eq!(
            Acl4SsrRenderError::from(ConversionRenderError::ConversionLimit).keep_pass(),
            Ok(ConversionRenderError::ConversionLimit)
        );
        assert_eq!(
            Acl4SsrRenderError::from(ConversionRenderError::Internal).keep_pass(),
            Ok(ConversionRenderError::Internal)
        );
        assert_eq!(
            Acl4SsrRenderError::ConversionLimit.keep_pass(),
            Err(Acl4SsrRenderError::ConversionLimit)
        );
        assert_eq!(
            Acl4SsrRenderError::Internal.keep_pass(),
            Err(Acl4SsrRenderError::Internal)
        );
    }

    #[test]
    fn unique_flight_fill_counts_first_seen_before_rule_set_finish() {
        let prepared = two_remote_rule_sets();
        assert_eq!(
            prepared.next_rule_set_url(0),
            Some("https://rules.example/first.list")
        );
        assert_eq!(
            prepared.next_rule_set_url(1),
            Some("https://rules.example/second.list")
        );
        assert_eq!(prepared.next_rule_set_url(2), None);
        let mut fill = crate::UniqueFlightFillV1::empty();
        let first = "https://rules.example/first.list";
        assert_eq!(fill.unique_count_if_push(first), 1);
        assert_eq!(fill.push_remote(first), 1);
        assert_eq!(fill.unique_count_if_push(first), 1);
        assert_eq!(fill.push_remote(first), 1);
        let bound = prepared.finish_rule_sets(fill).unwrap();
        assert_eq!(bound.covered_occurrence_count(1), 2);
    }
}
