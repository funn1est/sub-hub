//! ACL4SSR INI frontend: public prepare/render façade.
//!
//! The pipeline stages live in submodules — [`ini`] (parsing and reference
//! resolution), [`fingerprint`] (config hashing and pinned profile policies),
//! and [`policy_compile`] (Rule Set materialization and policy compilation).
//! This root module owns the public staged types, the closed error enums, and
//! per-target render dispatch.

mod fingerprint;
mod ini;
mod policy_compile;
#[cfg(test)]
mod reference_decoder;
mod sha256;

use std::fmt;

#[cfg(test)]
use fingerprint::{OmittedEvidenceEntry, encode_config_fingerprint, encode_omitted_evidence};
use fingerprint::{
    ProfileKind, hash_config_fingerprint, lookup_profile, validate_target_capability,
};
#[cfg(test)]
use ini::TargetRef;
use ini::{Config, Directive, GroupMember, RuleSource};
use policy_compile::{
    ParsedRuleSetFlights, RuleEntry, compile_acl4ssr_policy, increment_rule_count,
    materialize_rules,
};

use crate::{
    egern::render_egern_from_policy_v1,
    loon::render_loon_from_policy_v1,
    mihomo::render_mihomo_from_policy_v1,
    node_name::{NamedNodeOccurrence, resolve_node_names},
    policy::CompiledPolicyV1,
    quanx::render_quanx_from_policy_v1,
    render::{AdapterRenderError, MAX_OUTPUT_BYTES, RenderFromPolicyFn},
    singbox::render_singbox_from_policy_v1,
    subscription_source::ParsedSubscriptionSources,
};

const MAX_REGEX_EVALUATIONS: usize = 2_000_000;

pub struct PreparedAcl4SsrV1 {
    parsed_subscription: ParsedSubscriptionSources,
    config: Config,
    fingerprint: [u8; 32],
    profile: Option<ProfileKind>,
    requests: Vec<Acl4SsrRuleSetRequestV1>,
}

impl PreparedAcl4SsrV1 {
    #[must_use]
    pub fn rule_set_requests(&self) -> &[Acl4SsrRuleSetRequestV1] {
        &self.requests
    }

    /// Binds the ordered request occurrences to the broker's first-seen unique flights.
    ///
    /// `flight_by_occurrence` must contain one index for every request returned by
    /// [`Self::rule_set_requests`]. Indices are dense and assigned in first-occurrence order, so
    /// `[0, 0, 1]` is valid while `[1]` and `[0, 2]` are not. The resulting stage keeps transport
    /// identity opaque while ensuring each single-flighted body is parsed at most once.
    ///
    /// # Errors
    ///
    /// Returns a closed alignment or resource-limit error. No URLs or mapping values are retained
    /// by errors or debug output.
    pub fn bind_rule_set_flights_v1(
        self,
        flight_by_occurrence: &[usize],
    ) -> Result<PreparedAcl4SsrRuleSetsV1, Acl4SsrRenderError> {
        if flight_by_occurrence.len() != self.requests.len() {
            return Err(Acl4SsrRenderError::RuleSetAlignment);
        }
        let mut flight_count = 0_usize;
        for &flight in flight_by_occurrence {
            if flight > flight_count {
                return Err(Acl4SsrRenderError::RuleSetAlignment);
            }
            if flight == flight_count {
                flight_count = flight_count
                    .checked_add(1)
                    .ok_or(Acl4SsrRenderError::ConversionLimit)?;
            }
        }
        Ok(PreparedAcl4SsrRuleSetsV1 {
            prepared: self,
            flight_by_occurrence: flight_by_occurrence.to_vec(),
            flight_count,
            parsed_rule_sets: (0..flight_count).map(|_| None).collect(),
        })
    }
}

pub struct PreparedAcl4SsrRuleSetsV1 {
    prepared: PreparedAcl4SsrV1,
    flight_by_occurrence: Vec<usize>,
    flight_count: usize,
    parsed_rule_sets: Vec<Option<Vec<RuleEntry>>>,
}

impl PreparedAcl4SsrRuleSetsV1 {
    /// Consumes the bound stages and renders a Mihomo v1 document.
    ///
    /// `unique_rule_set_bodies` must contain one body per first-seen broker flight. Parsed typed
    /// entries are cached per flight and replayed at every declaration occurrence.
    ///
    /// # Errors
    ///
    /// Returns a closed error for alignment, Rule Set grammar/capability, resource-limit, naming,
    /// or serialization failures. No partial document is returned.
    pub fn render_mihomo_v1(
        self,
        unique_rule_set_bodies: &[&[u8]],
    ) -> Result<Acl4SsrOutputV1, Acl4SsrRenderError> {
        if unique_rule_set_bodies.len() != self.flight_count {
            return Err(Acl4SsrRenderError::RuleSetAlignment);
        }
        render(self, unique_rule_set_bodies, OutputFormat::Mihomo)
    }

    /// Consumes the bound stages and renders a Quantumult X document.
    ///
    /// # Errors
    ///
    /// Returns a closed error for alignment, Rule Set grammar/capability, resource-limit, naming,
    /// or serialization failures. No partial document is returned.
    pub fn render_quanx_v1(
        self,
        unique_rule_set_bodies: &[&[u8]],
    ) -> Result<Acl4SsrOutputV1, Acl4SsrRenderError> {
        if unique_rule_set_bodies.len() != self.flight_count {
            return Err(Acl4SsrRenderError::RuleSetAlignment);
        }
        render(self, unique_rule_set_bodies, OutputFormat::Quanx)
    }

    /// Consumes the bound stages and renders a sing-box document.
    ///
    /// # Errors
    ///
    /// Returns a closed error for alignment, Rule Set grammar/capability, resource-limit, naming,
    /// or serialization failures. No partial document is returned.
    pub fn render_singbox_v1(
        self,
        unique_rule_set_bodies: &[&[u8]],
    ) -> Result<Acl4SsrOutputV1, Acl4SsrRenderError> {
        if unique_rule_set_bodies.len() != self.flight_count {
            return Err(Acl4SsrRenderError::RuleSetAlignment);
        }
        render(self, unique_rule_set_bodies, OutputFormat::Singbox)
    }

    /// Consumes the bound stages and renders a Loon document.
    ///
    /// # Errors
    ///
    /// Returns a closed error for alignment, Rule Set grammar/capability, resource-limit, naming,
    /// or serialization failures. No partial document is returned.
    pub fn render_loon_v1(
        self,
        unique_rule_set_bodies: &[&[u8]],
    ) -> Result<Acl4SsrOutputV1, Acl4SsrRenderError> {
        if unique_rule_set_bodies.len() != self.flight_count {
            return Err(Acl4SsrRenderError::RuleSetAlignment);
        }
        render(self, unique_rule_set_bodies, OutputFormat::Loon)
    }

    /// Consumes the bound stages and renders an Egern document.
    ///
    /// # Errors
    ///
    /// Returns a closed error for alignment, Rule Set grammar/capability, resource-limit, naming,
    /// or serialization failures. No partial document is returned.
    pub fn render_egern_v1(
        self,
        unique_rule_set_bodies: &[&[u8]],
    ) -> Result<Acl4SsrOutputV1, Acl4SsrRenderError> {
        if unique_rule_set_bodies.len() != self.flight_count {
            return Err(Acl4SsrRenderError::RuleSetAlignment);
        }
        render(self, unique_rule_set_bodies, OutputFormat::Egern)
    }

    /// Validates a successfully loaded prefix of the ordered Rule Set occurrence plan.
    ///
    /// This is an error-arbitration seam for an orchestrator that must compare an earlier loaded
    /// body error with a later transport failure. `occurrence_exclusive` is the first remote
    /// declaration not yet available; inline rules before that declaration remain part of the
    /// prefix. It performs no I/O, naming, expansion, evidence completion, or rendering.
    ///
    /// # Errors
    ///
    /// Returns the same closed Rule Set grammar, generic capability, and resource-limit errors that
    /// final rendering would observe within this prefix.
    pub fn validate_occurrence_prefix_v1(
        &mut self,
        unique_rule_set_bodies: &[&[u8]],
        occurrence_exclusive: usize,
    ) -> Result<(), Acl4SsrRenderError> {
        if occurrence_exclusive > self.flight_by_occurrence.len()
            || unique_rule_set_bodies.len() > self.flight_count
        {
            return Err(Acl4SsrRenderError::RuleSetAlignment);
        }
        let mut parsed =
            ParsedRuleSetFlights::new(unique_rule_set_bodies, &mut self.parsed_rule_sets);
        let mut total_rule_count = 0;
        let mut remote_index = 0;
        for directive in &self.prepared.config.directives {
            let Directive::Ruleset { source, .. } = directive else {
                continue;
            };
            match source {
                RuleSource::Remote(_) => {
                    if remote_index == occurrence_exclusive {
                        return Ok(());
                    }
                    let flight = *self
                        .flight_by_occurrence
                        .get(remote_index)
                        .ok_or(Acl4SsrRenderError::RuleSetAlignment)?;
                    let entries = parsed.entries(flight, &mut total_rule_count)?;
                    if self.prepared.profile.is_none()
                        && entries
                            .iter()
                            .any(|entry| matches!(entry, RuleEntry::UrlRegex(_)))
                    {
                        return Err(Acl4SsrRenderError::UnsupportedRule);
                    }
                    remote_index += 1;
                }
                RuleSource::GeoIpCn | RuleSource::Final => {
                    increment_rule_count(&mut total_rule_count)?;
                }
            }
        }
        Ok(())
    }
}

impl fmt::Debug for PreparedAcl4SsrRuleSetsV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedAcl4SsrRuleSetsV1")
            .field("prepared", &"[REDACTED]")
            .field(
                "rule_set_occurrence_count",
                &self.flight_by_occurrence.len(),
            )
            .field("rule_set_flight_count", &self.flight_count)
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
}

impl fmt::Debug for Acl4SsrOutputV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Acl4SsrOutputV1")
            .field("bytes", &"[REDACTED]")
            .field("bytes_len", &self.bytes.len())
            .field("report", &self.report)
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
    UnsupportedRule,
    ConversionLimit,
    Internal,
}

impl fmt::Display for Acl4SsrRenderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RuleSetAlignment => "Rule Set responses are not aligned",
            Self::InvalidRuleSet => "ACL4SSR Rule Set is invalid",
            Self::UnsupportedRule => "ACL4SSR config uses an unsupported rule",
            Self::ConversionLimit => "conversion resource limit exceeded",
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
    let (preimage_bytes, fingerprint) =
        hash_config_fingerprint(&config).map_err(|()| Acl4SsrPreparationError::ConversionLimit)?;
    let profile = lookup_profile(preimage_bytes, &fingerprint);
    validate_target_capability(&config, profile)?;
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
        fingerprint,
        profile,
        requests,
    })
}

#[derive(Clone, Copy)]
enum OutputFormat {
    Mihomo,
    Quanx,
    Singbox,
    Loon,
    Egern,
}

fn render(
    mut bound: PreparedAcl4SsrRuleSetsV1,
    unique_bodies: &[&[u8]],
    format: OutputFormat,
) -> Result<Acl4SsrOutputV1, Acl4SsrRenderError> {
    let materialized = materialize_rules(
        &bound.prepared.config,
        bound.prepared.profile,
        bound.prepared.fingerprint,
        unique_bodies,
        &bound.flight_by_occurrence,
        &mut bound.parsed_rule_sets,
    )?;
    let prepared = bound.prepared;
    let omitted_url_regex_count = u8::try_from(materialized.omitted_url_regex_count)
        .map_err(|_| Acl4SsrRenderError::UnsupportedRule)?;

    let group_names = prepared
        .config
        .groups
        .iter()
        .map(|group| group.name.as_str())
        .collect::<Vec<_>>();
    let named = resolve_node_names(prepared.parsed_subscription, &group_names)
        .map_err(|_| Acl4SsrRenderError::Internal)?;
    let nodes = named
        .occurrences()
        .iter()
        .filter_map(|occurrence| match occurrence {
            NamedNodeOccurrence::Accepted { node, .. } => Some(node.as_ref()),
            NamedNodeOccurrence::Rejected { .. } => None,
        })
        .collect::<Vec<_>>();
    if nodes.is_empty() {
        return Err(Acl4SsrRenderError::Internal);
    }

    let node_names = nodes
        .iter()
        .map(|node| node.name().as_str())
        .collect::<Vec<_>>();
    let regex_count = prepared
        .config
        .groups
        .iter()
        .flat_map(|group| &group.members)
        .filter(|member| matches!(member, GroupMember::NodeRegex(_)))
        .count();
    let evaluation_count = regex_count
        .checked_mul(node_names.len())
        .ok_or(Acl4SsrRenderError::ConversionLimit)?;
    if evaluation_count > MAX_REGEX_EVALUATIONS {
        return Err(Acl4SsrRenderError::ConversionLimit);
    }

    let policy = compile_acl4ssr_policy(
        &prepared.config.groups,
        &node_names,
        materialized.rules,
        omitted_url_regex_count,
    )?;
    let report = Acl4SsrConversionReportV1 {
        omitted_url_regex: policy.report().omitted_url_regex,
        empty_groups: policy.report().empty_groups,
        ignored_legacy_probe_hints: policy.report().ignored_legacy_probe_hints,
    };
    let bytes = render_policy_bytes(format, &nodes, &policy)?;
    Ok(Acl4SsrOutputV1 { bytes, report })
}

fn render_policy_bytes(
    format: OutputFormat,
    nodes: &[&crate::node::ProxyNode],
    policy: &CompiledPolicyV1,
) -> Result<Vec<u8>, Acl4SsrRenderError> {
    let render: RenderFromPolicyFn = match format {
        OutputFormat::Mihomo => render_mihomo_from_policy_v1,
        OutputFormat::Quanx => render_quanx_from_policy_v1,
        OutputFormat::Singbox => render_singbox_from_policy_v1,
        OutputFormat::Loon => render_loon_from_policy_v1,
        OutputFormat::Egern => render_egern_from_policy_v1,
    };
    render(nodes, policy, MAX_OUTPUT_BYTES)
        .map(|rendered| rendered.bytes)
        .map_err(|error| match error {
            AdapterRenderError::OutputTooLarge { .. } => Acl4SsrRenderError::ConversionLimit,
            AdapterRenderError::NoValidNodes | AdapterRenderError::Internal => {
                Acl4SsrRenderError::Internal
            }
        })
}
