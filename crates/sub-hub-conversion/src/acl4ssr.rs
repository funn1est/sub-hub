#[cfg(test)]
mod reference_decoder;
mod sha256;

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::IpAddr,
};

use regex::{Regex, RegexBuilder};
use url::{Host as UrlHost, Url};

use crate::{
    egern::{EgernRenderError, render_egern_from_policy_v1},
    loon::{LoonRenderError, render_loon_from_policy_v1},
    mihomo::{MAX_MIHOMO_OUTPUT_BYTES, render_clash_rule, render_mihomo_from_policy_v1},
    node_name::{NamedNodeOccurrence, is_reserved_symbol, resolve_node_names, validate_group_name},
    policy::{
        CompiledGroupV1, CompiledPolicyV1, CompiledRuleV1, GroupStrategyV1, IpVersion,
        PolicyMemberV1, PolicyReportV1, RuleMatcherV1,
    },
    quanx::{QuanxRenderError, render_quanx_from_policy_v1},
    singbox::{SingboxRenderError, render_singbox_from_policy_v1},
    subscription_source::ParsedSubscriptionSources,
};

const MAX_CONFIG_BYTES: usize = 256 * 1024;
const MAX_RULE_SET_BYTES: usize = 4 * 1024 * 1024;
const MAX_GROUPS: usize = 128;
const MAX_MEMBERS_PER_GROUP: usize = 256;
const MAX_MEMBERS: usize = 4_096;
const MAX_REGEX_OCCURRENCES: usize = 256;
const MAX_REGEX_SOURCE_BYTES: usize = 1_024;
const MAX_REGEX_SOURCE_BYTES_TOTAL: usize = 64 * 1024;
const MAX_REGEX_COMPILED_BYTES: usize = 1024 * 1024;
const MAX_REGEX_DFA_BYTES: usize = 64 * 1024;
const MAX_REGEX_EVALUATIONS: usize = 2_000_000;
const MAX_EXPANDED_MEMBERS: usize = 200_000;
const MAX_RULES: usize = 200_000;

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

struct Config {
    directives: Vec<Directive>,
    groups: Vec<Group>,
}

enum Directive {
    Ruleset {
        target: TargetRef,
        source: RuleSource,
    },
    Group(usize),
    EnableRuleGenerator(bool),
    OverwriteOriginalRules(bool),
}

#[derive(Clone)]
enum TargetRef {
    Direct,
    Reject,
    Group(String),
}

enum RuleSource {
    Remote(DeclaredUrl),
    GeoIpCn,
    Final,
}

struct Group {
    name: String,
    kind: GroupType,
    members: Vec<GroupMember>,
    payload: Option<GroupPayload>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GroupType {
    Select,
    UrlTest,
    Fallback,
    LoadBalance,
}

enum GroupMember {
    LiteralRef(TargetRef),
    NodeRegex(NodeRegex),
}

struct NodeRegex {
    source: String,
    compiled: Regex,
}

struct GroupPayload {
    health: DeclaredUrl,
    probe: Probe,
}

struct Probe {
    interval: u32,
    tolerance: Option<u16>,
}

struct DeclaredUrl {
    declared: String,
    _parsed: Url,
}

enum UnresolvedDirective {
    Ruleset { target: String, source: RuleSource },
    Group(UnresolvedGroup),
    EnableRuleGenerator(bool),
    OverwriteOriginalRules(bool),
}

struct UnresolvedGroup {
    name: String,
    kind: GroupType,
    members: Vec<UnresolvedMember>,
    payload: Option<GroupPayload>,
}

enum UnresolvedMember {
    Literal(String),
    NodeRegex(NodeRegex),
}

struct ParseBudget {
    member_count: usize,
    regex_count: usize,
    regex_source_bytes: usize,
}

impl Config {
    fn parse(input: &[u8]) -> Result<Self, Acl4SsrPreparationError> {
        if input.len() > MAX_CONFIG_BYTES {
            return Err(Acl4SsrPreparationError::ConversionLimit);
        }
        let input =
            std::str::from_utf8(input).map_err(|_| Acl4SsrPreparationError::InvalidConfig)?;
        let input = input.strip_prefix('\u{feff}').unwrap_or(input);
        if input.starts_with('\u{feff}')
            || input.contains('\0')
            || has_bare_carriage_return(input.as_bytes())
        {
            return Err(Acl4SsrPreparationError::InvalidConfig);
        }

        let mut section_seen = false;
        let mut enable_seen = false;
        let mut overwrite_seen = false;
        let mut unresolved = Vec::new();
        let mut budget = ParseBudget {
            member_count: 0,
            regex_count: 0,
            regex_source_bytes: 0,
        };

        for raw_line in input.split('\n') {
            let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
            let line = ascii_outer_trim(line);
            if line.is_empty()
                || line.starts_with(';')
                || line.starts_with('#')
                || line.starts_with("//")
            {
                continue;
            }
            if line.starts_with('[') {
                if line != "[custom]" || section_seen {
                    return Err(Acl4SsrPreparationError::InvalidConfig);
                }
                section_seen = true;
                continue;
            }
            if !section_seen || line.contains('\0') {
                return Err(Acl4SsrPreparationError::InvalidConfig);
            }
            let (key, value) = line
                .split_once('=')
                .ok_or(Acl4SsrPreparationError::InvalidConfig)?;
            let key = ascii_outer_trim(key);
            let value = ascii_outer_trim(value);
            let directive = match key {
                "enable_rule_generator" => {
                    if enable_seen || value != "true" {
                        return Err(Acl4SsrPreparationError::InvalidConfig);
                    }
                    enable_seen = true;
                    UnresolvedDirective::EnableRuleGenerator(true)
                }
                "overwrite_original_rules" => {
                    if overwrite_seen || value != "true" {
                        return Err(Acl4SsrPreparationError::InvalidConfig);
                    }
                    overwrite_seen = true;
                    UnresolvedDirective::OverwriteOriginalRules(true)
                }
                "ruleset" => parse_ruleset(value)?,
                "custom_proxy_group" => {
                    UnresolvedDirective::Group(parse_group(value, &mut budget)?)
                }
                _ => return Err(Acl4SsrPreparationError::InvalidConfig),
            };
            unresolved.push(directive);
        }

        if !section_seen || !enable_seen || !overwrite_seen {
            return Err(Acl4SsrPreparationError::InvalidConfig);
        }
        resolve_config(unresolved)
    }
}

fn parse_ruleset(value: &str) -> Result<UnresolvedDirective, Acl4SsrPreparationError> {
    let (target, source) = value
        .split_once(',')
        .ok_or(Acl4SsrPreparationError::InvalidConfig)?;
    let target = ascii_outer_trim(target);
    let source = ascii_outer_trim(source);
    if target.is_empty() || source.is_empty() {
        return Err(Acl4SsrPreparationError::InvalidConfig);
    }
    let source = match source {
        "[]GEOIP,CN" => RuleSource::GeoIpCn,
        "[]FINAL" => RuleSource::Final,
        source if source.starts_with("[]") => {
            return Err(Acl4SsrPreparationError::InvalidConfig);
        }
        source => RuleSource::Remote(validate_url(source, UrlPurpose::RuleSet)?),
    };
    Ok(UnresolvedDirective::Ruleset {
        target: target.to_owned(),
        source,
    })
}

fn parse_group(
    value: &str,
    budget: &mut ParseBudget,
) -> Result<UnresolvedGroup, Acl4SsrPreparationError> {
    if value.bytes().filter(|byte| *byte == b'`').count() > MAX_MEMBERS_PER_GROUP + 3 {
        return Err(Acl4SsrPreparationError::ConversionLimit);
    }
    let fields = value.split('`').collect::<Vec<_>>();
    if fields.iter().any(|field| field.is_empty()) || fields.len() < 3 {
        return Err(Acl4SsrPreparationError::InvalidConfig);
    }
    let name = fields[0];
    let kind = match fields[1] {
        "select" => GroupType::Select,
        "url-test" => GroupType::UrlTest,
        "fallback" => GroupType::Fallback,
        "load-balance" => GroupType::LoadBalance,
        _ => return Err(Acl4SsrPreparationError::InvalidConfig),
    };
    let (member_fields, payload) = if kind == GroupType::Select {
        (&fields[2..], None)
    } else {
        if fields.len() < 5 {
            return Err(Acl4SsrPreparationError::InvalidConfig);
        }
        let member_end = fields.len() - 2;
        let health = validate_url(fields[member_end], UrlPurpose::Health)?;
        let probe = parse_probe(fields[member_end + 1])?;
        (&fields[2..member_end], Some(GroupPayload { health, probe }))
    };
    if member_fields.is_empty() || member_fields.len() > MAX_MEMBERS_PER_GROUP {
        return Err(if member_fields.len() > MAX_MEMBERS_PER_GROUP {
            Acl4SsrPreparationError::ConversionLimit
        } else {
            Acl4SsrPreparationError::InvalidConfig
        });
    }
    budget.member_count = budget
        .member_count
        .checked_add(member_fields.len())
        .ok_or(Acl4SsrPreparationError::ConversionLimit)?;
    if budget.member_count > MAX_MEMBERS {
        return Err(Acl4SsrPreparationError::ConversionLimit);
    }

    let mut literal_names = BTreeSet::new();
    let mut members = Vec::with_capacity(member_fields.len());
    for field in member_fields {
        let member = if let Some(literal) = field.strip_prefix("[]") {
            if literal.is_empty() || !literal_names.insert(literal.to_owned()) {
                return Err(Acl4SsrPreparationError::InvalidConfig);
            }
            UnresolvedMember::Literal(literal.to_owned())
        } else {
            budget.regex_count = budget
                .regex_count
                .checked_add(1)
                .ok_or(Acl4SsrPreparationError::ConversionLimit)?;
            budget.regex_source_bytes = budget
                .regex_source_bytes
                .checked_add(field.len())
                .ok_or(Acl4SsrPreparationError::ConversionLimit)?;
            if budget.regex_count > MAX_REGEX_OCCURRENCES
                || field.len() > MAX_REGEX_SOURCE_BYTES
                || budget.regex_source_bytes > MAX_REGEX_SOURCE_BYTES_TOTAL
            {
                return Err(Acl4SsrPreparationError::ConversionLimit);
            }
            let compiled = RegexBuilder::new(field)
                .size_limit(MAX_REGEX_COMPILED_BYTES)
                .dfa_size_limit(MAX_REGEX_DFA_BYTES)
                .build()
                .map_err(|error| match error {
                    regex::Error::CompiledTooBig(_) => Acl4SsrPreparationError::ConversionLimit,
                    _ => Acl4SsrPreparationError::InvalidConfig,
                })?;
            UnresolvedMember::NodeRegex(NodeRegex {
                source: (*field).to_owned(),
                compiled,
            })
        };
        members.push(member);
    }
    Ok(UnresolvedGroup {
        name: name.to_owned(),
        kind,
        members,
        payload,
    })
}

fn parse_probe(input: &str) -> Result<Probe, Acl4SsrPreparationError> {
    let mut fields = input.splitn(4, ',');
    let interval = fields.next().unwrap_or_default();
    let second = fields.next();
    let third = fields.next();
    let fourth = fields.next();
    let tolerance = match (second, third, fourth) {
        (None, None, None) => None,
        (Some(""), Some(tolerance), None) if !tolerance.is_empty() => {
            Some(parse_canonical_decimal::<u16>(tolerance, u16::MAX)?)
        }
        _ => return Err(Acl4SsrPreparationError::InvalidConfig),
    };
    Ok(Probe {
        interval: parse_canonical_decimal::<u32>(interval, i32::MAX as u32)?,
        tolerance,
    })
}

fn parse_canonical_decimal<T>(input: &str, maximum: T) -> Result<T, Acl4SsrPreparationError>
where
    T: std::str::FromStr + Ord + Copy,
{
    if input.is_empty()
        || input.starts_with('0')
        || !input.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(Acl4SsrPreparationError::InvalidConfig);
    }
    let value = input
        .parse::<T>()
        .map_err(|_| Acl4SsrPreparationError::InvalidConfig)?;
    if value > maximum {
        return Err(Acl4SsrPreparationError::InvalidConfig);
    }
    Ok(value)
}

#[derive(Clone, Copy)]
enum UrlPurpose {
    RuleSet,
    Health,
}

fn validate_url(
    declared: &str,
    purpose: UrlPurpose,
) -> Result<DeclaredUrl, Acl4SsrPreparationError> {
    let authority = declared
        .split_once("://")
        .map(|(_, remainder)| remainder.split(['/', '?', '#']).next().unwrap_or(remainder));
    if declared.contains(' ')
        || declared.chars().any(char::is_control)
        || authority.is_some_and(|authority| authority.contains('@'))
    {
        return Err(Acl4SsrPreparationError::InvalidConfig);
    }
    let parsed = Url::parse(declared).map_err(|_| Acl4SsrPreparationError::InvalidConfig)?;
    let valid_scheme = match purpose {
        UrlPurpose::RuleSet => parsed.scheme() == "https",
        UrlPurpose::Health => matches!(parsed.scheme(), "http" | "https"),
    };
    if !valid_scheme
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
        || parsed.port() == Some(0)
        || !matches!(parsed.host(), Some(UrlHost::Domain(host)) if is_dns_hostname(host))
    {
        return Err(Acl4SsrPreparationError::InvalidConfig);
    }
    Ok(DeclaredUrl {
        declared: declared.to_owned(),
        _parsed: parsed,
    })
}

fn is_dns_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

fn resolve_config(unresolved: Vec<UnresolvedDirective>) -> Result<Config, Acl4SsrPreparationError> {
    let group_names = unresolved
        .iter()
        .filter_map(|directive| match directive {
            UnresolvedDirective::Group(group) => Some(group.name.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    if group_names.len() > MAX_GROUPS {
        return Err(Acl4SsrPreparationError::ConversionLimit);
    }
    let mut group_indices = BTreeMap::new();
    for (index, name) in group_names.iter().copied().enumerate() {
        if validate_group_name(name).is_some()
            || is_reserved_symbol(name)
            || group_indices.insert(name.to_owned(), index).is_some()
        {
            return Err(Acl4SsrPreparationError::InvalidConfig);
        }
    }

    let resolve_target = |value: String| -> Result<TargetRef, Acl4SsrPreparationError> {
        match value.as_str() {
            "DIRECT" => Ok(TargetRef::Direct),
            "REJECT" => Ok(TargetRef::Reject),
            _ if group_indices.contains_key(value.as_str()) => Ok(TargetRef::Group(value)),
            _ => Err(Acl4SsrPreparationError::InvalidConfig),
        }
    };

    let mut directives = Vec::with_capacity(unresolved.len());
    let mut groups = Vec::with_capacity(group_names.len());
    let mut final_seen = false;
    let mut geo_ip_seen = false;
    for directive in unresolved {
        let directive = match directive {
            UnresolvedDirective::Ruleset { target, source } => {
                if final_seen {
                    return Err(Acl4SsrPreparationError::InvalidConfig);
                }
                match source {
                    RuleSource::GeoIpCn => {
                        if geo_ip_seen {
                            return Err(Acl4SsrPreparationError::InvalidConfig);
                        }
                        geo_ip_seen = true;
                    }
                    RuleSource::Final => final_seen = true,
                    RuleSource::Remote(_) => {}
                }
                Directive::Ruleset {
                    target: resolve_target(target)?,
                    source,
                }
            }
            UnresolvedDirective::Group(group) => {
                let own_name = group.name.clone();
                let members = group
                    .members
                    .into_iter()
                    .map(|member| match member {
                        UnresolvedMember::Literal(value) => {
                            let target = resolve_target(value)?;
                            if matches!(&target, TargetRef::Group(name) if name == &own_name) {
                                return Err(Acl4SsrPreparationError::InvalidConfig);
                            }
                            Ok(GroupMember::LiteralRef(target))
                        }
                        UnresolvedMember::NodeRegex(regex) => Ok(GroupMember::NodeRegex(regex)),
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let index = groups.len();
                groups.push(Group {
                    name: group.name,
                    kind: group.kind,
                    members,
                    payload: group.payload,
                });
                Directive::Group(index)
            }
            UnresolvedDirective::EnableRuleGenerator(value) => {
                Directive::EnableRuleGenerator(value)
            }
            UnresolvedDirective::OverwriteOriginalRules(value) => {
                Directive::OverwriteOriginalRules(value)
            }
        };
        directives.push(directive);
    }
    if !final_seen {
        return Err(Acl4SsrPreparationError::InvalidConfig);
    }
    validate_group_cycles(&groups, &group_indices)?;
    Ok(Config { directives, groups })
}

fn validate_group_cycles(
    groups: &[Group],
    indices: &BTreeMap<String, usize>,
) -> Result<(), Acl4SsrPreparationError> {
    fn visit(
        index: usize,
        groups: &[Group],
        indices: &BTreeMap<String, usize>,
        states: &mut [u8],
    ) -> Result<(), Acl4SsrPreparationError> {
        match states[index] {
            1 => return Err(Acl4SsrPreparationError::InvalidConfig),
            2 => return Ok(()),
            _ => {}
        }
        states[index] = 1;
        for member in &groups[index].members {
            if let GroupMember::LiteralRef(TargetRef::Group(name)) = member {
                let target = *indices
                    .get(name.as_str())
                    .ok_or(Acl4SsrPreparationError::Internal)?;
                visit(target, groups, indices, states)?;
            }
        }
        states[index] = 2;
        Ok(())
    }

    let mut states = vec![0; groups.len()];
    for index in 0..groups.len() {
        visit(index, groups, indices, &mut states)?;
    }
    Ok(())
}

fn validate_target_capability(
    config: &Config,
    profile: Option<ProfileKind>,
) -> Result<(), Acl4SsrPreparationError> {
    let policy = profile
        .map(|profile| profile_policy(profile).ok_or(Acl4SsrPreparationError::Internal))
        .transpose()?;
    let mut observed_legacy_hints = 0;
    for group in &config.groups {
        let tolerance = group
            .payload
            .as_ref()
            .and_then(|payload| payload.probe.tolerance);
        if let Some(tolerance) = tolerance
            && group.kind != GroupType::UrlTest
        {
            observed_legacy_hints += 1;
            let allowed = policy.is_some_and(|policy| {
                policy.legacy_probe_hints.iter().any(|expected| {
                    group.name == expected.group_name
                        && group.kind == expected.kind
                        && tolerance == expected.tolerance
                })
            });
            if !allowed {
                return Err(Acl4SsrPreparationError::InvalidConfig);
            }
        }
    }
    if observed_legacy_hints != policy.map_or(0, |policy| policy.legacy_probe_hints.len()) {
        return Err(Acl4SsrPreparationError::InvalidConfig);
    }
    Ok(())
}

fn ascii_outer_trim(input: &str) -> &str {
    input.trim_matches([' ', '\t'])
}

fn has_bare_carriage_return(input: &[u8]) -> bool {
    input
        .iter()
        .enumerate()
        .any(|(index, byte)| *byte == b'\r' && input.get(index + 1) != Some(&b'\n'))
}

trait WireOutput {
    fn write(&mut self, bytes: &[u8]) -> Result<(), ()>;

    fn write_byte(&mut self, byte: u8) -> Result<(), ()> {
        self.write(std::slice::from_ref(&byte))
    }
}

impl WireOutput for Vec<u8> {
    fn write(&mut self, bytes: &[u8]) -> Result<(), ()> {
        self.extend_from_slice(bytes);
        Ok(())
    }
}

struct HashedWire {
    hasher: sha256::Hasher,
    bytes: usize,
}

impl HashedWire {
    const fn new() -> Self {
        Self {
            hasher: sha256::Hasher::new(),
            bytes: 0,
        }
    }

    fn finish(self) -> Result<(usize, [u8; 32]), ()> {
        Ok((self.bytes, self.hasher.finalize()?))
    }
}

impl WireOutput for HashedWire {
    fn write(&mut self, bytes: &[u8]) -> Result<(), ()> {
        self.bytes = self.bytes.checked_add(bytes.len()).ok_or(())?;
        self.hasher.update(bytes)
    }
}

fn hash_config_fingerprint(config: &Config) -> Result<(usize, [u8; 32]), ()> {
    let mut output = HashedWire::new();
    encode_config_fingerprint_into(config, &mut output)?;
    output.finish()
}

#[cfg(test)]
fn encode_config_fingerprint(config: &Config) -> Result<Vec<u8>, ()> {
    let mut output = Vec::new();
    encode_config_fingerprint_into(config, &mut output)?;
    Ok(output)
}

fn encode_config_fingerprint_into<O: WireOutput>(
    config: &Config,
    output: &mut O,
) -> Result<(), ()> {
    encode_lp16_ascii(output, b"sub-hub/ConfigFingerprint/SHA-256")?;
    output.write(&1_u16.to_be_bytes())?;
    output.write_byte(1)?;
    encode_count(output, config.directives.len())?;
    for directive in &config.directives {
        match directive {
            Directive::Ruleset { target, source } => {
                output.write_byte(1)?;
                encode_target(output, target)?;
                match source {
                    RuleSource::Remote(url) => {
                        output.write_byte(1)?;
                        encode_text(output, &url.declared)?;
                    }
                    RuleSource::GeoIpCn => output.write_byte(2)?,
                    RuleSource::Final => output.write_byte(3)?,
                }
            }
            Directive::Group(index) => {
                let group = config.groups.get(*index).ok_or(())?;
                output.write_byte(2)?;
                encode_text(output, &group.name)?;
                output.write_byte(match group.kind {
                    GroupType::Select => 1,
                    GroupType::UrlTest => 2,
                    GroupType::Fallback => 3,
                    GroupType::LoadBalance => 4,
                })?;
                encode_count(output, group.members.len())?;
                for member in &group.members {
                    match member {
                        GroupMember::LiteralRef(target) => {
                            output.write_byte(1)?;
                            encode_target(output, target)?;
                        }
                        GroupMember::NodeRegex(regex) => {
                            output.write_byte(2)?;
                            encode_text(output, &regex.source)?;
                        }
                    }
                }
                if let Some(payload) = &group.payload {
                    encode_text(output, &payload.health.declared)?;
                    output.write(&payload.probe.interval.to_be_bytes())?;
                    match payload.probe.tolerance {
                        None => output.write_byte(0)?,
                        Some(tolerance) => {
                            output.write_byte(1)?;
                            output.write(&u32::from(tolerance).to_be_bytes())?;
                        }
                    }
                }
            }
            Directive::EnableRuleGenerator(value) => {
                output.write(&[3, u8::from(*value)])?;
            }
            Directive::OverwriteOriginalRules(value) => {
                output.write(&[4, u8::from(*value)])?;
            }
        }
    }
    Ok(())
}

fn encode_target<O: WireOutput>(output: &mut O, target: &TargetRef) -> Result<(), ()> {
    match target {
        TargetRef::Direct => output.write_byte(1)?,
        TargetRef::Reject => output.write_byte(2)?,
        TargetRef::Group(name) => {
            output.write_byte(3)?;
            encode_text(output, name)?;
        }
    }
    Ok(())
}

fn encode_lp16_ascii<O: WireOutput>(output: &mut O, value: &[u8]) -> Result<(), ()> {
    let length = u16::try_from(value.len()).map_err(|_| ())?;
    output.write(&length.to_be_bytes())?;
    output.write(value)?;
    Ok(())
}

fn encode_count<O: WireOutput>(output: &mut O, count: usize) -> Result<(), ()> {
    output.write(&u32::try_from(count).map_err(|_| ())?.to_be_bytes())?;
    Ok(())
}

fn encode_text<O: WireOutput>(output: &mut O, value: &str) -> Result<(), ()> {
    encode_count(output, value.len())?;
    output.write(value.as_bytes())?;
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProfileKind {
    Online,
    Full,
}

struct ProfilePolicy {
    kind: ProfileKind,
    config_preimage_bytes: usize,
    config_digest: [u8; 32],
    evidence_preimage_bytes: usize,
    evidence_digest: [u8; 32],
    omitted_distribution: &'static [ExpectedOmittedPolicy],
    legacy_probe_hints: &'static [ExpectedLegacyProbeHint],
}

struct ExpectedOmittedPolicy {
    target: &'static str,
    count: usize,
}

struct ExpectedLegacyProbeHint {
    group_name: &'static str,
    kind: GroupType,
    tolerance: u16,
}

// These values were promoted only after an independent parse of the pinned Git
// blob corpus agreed with the Rust encoder on all four preimage lengths and
// SHA-256 digests. This table intentionally cannot be changed by request,
// environment, KV, or runtime configuration.
const PROFILE_POLICIES: &[ProfilePolicy] = &[
    ProfilePolicy {
        kind: ProfileKind::Online,
        config_preimage_bytes: 2_419,
        config_digest: [
            0x6b, 0xa3, 0xcf, 0x43, 0xff, 0x20, 0xb8, 0x5a, 0xdd, 0x8d, 0x17, 0x29, 0x3a, 0x5e,
            0xbd, 0x30, 0x59, 0x2b, 0x17, 0x29, 0xa8, 0x93, 0xe6, 0xbf, 0x77, 0x6e, 0x14, 0x27,
            0x4b, 0x2d, 0xaf, 0x58,
        ],
        evidence_preimage_bytes: 167,
        evidence_digest: [
            0x8c, 0xfb, 0xc9, 0x0f, 0xbf, 0x87, 0xcc, 0x5b, 0x87, 0x42, 0x32, 0xf5, 0x2a, 0x31,
            0x60, 0x2f, 0x80, 0x38, 0x09, 0x43, 0x7d, 0x63, 0x69, 0x04, 0x1c, 0x10, 0xfc, 0x2f,
            0xb4, 0x83, 0xb3, 0xd8,
        ],
        omitted_distribution: &[ExpectedOmittedPolicy {
            target: "🌍 国外媒体",
            count: 1,
        }],
        legacy_probe_hints: &[],
    },
    ProfilePolicy {
        kind: ProfileKind::Full,
        config_preimage_bytes: 8_557,
        config_digest: [
            0x98, 0xfd, 0x7e, 0x18, 0x68, 0x74, 0xd7, 0x03, 0x57, 0x44, 0xa1, 0xb5, 0xc8, 0xb5,
            0x18, 0xdc, 0xc6, 0x22, 0xd1, 0x09, 0x0a, 0x20, 0x7f, 0x29, 0x93, 0xea, 0x3f, 0x9e,
            0xd2, 0x88, 0x57, 0x79,
        ],
        evidence_preimage_bytes: 863,
        evidence_digest: [
            0x8d, 0x4b, 0x98, 0x6b, 0xcf, 0xd2, 0x49, 0x8c, 0x45, 0x0d, 0xb3, 0x09, 0x01, 0xf2,
            0xe4, 0x97, 0x6d, 0x3f, 0xd9, 0x5f, 0x25, 0xa2, 0xa1, 0xe0, 0x9b, 0xb2, 0x4d, 0x7f,
            0x2b, 0xa3, 0x7d, 0x20,
        ],
        omitted_distribution: &[
            ExpectedOmittedPolicy {
                target: "🎯 全球直连",
                count: 7,
            },
            ExpectedOmittedPolicy {
                target: "🌏 国内媒体",
                count: 1,
            },
            ExpectedOmittedPolicy {
                target: "🌍 国外媒体",
                count: 1,
            },
        ],
        legacy_probe_hints: &[
            ExpectedLegacyProbeHint {
                group_name: "🔯 故障转移",
                kind: GroupType::Fallback,
                tolerance: 50,
            },
            ExpectedLegacyProbeHint {
                group_name: "🔮 负载均衡",
                kind: GroupType::LoadBalance,
                tolerance: 50,
            },
        ],
    },
];

fn lookup_profile(preimage_bytes: usize, digest: &[u8; 32]) -> Option<ProfileKind> {
    PROFILE_POLICIES
        .iter()
        .find(|entry| {
            entry.config_preimage_bytes == preimage_bytes && entry.config_digest == *digest
        })
        .map(|entry| entry.kind)
}

fn profile_policy(kind: ProfileKind) -> Option<&'static ProfilePolicy> {
    PROFILE_POLICIES.iter().find(|entry| entry.kind == kind)
}

enum RuleEntry {
    Domain {
        kind: DomainRuleType,
        value: String,
    },
    Cidr {
        kind: CidrRuleType,
        value: String,
        no_resolve: bool,
    },
    UrlRegex(String),
}

#[derive(Clone, Copy)]
enum DomainRuleType {
    Domain,
    DomainSuffix,
    DomainKeyword,
    ProcessName,
}

#[derive(Clone, Copy)]
enum CidrRuleType {
    V4,
    V6,
}

#[cfg(test)]
struct OmittedEvidenceEntry {
    remote_source_ordinal: u32,
    url_regex_ordinal: u32,
    target: TargetRef,
    pattern: String,
}

struct MaterializedRules {
    rules: Vec<CompiledRuleV1>,
    omitted_url_regex_count: usize,
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
    match format {
        OutputFormat::Mihomo => {
            render_mihomo_from_policy_v1(nodes, policy, MAX_MIHOMO_OUTPUT_BYTES).map_err(|error| {
                match error {
                    crate::mihomo::BuiltinMihomoError::OutputTooLarge { .. } => {
                        Acl4SsrRenderError::ConversionLimit
                    }
                    crate::mihomo::BuiltinMihomoError::NodeNaming(_)
                    | crate::mihomo::BuiltinMihomoError::NoValidNodes { .. }
                    | crate::mihomo::BuiltinMihomoError::Serialization => {
                        Acl4SsrRenderError::Internal
                    }
                }
            })
        }
        OutputFormat::Quanx => render_quanx_from_policy_v1(nodes, policy, MAX_MIHOMO_OUTPUT_BYTES)
            .map_err(|error| match error {
                QuanxRenderError::OutputTooLarge { .. } => Acl4SsrRenderError::ConversionLimit,
                QuanxRenderError::NoValidNodes | QuanxRenderError::Internal => {
                    Acl4SsrRenderError::Internal
                }
            }),
        OutputFormat::Singbox => {
            render_singbox_from_policy_v1(nodes, policy, MAX_MIHOMO_OUTPUT_BYTES).map_err(|error| {
                match error {
                    SingboxRenderError::OutputTooLarge { .. } => {
                        Acl4SsrRenderError::ConversionLimit
                    }
                    SingboxRenderError::NoValidNodes | SingboxRenderError::Internal => {
                        Acl4SsrRenderError::Internal
                    }
                }
            })
        }
        OutputFormat::Loon => render_loon_from_policy_v1(nodes, policy, MAX_MIHOMO_OUTPUT_BYTES)
            .map_err(|error| match error {
                LoonRenderError::OutputTooLarge { .. } => Acl4SsrRenderError::ConversionLimit,
                LoonRenderError::NoValidNodes | LoonRenderError::Internal => {
                    Acl4SsrRenderError::Internal
                }
            }),
        OutputFormat::Egern => render_egern_from_policy_v1(nodes, policy, MAX_MIHOMO_OUTPUT_BYTES)
            .map_err(|error| match error {
                EgernRenderError::OutputTooLarge { .. } => Acl4SsrRenderError::ConversionLimit,
                EgernRenderError::NoValidNodes | EgernRenderError::Internal => {
                    Acl4SsrRenderError::Internal
                }
            }),
    }
}

fn compile_acl4ssr_policy(
    groups: &[Group],
    node_names: &[&str],
    rules: Vec<CompiledRuleV1>,
    omitted_url_regex_count: u8,
) -> Result<CompiledPolicyV1, Acl4SsrRenderError> {
    let (compiled_groups, empty_group_count) = expand_groups(groups, node_names)?;
    let ignored_legacy_probe_hint_count = groups
        .iter()
        .filter(|group| {
            group.kind != GroupType::UrlTest
                && group
                    .payload
                    .as_ref()
                    .and_then(|payload| payload.probe.tolerance)
                    .is_some()
        })
        .count();
    Ok(CompiledPolicyV1::new(
        compiled_groups,
        rules,
        PolicyReportV1 {
            omitted_url_regex: omitted_url_regex_count,
            empty_groups: u8::try_from(empty_group_count)
                .map_err(|_| Acl4SsrRenderError::Internal)?,
            ignored_legacy_probe_hints: u8::try_from(ignored_legacy_probe_hint_count)
                .map_err(|_| Acl4SsrRenderError::Internal)?,
        },
    ))
}

fn materialize_rules(
    config: &Config,
    profile: Option<ProfileKind>,
    config_fingerprint: [u8; 32],
    unique_bodies: &[&[u8]],
    flight_by_occurrence: &[usize],
    parsed_rule_sets: &mut [Option<Vec<RuleEntry>>],
) -> Result<MaterializedRules, Acl4SsrRenderError> {
    let mut rules = Vec::new();
    let mut rendered_bytes = 0_usize;
    let mut evidence = profile
        .map(|profile| OmittedEvidenceAccumulator::new(profile, config_fingerprint))
        .transpose()?;
    let mut parsed = ParsedRuleSetFlights::new(unique_bodies, parsed_rule_sets);
    let mut remote_body_index = 0;
    let mut remote_source_ordinal = 0_u32;
    let mut rule_count = 0_usize;
    for directive in &config.directives {
        let Directive::Ruleset { target, source } = directive else {
            continue;
        };
        match source {
            RuleSource::Remote(_) => {
                let flight = *flight_by_occurrence
                    .get(remote_body_index)
                    .ok_or(Acl4SsrRenderError::RuleSetAlignment)?;
                let entries = parsed.entries(flight, &mut rule_count)?;
                let mut url_regex_ordinal = 0_u32;
                for entry in entries {
                    match entry {
                        RuleEntry::UrlRegex(pattern) => {
                            let accumulator = evidence
                                .as_mut()
                                .ok_or(Acl4SsrRenderError::UnsupportedRule)?;
                            accumulator.push(
                                remote_source_ordinal,
                                url_regex_ordinal,
                                target,
                                pattern,
                            )?;
                            url_regex_ordinal = url_regex_ordinal
                                .checked_add(1)
                                .ok_or(Acl4SsrRenderError::ConversionLimit)?;
                        }
                        entry => push_compiled_rule(
                            &mut rules,
                            compiled_rule(entry, target),
                            &mut rendered_bytes,
                        )?,
                    }
                }
                remote_body_index += 1;
                remote_source_ordinal = remote_source_ordinal
                    .checked_add(1)
                    .ok_or(Acl4SsrRenderError::ConversionLimit)?;
            }
            RuleSource::GeoIpCn => {
                increment_rule_count(&mut rule_count)?;
                push_compiled_rule(
                    &mut rules,
                    CompiledRuleV1::new(RuleMatcherV1::GeoIpCn, policy_member(target)),
                    &mut rendered_bytes,
                )?;
            }
            RuleSource::Final => {
                increment_rule_count(&mut rule_count)?;
                push_compiled_rule(
                    &mut rules,
                    CompiledRuleV1::new(RuleMatcherV1::Match, policy_member(target)),
                    &mut rendered_bytes,
                )?;
            }
        }
    }
    if remote_body_index != flight_by_occurrence.len() {
        return Err(Acl4SsrRenderError::RuleSetAlignment);
    }
    let omitted_url_regex_count = match evidence {
        Some(evidence) => evidence.finish()?,
        None => 0,
    };
    Ok(MaterializedRules {
        rules,
        omitted_url_regex_count,
    })
}

struct ParsedRuleSetFlights<'a> {
    bodies: &'a [&'a [u8]],
    entries: &'a mut [Option<Vec<RuleEntry>>],
    #[cfg(test)]
    parse_misses: usize,
}

impl<'a> ParsedRuleSetFlights<'a> {
    fn new(bodies: &'a [&'a [u8]], entries: &'a mut [Option<Vec<RuleEntry>>]) -> Self {
        Self {
            bodies,
            entries,
            #[cfg(test)]
            parse_misses: 0,
        }
    }

    fn entries(
        &mut self,
        flight: usize,
        total_rule_count: &mut usize,
    ) -> Result<&[RuleEntry], Acl4SsrRenderError> {
        let body = self
            .bodies
            .get(flight)
            .ok_or(Acl4SsrRenderError::RuleSetAlignment)?;
        let slot = self
            .entries
            .get_mut(flight)
            .ok_or(Acl4SsrRenderError::RuleSetAlignment)?;
        let newly_parsed = slot.is_none();
        if newly_parsed {
            #[cfg(test)]
            {
                self.parse_misses += 1;
            }
            *slot = Some(parse_rule_set(body, total_rule_count)?);
        } else {
            let entry_count = slot
                .as_ref()
                .ok_or(Acl4SsrRenderError::RuleSetAlignment)?
                .len();
            increment_rule_count_by(total_rule_count, entry_count)?;
        }
        slot.as_deref().ok_or(Acl4SsrRenderError::RuleSetAlignment)
    }
}

fn parse_rule_set(
    input: &[u8],
    total_rule_count: &mut usize,
) -> Result<Vec<RuleEntry>, Acl4SsrRenderError> {
    if input.is_empty() || input.len() > MAX_RULE_SET_BYTES {
        return Err(if input.len() > MAX_RULE_SET_BYTES {
            Acl4SsrRenderError::ConversionLimit
        } else {
            Acl4SsrRenderError::InvalidRuleSet
        });
    }
    let input = std::str::from_utf8(input).map_err(|_| Acl4SsrRenderError::InvalidRuleSet)?;
    if input.starts_with('\u{feff}')
        || input.contains('\0')
        || has_bare_carriage_return(input.as_bytes())
    {
        return Err(Acl4SsrRenderError::InvalidRuleSet);
    }
    let mut entries = Vec::new();
    for raw_line in input.split('\n') {
        let line = ascii_outer_trim(raw_line.strip_suffix('\r').unwrap_or(raw_line));
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        increment_rule_count(total_rule_count)?;
        entries.push(parse_rule_line(line)?);
    }
    if entries.is_empty() {
        return Err(Acl4SsrRenderError::InvalidRuleSet);
    }
    Ok(entries)
}

fn parse_rule_line(line: &str) -> Result<RuleEntry, Acl4SsrRenderError> {
    if let Some(pattern) = line.strip_prefix("URL-REGEX,") {
        if pattern.is_empty() || pattern.chars().any(char::is_control) {
            return Err(Acl4SsrRenderError::InvalidRuleSet);
        }
        return Ok(RuleEntry::UrlRegex(pattern.to_owned()));
    }
    let mut split = line.splitn(4, ',');
    let kind = split.next().unwrap_or_default();
    let value = split.next().unwrap_or_default();
    let third = split.next();
    let fourth = split.next();
    match (third, fourth) {
        (None, None)
            if matches!(
                kind,
                "DOMAIN" | "DOMAIN-SUFFIX" | "DOMAIN-KEYWORD" | "PROCESS-NAME"
            ) =>
        {
            validate_ordinary_rule_value(value)?;
            Ok(RuleEntry::Domain {
                kind: match kind {
                    "DOMAIN" => DomainRuleType::Domain,
                    "DOMAIN-SUFFIX" => DomainRuleType::DomainSuffix,
                    "DOMAIN-KEYWORD" => DomainRuleType::DomainKeyword,
                    "PROCESS-NAME" => DomainRuleType::ProcessName,
                    _ => unreachable!("guarded domain kind"),
                },
                value: value.to_owned(),
            })
        }
        (None, None) if matches!(kind, "IP-CIDR" | "IP-CIDR6") => {
            parse_cidr_rule(kind, value, false)
        }
        (Some("no-resolve"), None) if matches!(kind, "IP-CIDR" | "IP-CIDR6") => {
            parse_cidr_rule(kind, value, true)
        }
        _ => Err(Acl4SsrRenderError::InvalidRuleSet),
    }
}

fn validate_ordinary_rule_value(value: &str) -> Result<(), Acl4SsrRenderError> {
    if value.is_empty() || value.chars().any(char::is_control) {
        Err(Acl4SsrRenderError::InvalidRuleSet)
    } else {
        Ok(())
    }
}

fn parse_cidr_rule(
    kind: &str,
    value: &str,
    no_resolve: bool,
) -> Result<RuleEntry, Acl4SsrRenderError> {
    validate_ordinary_rule_value(value)?;
    let (address, prefix) = value
        .rsplit_once('/')
        .ok_or(Acl4SsrRenderError::InvalidRuleSet)?;
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| Acl4SsrRenderError::InvalidRuleSet)?;
    let prefix = parse_cidr_prefix(prefix)?;
    let cidr_kind = match (kind, address) {
        ("IP-CIDR", IpAddr::V4(_)) if prefix <= 32 => CidrRuleType::V4,
        ("IP-CIDR6", IpAddr::V6(_)) if prefix <= 128 => CidrRuleType::V6,
        _ => return Err(Acl4SsrRenderError::InvalidRuleSet),
    };
    Ok(RuleEntry::Cidr {
        kind: cidr_kind,
        value: value.to_owned(),
        no_resolve,
    })
}

fn parse_cidr_prefix(input: &str) -> Result<u8, Acl4SsrRenderError> {
    if input.is_empty()
        || !input.bytes().all(|byte| byte.is_ascii_digit())
        || input.len() > 1 && input.starts_with('0')
    {
        return Err(Acl4SsrRenderError::InvalidRuleSet);
    }
    input
        .parse()
        .map_err(|_| Acl4SsrRenderError::InvalidRuleSet)
}

fn increment_rule_count(count: &mut usize) -> Result<(), Acl4SsrRenderError> {
    increment_rule_count_by(count, 1)
}

fn increment_rule_count_by(count: &mut usize, additional: usize) -> Result<(), Acl4SsrRenderError> {
    let next = count
        .checked_add(additional)
        .filter(|next| *next <= MAX_RULES)
        .ok_or(Acl4SsrRenderError::ConversionLimit)?;
    *count = next;
    Ok(())
}

fn push_compiled_rule(
    output: &mut Vec<CompiledRuleV1>,
    rule: CompiledRuleV1,
    rendered_bytes: &mut usize,
) -> Result<(), Acl4SsrRenderError> {
    *rendered_bytes = rendered_bytes
        .checked_add(render_clash_rule(&rule).len())
        .ok_or(Acl4SsrRenderError::ConversionLimit)?;
    if *rendered_bytes > MAX_MIHOMO_OUTPUT_BYTES {
        return Err(Acl4SsrRenderError::ConversionLimit);
    }
    output.push(rule);
    Ok(())
}

fn compiled_rule(entry: &RuleEntry, target: &TargetRef) -> CompiledRuleV1 {
    let matcher = match entry {
        RuleEntry::Domain { kind, value } => match kind {
            DomainRuleType::Domain => RuleMatcherV1::Domain(value.clone()),
            DomainRuleType::DomainSuffix => RuleMatcherV1::DomainSuffix(value.clone()),
            DomainRuleType::DomainKeyword => RuleMatcherV1::DomainKeyword(value.clone()),
            DomainRuleType::ProcessName => RuleMatcherV1::ProcessName(value.clone()),
        },
        RuleEntry::Cidr {
            kind,
            value,
            no_resolve,
        } => RuleMatcherV1::IpCidr {
            value: value.clone(),
            version: match kind {
                CidrRuleType::V4 => IpVersion::V4,
                CidrRuleType::V6 => IpVersion::V6,
            },
            no_resolve: *no_resolve,
        },
        RuleEntry::UrlRegex(_) => unreachable!("URL-REGEX is gated before rendering"),
    };
    CompiledRuleV1::new(matcher, policy_member(target))
}

fn policy_member(target: &TargetRef) -> PolicyMemberV1 {
    match target {
        TargetRef::Direct => PolicyMemberV1::Direct,
        TargetRef::Reject => PolicyMemberV1::Reject,
        TargetRef::Group(name) => PolicyMemberV1::Group(name.clone()),
    }
}

fn target_name(target: &TargetRef) -> &str {
    match target {
        TargetRef::Direct => "DIRECT",
        TargetRef::Reject => "REJECT",
        TargetRef::Group(name) => name,
    }
}

struct OmittedEvidenceAccumulator {
    policy: &'static ProfilePolicy,
    output: HashedWire,
    expected_entry_count: usize,
    entry_count: usize,
    distribution: Vec<usize>,
}

impl OmittedEvidenceAccumulator {
    fn new(profile: ProfileKind, config_fingerprint: [u8; 32]) -> Result<Self, Acl4SsrRenderError> {
        let policy = profile_policy(profile).ok_or(Acl4SsrRenderError::Internal)?;
        let expected_total = policy
            .omitted_distribution
            .iter()
            .try_fold(0_usize, |total, expected| total.checked_add(expected.count))
            .ok_or(Acl4SsrRenderError::Internal)?;
        let mut output = HashedWire::new();
        encode_lp16_ascii(&mut output, b"sub-hub/OmittedRuleEvidence/SHA-256")
            .map_err(|()| Acl4SsrRenderError::ConversionLimit)?;
        output
            .write(&1_u16.to_be_bytes())
            .and_then(|()| output.write_byte(1))
            .and_then(|()| output.write(&config_fingerprint))
            .and_then(|()| encode_count(&mut output, expected_total))
            .map_err(|()| Acl4SsrRenderError::ConversionLimit)?;
        Ok(Self {
            policy,
            output,
            expected_entry_count: expected_total,
            entry_count: 0,
            distribution: vec![0; policy.omitted_distribution.len()],
        })
    }

    fn push(
        &mut self,
        remote_source_ordinal: u32,
        url_regex_ordinal: u32,
        target: &TargetRef,
        pattern: &str,
    ) -> Result<(), Acl4SsrRenderError> {
        self.entry_count = self
            .entry_count
            .checked_add(1)
            .ok_or(Acl4SsrRenderError::ConversionLimit)?;
        if let Some(index) = self
            .policy
            .omitted_distribution
            .iter()
            .position(|expected| expected.target == target_name(target))
        {
            self.distribution[index] = self.distribution[index]
                .checked_add(1)
                .ok_or(Acl4SsrRenderError::ConversionLimit)?;
        }
        self.output
            .write_byte(1)
            .and_then(|()| self.output.write(&remote_source_ordinal.to_be_bytes()))
            .and_then(|()| self.output.write(&url_regex_ordinal.to_be_bytes()))
            .and_then(|()| encode_target(&mut self.output, target))
            .and_then(|()| encode_text(&mut self.output, pattern))
            .map_err(|()| Acl4SsrRenderError::ConversionLimit)
    }

    fn finish(self) -> Result<usize, Acl4SsrRenderError> {
        let distribution_matches = self
            .policy
            .omitted_distribution
            .iter()
            .zip(&self.distribution)
            .all(|(expected, observed)| expected.count == *observed);
        if self.entry_count != self.expected_entry_count || !distribution_matches {
            return Err(Acl4SsrRenderError::UnsupportedRule);
        }
        let (preimage_bytes, digest) = self
            .output
            .finish()
            .map_err(|()| Acl4SsrRenderError::ConversionLimit)?;
        if preimage_bytes != self.policy.evidence_preimage_bytes
            || digest != self.policy.evidence_digest
        {
            return Err(Acl4SsrRenderError::UnsupportedRule);
        }
        Ok(self.entry_count)
    }
}

#[cfg(test)]
fn encode_omitted_evidence(
    config_fingerprint: [u8; 32],
    entries: &[OmittedEvidenceEntry],
) -> Result<Vec<u8>, ()> {
    let mut output = Vec::new();
    encode_lp16_ascii(&mut output, b"sub-hub/OmittedRuleEvidence/SHA-256")?;
    output.extend_from_slice(&1_u16.to_be_bytes());
    output.push(1);
    output.extend_from_slice(&config_fingerprint);
    encode_count(&mut output, entries.len())?;
    for entry in entries {
        output.push(1);
        output.extend_from_slice(&entry.remote_source_ordinal.to_be_bytes());
        output.extend_from_slice(&entry.url_regex_ordinal.to_be_bytes());
        encode_target(&mut output, &entry.target)?;
        encode_text(&mut output, &entry.pattern)?;
    }
    Ok(output)
}

fn expand_groups(
    groups: &[Group],
    node_names: &[&str],
) -> Result<(Vec<CompiledGroupV1>, usize), Acl4SsrRenderError> {
    let mut output = Vec::with_capacity(groups.len());
    let mut total_expanded_members = 0_usize;
    let mut total_expanded_member_bytes = 0_usize;
    let mut empty_count = 0_usize;
    for group in groups {
        let mut members = Vec::new();
        let mut seen = BTreeSet::new();
        for member in &group.members {
            match member {
                GroupMember::LiteralRef(target) => {
                    let member = policy_member(target);
                    if seen.insert(member.as_symbol().to_owned()) {
                        push_expanded_member(
                            &mut members,
                            member,
                            &mut total_expanded_members,
                            &mut total_expanded_member_bytes,
                        )?;
                    }
                }
                GroupMember::NodeRegex(regex) => {
                    for node_name in node_names {
                        if regex.compiled.is_match(node_name)
                            && seen.insert((*node_name).to_owned())
                        {
                            push_expanded_member(
                                &mut members,
                                PolicyMemberV1::Node((*node_name).to_owned()),
                                &mut total_expanded_members,
                                &mut total_expanded_member_bytes,
                            )?;
                        }
                    }
                }
            }
        }
        if members.is_empty() {
            empty_count += 1;
            push_expanded_member(
                &mut members,
                PolicyMemberV1::Reject,
                &mut total_expanded_members,
                &mut total_expanded_member_bytes,
            )?;
            output.push(CompiledGroupV1::new(
                group.name.clone(),
                GroupStrategyV1::Select,
                members,
            ));
            continue;
        }
        let strategy = compiled_strategy(group)?;
        output.push(CompiledGroupV1::new(group.name.clone(), strategy, members));
    }
    Ok((output, empty_count))
}

fn compiled_strategy(group: &Group) -> Result<GroupStrategyV1, Acl4SsrRenderError> {
    if group.kind == GroupType::Select {
        return Ok(GroupStrategyV1::Select);
    }
    let payload = group.payload.as_ref().ok_or(Acl4SsrRenderError::Internal)?;
    Ok(match group.kind {
        GroupType::Select => GroupStrategyV1::Select,
        GroupType::UrlTest => GroupStrategyV1::UrlTest {
            url: payload.health.declared.clone(),
            interval: payload.probe.interval,
            tolerance: payload.probe.tolerance,
        },
        GroupType::Fallback => GroupStrategyV1::Fallback {
            url: payload.health.declared.clone(),
            interval: payload.probe.interval,
        },
        GroupType::LoadBalance => GroupStrategyV1::LoadBalance {
            url: payload.health.declared.clone(),
            interval: payload.probe.interval,
        },
    })
}

fn push_expanded_member(
    output: &mut Vec<PolicyMemberV1>,
    member: PolicyMemberV1,
    total: &mut usize,
    total_bytes: &mut usize,
) -> Result<(), Acl4SsrRenderError> {
    if *total == MAX_EXPANDED_MEMBERS {
        return Err(Acl4SsrRenderError::ConversionLimit);
    }
    *total += 1;
    *total_bytes = total_bytes
        .checked_add(member.as_symbol().len())
        .ok_or(Acl4SsrRenderError::ConversionLimit)?;
    if *total_bytes > MAX_MIHOMO_OUTPUT_BYTES {
        return Err(Acl4SsrRenderError::ConversionLimit);
    }
    output.push(member);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::{
        Config, PROFILE_POLICIES, ParsedRuleSetFlights, ProfileKind, encode_config_fingerprint,
        lookup_profile, sha256,
    };

    #[test]
    fn single_flight_rule_set_body_is_parsed_once_and_replayed() {
        let bodies = [&b"DOMAIN,example.test\n"[..]];
        let mut entries = [None];
        let mut replay = ParsedRuleSetFlights::new(&bodies, &mut entries);
        let mut rule_count = 0;

        let entries = replay.entries(0, &mut rule_count).unwrap();
        assert_eq!(entries.len(), 1);
        let entries = replay.entries(0, &mut rule_count).unwrap();
        assert_eq!(entries.len(), 1);

        assert_eq!(replay.parse_misses, 1);
        assert_eq!(rule_count, 2);
    }

    #[test]
    fn fingerprint_prefix_matches_the_independent_golden() {
        let mut prefix = Vec::new();
        super::encode_lp16_ascii(&mut prefix, b"sub-hub/ConfigFingerprint/SHA-256").unwrap();
        prefix.extend_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            hex(sha256::digest(&prefix)),
            "221bc2794e3eabd2ba924d67c977df84acd0cf99fa89cdf4b7b91a763fd5a138"
        );
    }

    #[test]
    fn fingerprint_ignores_comments_and_line_endings_but_not_directive_order() {
        let first = Config::parse(
            b"[custom]\n\
              enable_rule_generator=true\n\
              custom_proxy_group=P`select`.*\n\
              ruleset=P,[]FINAL\n\
              overwrite_original_rules=true\n",
        )
        .unwrap();
        let equivalent = Config::parse(
            b"\xef\xbb\xbf [custom]\r\n\
              # comment\r\n\
              enable_rule_generator=true\r\n\
              custom_proxy_group=P`select`.*\r\n\
              ruleset=P,[]FINAL\r\n\
              overwrite_original_rules=true\r\n",
        )
        .unwrap();
        assert_eq!(
            encode_config_fingerprint(&first).unwrap(),
            encode_config_fingerprint(&equivalent).unwrap()
        );
        let reordered = Config::parse(
            b"[custom]\n\
              overwrite_original_rules=true\n\
              custom_proxy_group=P`select`.*\n\
              ruleset=P,[]FINAL\n\
              enable_rule_generator=true\n",
        )
        .unwrap();
        assert_ne!(
            encode_config_fingerprint(&first).unwrap(),
            encode_config_fingerprint(&reordered).unwrap()
        );
    }

    #[test]
    fn fingerprint_wire_matches_a_hand_framed_cross_implementation_vector() {
        let config = Config::parse(
            b"[custom]\n\
              enable_rule_generator=true\n\
              custom_proxy_group=P`select`[]DIRECT\n\
              ruleset=P,[]FINAL\n\
              overwrite_original_rules=true\n",
        )
        .unwrap();
        let wire = encode_config_fingerprint(&config).unwrap();
        assert_eq!(
            wire,
            decode_hex(concat!(
                "00217375622d6875622f436f6e66696746696e6765727072696e742f5348412d3235360001",
                "0100000004",
                "0301",
                "02000000015001000000010101",
                "0103000000015003",
                "0401",
            )),
        );
        assert_eq!(
            hex(sha256::digest(&wire)),
            "db0f738f07e836c2b39c6a5d3fc9b006a39406e0172339cc025c9a0209378fcd"
        );
    }

    #[test]
    fn omitted_evidence_wire_matches_a_hand_framed_cross_implementation_vector() {
        let config_digest = std::array::from_fn(|index| u8::try_from(index).unwrap());
        let entries = [super::OmittedEvidenceEntry {
            remote_source_ordinal: 2,
            url_regex_ordinal: 3,
            target: super::TargetRef::Direct,
            pattern: "a,b".to_owned(),
        }];
        let wire = super::encode_omitted_evidence(config_digest, &entries).unwrap();
        assert_eq!(
            wire,
            decode_hex(concat!(
                "00237375622d6875622f4f6d697474656452756c6545766964656e63652f5348412d3235360001",
                "01",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "00000001",
                "01000000020000000301",
                "00000003612c62",
            )),
        );
        assert_eq!(
            hex(sha256::digest(&wire)),
            "b203dc281d264aade0d23c97a65a51905f3cd8eeb68c7dd8448753a9dd1525f1"
        );
    }

    #[test]
    fn promoted_profile_policy_requires_both_exact_length_and_digest() {
        assert_eq!(PROFILE_POLICIES.len(), 2);
        for policy in PROFILE_POLICIES {
            assert_eq!(
                lookup_profile(policy.config_preimage_bytes, &policy.config_digest),
                Some(policy.kind)
            );
            assert_eq!(
                lookup_profile(policy.config_preimage_bytes + 1, &policy.config_digest),
                None
            );
            let mut changed_digest = policy.config_digest;
            changed_digest[31] ^= 1;
            assert_eq!(
                lookup_profile(policy.config_preimage_bytes, &changed_digest),
                None
            );
        }
        assert_eq!(PROFILE_POLICIES[0].kind, ProfileKind::Online);
        assert_eq!(PROFILE_POLICIES[1].kind, ProfileKind::Full);
    }

    fn hex(bytes: [u8; 32]) -> String {
        let mut output = String::with_capacity(64);
        for byte in bytes {
            write!(&mut output, "{byte:02x}").unwrap();
        }
        output
    }

    fn decode_hex(input: &str) -> Vec<u8> {
        input
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let pair = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(pair, 16).unwrap()
            })
            .collect()
    }
}
