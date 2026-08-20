//! Stage 1: strict ACL4SSR INI parsing and reference resolution.
//!
//! Produces the resolved [`Config`] consumed by policy compilation. Grammar,
//! budgets, and reference validation live here; no I/O and no policy semantics.

use std::collections::{BTreeMap, BTreeSet};

use regex::{Regex, RegexBuilder};
use url::{Host as UrlHost, Url};

use super::Acl4SsrPreparationError;
use crate::node_name::{is_reserved_symbol, validate_group_name};

const MAX_CONFIG_BYTES: usize = 256 * 1024;
const MAX_GROUPS: usize = 128;
const MAX_MEMBERS_PER_GROUP: usize = 256;
const MAX_MEMBERS: usize = 4_096;
const MAX_REGEX_OCCURRENCES: usize = 256;
const MAX_REGEX_SOURCE_BYTES: usize = 1_024;
const MAX_REGEX_SOURCE_BYTES_TOTAL: usize = 64 * 1024;
const MAX_REGEX_COMPILED_BYTES: usize = 1024 * 1024;
const MAX_REGEX_DFA_BYTES: usize = 64 * 1024;

pub(super) struct Config {
    pub(super) directives: Vec<Directive>,
    pub(super) groups: Vec<Group>,
}

pub(super) enum Directive {
    Ruleset {
        target: TargetRef,
        source: RuleSource,
    },
    #[expect(
        dead_code,
        reason = "declaration-order slot; unused after fingerprint removal"
    )]
    Group(usize),
    #[expect(dead_code, reason = "parsed grammar; unused after fingerprint removal")]
    EnableRuleGenerator(bool),
    #[expect(dead_code, reason = "parsed grammar; unused after fingerprint removal")]
    OverwriteOriginalRules(bool),
}

#[derive(Clone)]
pub(super) enum TargetRef {
    Direct,
    Reject,
    Group(String),
}

pub(super) enum RuleSource {
    Remote(DeclaredUrl),
    GeoIpCn,
    Final,
}

pub(super) struct Group {
    pub(super) name: String,
    pub(super) kind: GroupType,
    pub(super) members: Vec<GroupMember>,
    pub(super) payload: Option<GroupPayload>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum GroupType {
    Select,
    UrlTest,
    Fallback,
    LoadBalance,
}

pub(super) enum GroupMember {
    LiteralRef(TargetRef),
    NodeRegex(NodeRegex),
}

pub(super) struct NodeRegex {
    #[expect(
        dead_code,
        reason = "regex source retained for parse fidelity; matching uses compiled"
    )]
    pub(super) source: String,
    pub(super) compiled: Regex,
}

pub(super) struct GroupPayload {
    pub(super) health: DeclaredUrl,
    pub(super) probe: Probe,
}

pub(super) struct Probe {
    pub(super) interval: u32,
    pub(super) tolerance: Option<u16>,
}

pub(super) struct DeclaredUrl {
    pub(super) declared: String,
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
    pub(super) fn parse(input: &[u8]) -> Result<Self, Acl4SsrPreparationError> {
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

pub(super) fn ascii_outer_trim(input: &str) -> &str {
    input.trim_matches([' ', '\t'])
}

pub(super) fn has_bare_carriage_return(input: &[u8]) -> bool {
    input
        .iter()
        .enumerate()
        .any(|(index, byte)| *byte == b'\r' && input.get(index + 1) != Some(&b'\n'))
}
