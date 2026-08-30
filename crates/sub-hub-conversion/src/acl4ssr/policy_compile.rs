//! Stage 3: Rule Set parsing, rule materialization, and policy compilation.
//!
//! Turns loaded Rule Set bodies plus the resolved config into the
//! crate-internal `CompiledPolicyV1` inputs (rules and expanded groups),
//! enforcing the request-level rule and expansion budgets.

use std::{collections::BTreeSet, net::IpAddr};

use super::{
    Acl4SsrRenderError,
    ini::{
        Config, Directive, Group, GroupMember, GroupType, RuleSource, TargetRef, ascii_outer_trim,
    },
};
use crate::{
    MAX_RULE_SET_BYTES, UniqueFlightFillV1,
    policy::{
        CompiledGroupV1, CompiledPolicyV1, CompiledRuleV1, GroupStrategyV1, IpVersion,
        PolicyMemberV1, PolicyReportV1, RuleMatcherV1,
    },
    render::MAX_OUTPUT_BYTES,
    subscription_source::has_bare_carriage_return,
};
const MAX_EXPANDED_MEMBERS: usize = 200_000;
const MAX_RULES: usize = 200_000;
const MAX_REGEX_EVALUATIONS: usize = 2_000_000;

pub(super) enum RuleEntry {
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
pub(super) enum DomainRuleType {
    Domain,
    DomainSuffix,
    DomainKeyword,
    ProcessName,
}

#[derive(Clone, Copy)]
pub(super) enum CidrRuleType {
    V4,
    V6,
}

pub(super) fn compile_acl4ssr_policy(
    groups: &[Group],
    node_names: &[&str],
    rules: Vec<CompiledRuleV1>,
    unexpanded: Vec<crate::policy::UnexpandedSubscriptionV1>,
    remote_rule_sets: Vec<crate::policy::RemoteRuleSetRefV1>,
) -> Result<CompiledPolicyV1, Acl4SsrRenderError> {
    let regex_count = groups
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
    let (compiled_groups, empty_group_count) =
        expand_groups(groups, node_names, !unexpanded.is_empty())?;
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
    Ok(CompiledPolicyV1::with_remotes(
        compiled_groups,
        rules,
        PolicyReportV1 {
            empty_groups: u8::try_from(empty_group_count)
                .map_err(|_| Acl4SsrRenderError::Internal)?,
            ignored_legacy_probe_hints: u8::try_from(ignored_legacy_probe_hint_count)
                .map_err(|_| Acl4SsrRenderError::Internal)?,
        },
        unexpanded,
        remote_rule_sets,
    ))
}

pub(super) fn validate_rule_sets(
    config: &Config,
    unique_bodies: &[&[u8]],
    fill: &UniqueFlightFillV1,
    parsed_rule_sets: &mut [Option<Vec<RuleEntry>>],
    occurrence_exclusive: usize,
) -> Result<(), Acl4SsrRenderError> {
    consume_rule_sets(
        config,
        unique_bodies,
        fill,
        parsed_rule_sets,
        occurrence_exclusive,
        false,
    )
    .map(|_| ())
}

pub(super) fn materialize_rule_sets(
    config: &Config,
    unique_bodies: &[&[u8]],
    fill: &UniqueFlightFillV1,
    parsed_rule_sets: &mut [Option<Vec<RuleEntry>>],
    occurrence_exclusive: usize,
) -> Result<Vec<CompiledRuleV1>, Acl4SsrRenderError> {
    consume_rule_sets(
        config,
        unique_bodies,
        fill,
        parsed_rule_sets,
        occurrence_exclusive,
        true,
    )
}

fn consume_rule_sets(
    config: &Config,
    unique_bodies: &[&[u8]],
    fill: &UniqueFlightFillV1,
    parsed_rule_sets: &mut [Option<Vec<RuleEntry>>],
    occurrence_exclusive: usize,
    collect: bool,
) -> Result<Vec<CompiledRuleV1>, Acl4SsrRenderError> {
    if occurrence_exclusive > fill.occurrence_count() || unique_bodies.len() > fill.flight_count() {
        return Err(Acl4SsrRenderError::RuleSetAlignment);
    }
    let mut rules = Vec::new();
    let mut rendered_bytes = 0_usize;
    let mut parsed = ParsedRuleSetFlights::new(unique_bodies, parsed_rule_sets);
    let mut remote_index = 0_usize;
    let mut rule_count = 0_usize;
    for directive in &config.directives {
        let Directive::Ruleset { target, source } = directive;
        match source {
            RuleSource::Remote(_) => {
                if remote_index == occurrence_exclusive {
                    return Ok(rules);
                }
                let flight = fill
                    .flight_of(remote_index)
                    .ok_or(Acl4SsrRenderError::RuleSetAlignment)?;
                let entries = parsed.entries(flight.get(), &mut rule_count)?;
                if collect {
                    for entry in entries {
                        push_compiled_rule(
                            &mut rules,
                            compiled_rule(entry, target),
                            &mut rendered_bytes,
                        )?;
                    }
                }
                remote_index += 1;
            }
            RuleSource::GeoIpCn => {
                increment_rule_count(&mut rule_count)?;
                if collect {
                    push_compiled_rule(
                        &mut rules,
                        CompiledRuleV1::new(RuleMatcherV1::GeoIpCn, policy_member(target)),
                        &mut rendered_bytes,
                    )?;
                }
            }
            RuleSource::Final => {
                increment_rule_count(&mut rule_count)?;
                if collect {
                    push_compiled_rule(
                        &mut rules,
                        CompiledRuleV1::new(RuleMatcherV1::Match, policy_member(target)),
                        &mut rendered_bytes,
                    )?;
                }
            }
        }
    }
    if collect && remote_index != fill.occurrence_count() {
        return Err(Acl4SsrRenderError::RuleSetAlignment);
    }
    Ok(rules)
}

pub(super) struct ParsedRuleSetFlights<'a> {
    bodies: &'a [&'a [u8]],
    entries: &'a mut [Option<Vec<RuleEntry>>],
    #[cfg(test)]
    parse_misses: usize,
}

impl<'a> ParsedRuleSetFlights<'a> {
    pub(super) fn new(bodies: &'a [&'a [u8]], entries: &'a mut [Option<Vec<RuleEntry>>]) -> Self {
        Self {
            bodies,
            entries,
            #[cfg(test)]
            parse_misses: 0,
        }
    }

    pub(super) fn entries(
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

pub(super) fn increment_rule_count(count: &mut usize) -> Result<(), Acl4SsrRenderError> {
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
        .checked_add(rule.structural_budget_bytes())
        .ok_or(Acl4SsrRenderError::ConversionLimit)?;
    if *rendered_bytes > MAX_OUTPUT_BYTES {
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
        RuleEntry::UrlRegex(pattern) => RuleMatcherV1::UrlRegex(pattern.clone()),
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

fn expand_groups(
    groups: &[Group],
    node_names: &[&str],
    has_unexpanded: bool,
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
                    if seen.insert(member.clone()) {
                        push_expanded_member(
                            &mut members,
                            member,
                            &mut total_expanded_members,
                            &mut total_expanded_member_bytes,
                        )?;
                    }
                }
                GroupMember::NodeRegex(regex) => {
                    if has_unexpanded && node_names.is_empty() {
                        let member = PolicyMemberV1::UnexpandedAll;
                        if seen.insert(member.clone()) {
                            push_expanded_member(
                                &mut members,
                                member,
                                &mut total_expanded_members,
                                &mut total_expanded_member_bytes,
                            )?;
                        }
                    }
                    for node_name in node_names {
                        let member = PolicyMemberV1::Node((*node_name).to_owned());
                        if regex.compiled.is_match(node_name) && seen.insert(member.clone()) {
                            push_expanded_member(
                                &mut members,
                                member,
                                &mut total_expanded_members,
                                &mut total_expanded_member_bytes,
                            )?;
                        }
                    }
                    if has_unexpanded && !node_names.is_empty() {
                        let member = PolicyMemberV1::UnexpandedAll;
                        if seen.insert(member.clone()) {
                            push_expanded_member(
                                &mut members,
                                member,
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
        .checked_add(member.budget_bytes())
        .ok_or(Acl4SsrRenderError::ConversionLimit)?;
    if *total_bytes > MAX_OUTPUT_BYTES {
        return Err(Acl4SsrRenderError::ConversionLimit);
    }
    output.push(member);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::ParsedRuleSetFlights;

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
}
