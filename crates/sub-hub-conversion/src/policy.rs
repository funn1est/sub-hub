use std::fmt;

use crate::node::ProxyNode;

pub(crate) const BUILTIN_AUTO_PROBE_URL: &str = "https://www.gstatic.com/generate_204";
pub(crate) const BUILTIN_AUTO_PROBE_INTERVAL: u32 = 300;

pub(crate) struct CompiledPolicyV1 {
    groups: Vec<CompiledGroupV1>,
    rules: Vec<CompiledRuleV1>,
    report: PolicyReportV1,
}

impl CompiledPolicyV1 {
    pub(crate) fn new(
        groups: Vec<CompiledGroupV1>,
        rules: Vec<CompiledRuleV1>,
        report: PolicyReportV1,
    ) -> Self {
        Self {
            groups,
            rules,
            report,
        }
    }

    pub(crate) fn groups(&self) -> &[CompiledGroupV1] {
        &self.groups
    }

    pub(crate) fn rules(&self) -> &[CompiledRuleV1] {
        &self.rules
    }

    pub(crate) const fn report(&self) -> PolicyReportV1 {
        self.report
    }
}

impl fmt::Debug for CompiledPolicyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledPolicyV1")
            .field("group_count", &self.groups.len())
            .field("rule_count", &self.rules.len())
            .field("report", &self.report)
            .finish()
    }
}

pub(crate) struct CompiledGroupV1 {
    name: String,
    strategy: GroupStrategyV1,
    members: Vec<PolicyMemberV1>,
}

impl CompiledGroupV1 {
    pub(crate) fn new(
        name: String,
        strategy: GroupStrategyV1,
        members: Vec<PolicyMemberV1>,
    ) -> Self {
        Self {
            name,
            strategy,
            members,
        }
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) const fn strategy(&self) -> &GroupStrategyV1 {
        &self.strategy
    }

    pub(crate) fn members(&self) -> &[PolicyMemberV1] {
        &self.members
    }
}

impl fmt::Debug for CompiledGroupV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledGroupV1")
            .field("strategy", &self.strategy)
            .field("member_count", &self.members.len())
            .finish_non_exhaustive()
    }
}

pub(crate) enum GroupStrategyV1 {
    Select,
    UrlTest {
        url: String,
        interval: u32,
        tolerance: Option<u16>,
    },
    Fallback {
        url: String,
        interval: u32,
    },
    LoadBalance {
        url: String,
        interval: u32,
    },
}

impl fmt::Debug for GroupStrategyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Select => formatter.write_str("Select"),
            Self::UrlTest {
                interval,
                tolerance,
                ..
            } => formatter
                .debug_struct("UrlTest")
                .field("interval", interval)
                .field("tolerance", tolerance)
                .finish_non_exhaustive(),
            Self::Fallback { interval, .. } => formatter
                .debug_struct("Fallback")
                .field("interval", interval)
                .finish_non_exhaustive(),
            Self::LoadBalance { interval, .. } => formatter
                .debug_struct("LoadBalance")
                .field("interval", interval)
                .finish_non_exhaustive(),
        }
    }
}

#[derive(Clone)]
pub(crate) enum PolicyMemberV1 {
    Direct,
    Reject,
    Group(String),
    Node(String),
}

impl PolicyMemberV1 {
    pub(crate) fn as_symbol(&self) -> &str {
        match self {
            Self::Direct => "DIRECT",
            Self::Reject => "REJECT",
            Self::Group(name) | Self::Node(name) => name,
        }
    }
}

impl fmt::Debug for PolicyMemberV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Direct => "Direct",
            Self::Reject => "Reject",
            Self::Group(_) => "Group",
            Self::Node(_) => "Node",
        })
    }
}

pub(crate) struct CompiledRuleV1 {
    matcher: RuleMatcherV1,
    target: PolicyMemberV1,
}

impl CompiledRuleV1 {
    pub(crate) fn new(matcher: RuleMatcherV1, target: PolicyMemberV1) -> Self {
        Self { matcher, target }
    }

    pub(crate) const fn matcher(&self) -> &RuleMatcherV1 {
        &self.matcher
    }

    pub(crate) const fn target(&self) -> &PolicyMemberV1 {
        &self.target
    }
}

impl fmt::Debug for CompiledRuleV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledRuleV1")
            .field("matcher", &self.matcher)
            .field("target", &self.target)
            .finish()
    }
}

pub(crate) enum RuleMatcherV1 {
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    ProcessName(String),
    IpCidr {
        value: String,
        version: IpVersion,
        no_resolve: bool,
    },
    GeoIpCn,
    Match,
    UrlRegex(String),
}

impl fmt::Debug for RuleMatcherV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain(_) => formatter.write_str("Domain"),
            Self::DomainSuffix(_) => formatter.write_str("DomainSuffix"),
            Self::DomainKeyword(_) => formatter.write_str("DomainKeyword"),
            Self::ProcessName(_) => formatter.write_str("ProcessName"),
            Self::IpCidr {
                version,
                no_resolve,
                ..
            } => formatter
                .debug_struct("IpCidr")
                .field("version", version)
                .field("no_resolve", no_resolve)
                .finish_non_exhaustive(),
            Self::GeoIpCn => formatter.write_str("GeoIpCn"),
            Self::Match => formatter.write_str("Match"),
            Self::UrlRegex(_) => formatter.write_str("UrlRegex"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IpVersion {
    V4,
    V6,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct PolicyReportV1 {
    pub(crate) omitted_url_regex: u8,
    pub(crate) empty_groups: u8,
    pub(crate) ignored_legacy_probe_hints: u8,
}

pub(crate) fn compile_builtin_policy_v1(named_nodes: &[&ProxyNode]) -> CompiledPolicyV1 {
    let node_members = named_nodes
        .iter()
        .map(|node| PolicyMemberV1::Node(node.name().as_str().to_owned()))
        .collect::<Vec<_>>();
    let mut proxy_members = Vec::with_capacity(node_members.len() + 2);
    proxy_members.push(PolicyMemberV1::Group("AUTO".to_owned()));
    proxy_members.extend(node_members.iter().cloned());
    proxy_members.push(PolicyMemberV1::Direct);

    CompiledPolicyV1::new(
        vec![
            CompiledGroupV1::new("PROXY".to_owned(), GroupStrategyV1::Select, proxy_members),
            CompiledGroupV1::new(
                "AUTO".to_owned(),
                GroupStrategyV1::UrlTest {
                    url: BUILTIN_AUTO_PROBE_URL.to_owned(),
                    interval: BUILTIN_AUTO_PROBE_INTERVAL,
                    tolerance: None,
                },
                node_members,
            ),
        ],
        vec![CompiledRuleV1::new(
            RuleMatcherV1::Match,
            PolicyMemberV1::Group("PROXY".to_owned()),
        )],
        PolicyReportV1::default(),
    )
}

#[cfg(test)]
mod tests {
    use super::compile_builtin_policy_v1;
    use crate::node_name::{NamedNodeOccurrence, resolve_node_names};
    use crate::subscription_source::parse_subscription_sources;

    #[test]
    fn builtin_policy_debug_omits_node_names_and_probe_urls() {
        let parsed = parse_subscription_sources(&[
            &b"vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443#SecretName"[..],
        ])
        .expect("valid source");
        let named = resolve_node_names(parsed, &["PROXY", "AUTO"]).expect("names");
        let nodes = named
            .occurrences()
            .iter()
            .filter_map(|occurrence| match occurrence {
                NamedNodeOccurrence::Accepted { node, .. } => Some(node.as_ref()),
                NamedNodeOccurrence::Rejected { .. } => None,
            })
            .collect::<Vec<_>>();
        let policy = compile_builtin_policy_v1(&nodes);
        let debug = format!("{policy:?}");
        assert!(
            !debug.contains("SecretName"),
            "node names must not appear in policy debug: {debug}"
        );
        assert!(
            !debug.contains("gstatic"),
            "probe URLs must not appear in policy debug: {debug}"
        );
    }
}
