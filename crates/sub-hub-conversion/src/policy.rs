use std::collections::BTreeSet;
use std::fmt;

use url::{Host, Url};

use crate::node::ProxyNode;

pub(crate) const BUILTIN_AUTO_PROBE_URL: &str = "https://www.gstatic.com/generate_204";
pub(crate) const BUILTIN_AUTO_PROBE_INTERVAL: u32 = 300;

#[derive(Clone)]
pub(crate) struct UnexpandedSubscriptionV1 {
    name: String,
    url: String,
}

impl UnexpandedSubscriptionV1 {
    pub(crate) fn new(name: String, url: String) -> Self {
        Self { name, url }
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn url(&self) -> &str {
        &self.url
    }
}

#[derive(Clone)]
pub(crate) struct RemoteRuleSetRefV1 {
    name: String,
    url: String,
    target: PolicyMemberV1,
}

impl RemoteRuleSetRefV1 {
    pub(crate) fn new(name: String, url: String, target: PolicyMemberV1) -> Self {
        Self { name, url, target }
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn url(&self) -> &str {
        &self.url
    }

    pub(crate) fn target(&self) -> &PolicyMemberV1 {
        &self.target
    }
}

pub(crate) struct CompiledPolicyV1 {
    groups: Vec<CompiledGroupV1>,
    rules: Vec<CompiledRuleV1>,
    empty_groups: u8,
    unexpanded_subscriptions: Vec<UnexpandedSubscriptionV1>,
    remote_rule_sets: Vec<RemoteRuleSetRefV1>,
}

impl CompiledPolicyV1 {
    pub(crate) fn with_remotes(
        groups: Vec<CompiledGroupV1>,
        rules: Vec<CompiledRuleV1>,
        empty_groups: u8,
        unexpanded_subscriptions: Vec<UnexpandedSubscriptionV1>,
        remote_rule_sets: Vec<RemoteRuleSetRefV1>,
    ) -> Self {
        Self {
            groups,
            rules,
            empty_groups,
            unexpanded_subscriptions,
            remote_rule_sets,
        }
    }

    pub(crate) fn groups(&self) -> &[CompiledGroupV1] {
        &self.groups
    }

    pub(crate) fn rules(&self) -> &[CompiledRuleV1] {
        &self.rules
    }

    pub(crate) const fn empty_groups(&self) -> u8 {
        self.empty_groups
    }

    pub(crate) fn unexpanded_subscriptions(&self) -> &[UnexpandedSubscriptionV1] {
        &self.unexpanded_subscriptions
    }

    pub(crate) fn remote_rule_sets(&self) -> &[RemoteRuleSetRefV1] {
        &self.remote_rule_sets
    }
}

impl fmt::Debug for CompiledPolicyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompiledPolicyV1")
            .field("group_count", &self.groups.len())
            .field("rule_count", &self.rules.len())
            .field("empty_groups", &self.empty_groups)
            .field(
                "unexpanded_subscription_count",
                &self.unexpanded_subscriptions.len(),
            )
            .field("remote_rule_set_count", &self.remote_rule_sets.len())
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

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum PolicyMemberV1 {
    Direct,
    Reject,
    Group(String),
    Node(String),
    /// ACL4SSR `.*` when subscriptions stay as client remote refs.
    UnexpandedAll,
}

impl PolicyMemberV1 {
    /// Target-neutral size used by compile-time output budgets.
    ///
    /// Bounds every client spelling of Direct/Reject (`DIRECT` / `direct` /
    /// `REJECT` / `reject`) without baking one adapter's token into the IR.
    pub(crate) fn budget_bytes(&self) -> usize {
        match self {
            Self::Direct | Self::Reject | Self::UnexpandedAll => 6,
            Self::Group(name) | Self::Node(name) => name.len(),
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
            Self::UnexpandedAll => "UnexpandedAll",
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

    /// Target-neutral size used by compile-time output budgets.
    ///
    /// Counts matcher payload, policy symbol, and a fixed record overhead that
    /// bounds every client spelling. It is not a Mihomo CSV length.
    pub(crate) fn structural_budget_bytes(&self) -> usize {
        const RECORD_OVERHEAD: usize = 16;
        let payload = match &self.matcher {
            RuleMatcherV1::Domain(value)
            | RuleMatcherV1::DomainSuffix(value)
            | RuleMatcherV1::DomainKeyword(value)
            | RuleMatcherV1::ProcessName(value)
            | RuleMatcherV1::UrlRegex(value) => value.len(),
            RuleMatcherV1::IpCidr {
                value, no_resolve, ..
            } => value.len() + if *no_resolve { 10 } else { 0 },
            RuleMatcherV1::GeoIpCn => 2,
            RuleMatcherV1::Match => 0,
        };
        RECORD_OVERHEAD
            .saturating_add(payload)
            .saturating_add(self.target.budget_bytes())
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

/// Names each unexpanded HTTPS source from its canonical DNS host. The first
/// occurrence of a host keeps the bare host; later repeats get `-2`, `-3`, …
/// `reserved` (policy groups plus Direct/Reject) is occupied first so a host
/// that collides is suffixed instead of clashing in the client.
pub(crate) fn unexpanded_from_urls(
    urls: &[String],
    reserved: &[&str],
) -> Vec<UnexpandedSubscriptionV1> {
    let mut used = BTreeSet::new();
    for name in reserved
        .iter()
        .copied()
        .chain(["DIRECT", "REJECT", "direct", "reject"])
    {
        used.insert(occupied_key(name));
    }
    urls.iter()
        .map(|url| {
            let name = allocate_unexpanded_name(host_label_from_https(url), &mut used);
            UnexpandedSubscriptionV1::new(name, url.clone())
        })
        .collect()
}

fn host_label_from_https(url: &str) -> String {
    const FALLBACK: &str = "sub-hub";
    let Ok(parsed) = Url::parse(url) else {
        return FALLBACK.to_owned();
    };
    if parsed.scheme() != "https" {
        return FALLBACK.to_owned();
    }
    let Some(Host::Domain(host)) = parsed.host() else {
        return FALLBACK.to_owned();
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        FALLBACK.to_owned()
    } else {
        first_bytes(&host, 128).to_owned()
    }
}

fn allocate_unexpanded_name(base: String, used: &mut BTreeSet<String>) -> String {
    if try_occupy(&base, used) {
        return base;
    }
    let root = first_bytes(&base, 122);
    for index in 2_u32..=99_999 {
        let candidate = format!("{root}-{index}");
        if try_occupy(&candidate, used) {
            return candidate;
        }
    }
    base
}

fn try_occupy(name: &str, used: &mut BTreeSet<String>) -> bool {
    let key = occupied_key(name);
    if used.contains(&key) {
        return false;
    }
    used.insert(key);
    true
}

fn occupied_key(name: &str) -> String {
    name.to_ascii_lowercase()
}

fn first_bytes(input: &str, max: usize) -> &str {
    if input.len() <= max {
        return input;
    }
    let mut end = max;
    while !input.is_char_boundary(end) {
        end -= 1;
    }
    &input[..end]
}

pub(crate) fn compile_builtin_policy_v1(
    named_nodes: &[&ProxyNode],
    unexpanded: &[UnexpandedSubscriptionV1],
) -> CompiledPolicyV1 {
    let node_members = named_nodes
        .iter()
        .map(|node| PolicyMemberV1::Node(node.name().as_str().to_owned()))
        .collect::<Vec<_>>();
    let mut auto_members = node_members.clone();
    let mut proxy_members = Vec::with_capacity(node_members.len() + 3);
    proxy_members.push(PolicyMemberV1::Group("AUTO".to_owned()));
    proxy_members.extend(node_members);
    if !unexpanded.is_empty() {
        proxy_members.push(PolicyMemberV1::UnexpandedAll);
        auto_members.push(PolicyMemberV1::UnexpandedAll);
    }
    proxy_members.push(PolicyMemberV1::Direct);

    CompiledPolicyV1::with_remotes(
        vec![
            CompiledGroupV1::new("PROXY".to_owned(), GroupStrategyV1::Select, proxy_members),
            CompiledGroupV1::new(
                "AUTO".to_owned(),
                GroupStrategyV1::UrlTest {
                    url: BUILTIN_AUTO_PROBE_URL.to_owned(),
                    interval: BUILTIN_AUTO_PROBE_INTERVAL,
                    tolerance: None,
                },
                auto_members,
            ),
        ],
        vec![CompiledRuleV1::new(
            RuleMatcherV1::Match,
            PolicyMemberV1::Group("PROXY".to_owned()),
        )],
        0,
        unexpanded.to_vec(),
        Vec::new(),
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
        let policy = compile_builtin_policy_v1(&nodes, &[]);
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

    #[test]
    fn unexpanded_names_use_host_and_suffix_only_on_repeat() {
        let named = super::unexpanded_from_urls(
            &[
                "https://panel.example/a".to_owned(),
                "https://other.example/b".to_owned(),
                "https://panel.example/c?token=one".to_owned(),
            ],
            &[],
        );
        assert_eq!(named[0].name(), "panel.example");
        assert_eq!(named[1].name(), "other.example");
        assert_eq!(named[2].name(), "panel.example-2");
        assert!(
            !named[2].name().contains("token"),
            "path and query must not enter the name"
        );
    }

    #[test]
    fn unexpanded_names_suffix_when_the_host_matches_a_reserved_group() {
        let named = super::unexpanded_from_urls(
            &[
                "https://proxy.example/sub".to_owned(),
                "https://proxy/sub".to_owned(),
            ],
            &["PROXY", "AUTO"],
        );
        assert_eq!(named[0].name(), "proxy.example");
        assert_eq!(named[1].name(), "proxy-2");
    }
}
