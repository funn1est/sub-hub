//! Keep-pass and closed adapter dispatch shared by every Client Format Adapter.
//!
//! This module owns Keep-pass, Target dispatch, the request-wide output limit,
//! and builtin (config-less) orchestration. Adapter spelling lives in
//! [`spelling`].

mod spelling;

pub(crate) use spelling::{
    encode_hex, hysteria2_has_gecko, hysteria2_has_pin, hysteria2_official_ports,
    hysteria2_singbox_ports, plain_group_tag, plain_node_tag, policy_member_token,
    probe_url_or_default, reality_public_key_base64, reality_short_id_hex, reject_when_empty,
    render_fingerprint, render_host_bracketed, render_host_plain, serialize_bounded,
    shadowsocks_method, shadowsocks_password, shared_probe_url,
};

use std::fmt;

use crate::{
    OutputTarget,
    egern::render_egern_from_policy_v1,
    loon::render_loon_from_policy_v1,
    mihomo::render_mihomo_from_policy_v1,
    node::ProxyNode,
    node_name::{NamedNodeOccurrence, NamedSubscriptionSources, resolve_node_names},
    policy::{CompiledPolicyV1, CompiledRuleV1, RuleMatcherV1, compile_builtin_policy_v1},
    quanx::render_quanx_from_policy_v1,
    singbox::render_singbox_from_policy_v1,
    skip::SkipCountsV1,
    subscription_source::ParsedSubscriptionSources,
};

/// Request-wide serialized output limit shared by every target adapter.
pub(crate) const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

/// Closed policy-render error shared by every `render_*_from_policy_v1` adapter entry.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdapterRenderError {
    NoValidNodes {
        capability_skips: u32,
        name_skips: u32,
    },
    OutputTooLarge {
        limit_bytes: usize,
    },
    Internal,
}

impl fmt::Debug for AdapterRenderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoValidNodes {
                capability_skips,
                name_skips,
            } => formatter
                .debug_struct("NoValidNodes")
                .field("capability_skips", capability_skips)
                .field("name_skips", name_skips)
                .finish(),
            Self::OutputTooLarge { limit_bytes } => formatter
                .debug_struct("OutputTooLarge")
                .field("limit_bytes", limit_bytes)
                .finish(),
            Self::Internal => formatter.write_str("Internal"),
        }
    }
}

/// A rendered target document plus per-target capability accounting.
pub(crate) struct RenderedTargetV1 {
    pub(crate) bytes: Vec<u8>,
    /// Nodes that were accepted upstream but dropped by this target's
    /// protocol/transport capability filter.
    pub(crate) capability_skips: u32,
    /// Parse-accepted nodes dropped because the allocated name is reserved
    /// or unrepresentable on this target.
    pub(crate) name_skips: u32,
    /// URL-REGEX matchers this adapter omitted from the document.
    pub(crate) omitted_url_regex: u8,
}

impl RenderedTargetV1 {
    pub(crate) fn from_parts(bytes: Vec<u8>, kept: &KeptNodes, omitted_url_regex: u8) -> Self {
        Self {
            bytes,
            capability_skips: kept.capability_skips,
            name_skips: kept.name_skips,
            omitted_url_regex,
        }
    }
}

impl fmt::Debug for RenderedTargetV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RenderedTargetV1")
            .field("bytes", &"[REDACTED]")
            .field("bytes_len", &self.bytes.len())
            .field("capability_skips", &self.capability_skips)
            .field("name_skips", &self.name_skips)
            .field("omitted_url_regex", &self.omitted_url_regex)
            .finish()
    }
}

/// Keep-pass document: target bytes plus skip and omitted URL-REGEX counts.
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

/// Closed Keep-pass failure shared by No remote config and Rule frontend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConversionRenderError {
    ConversionLimit,
    NoValidNodes { skips: SkipCountsV1 },
    Internal,
}

impl ConversionRenderError {
    fn from_adapter(error: AdapterRenderError, parse: u32) -> Self {
        match error {
            AdapterRenderError::NoValidNodes {
                capability_skips,
                name_skips,
            } => Self::NoValidNodes {
                skips: SkipCountsV1 {
                    parse,
                    capability: capability_skips,
                    name: name_skips,
                },
            },
            AdapterRenderError::OutputTooLarge { .. } => Self::ConversionLimit,
            AdapterRenderError::Internal => Self::Internal,
        }
    }
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

/// Signature shared by the five per-target policy renderers.
pub(crate) type RenderFromPolicyFn =
    fn(&[&ProxyNode], &CompiledPolicyV1, usize) -> Result<RenderedTargetV1, AdapterRenderError>;

/// Whether a named, parse-accepted node is kept by one target adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NodeKeep {
    Name,
    Capability,
}

/// Keep accounting for one target adapter's encode pass.
#[derive(Debug)]
pub(crate) struct KeptNodes {
    pub(crate) capability_skips: u32,
    pub(crate) name_skips: u32,
}

impl KeptNodes {
    /// Keep-pass accounting: Name and Capability skips.
    pub(crate) fn from_encoded<T>(
        results: impl IntoIterator<Item = Result<T, NodeKeep>>,
    ) -> Result<(Self, Vec<T>), AdapterRenderError> {
        let mut items = Vec::new();
        let mut capability_skips = 0_u32;
        let mut name_skips = 0_u32;
        for result in results {
            match result {
                Ok(item) => items.push(item),
                Err(NodeKeep::Name) => name_skips = name_skips.saturating_add(1),
                Err(NodeKeep::Capability) => capability_skips = capability_skips.saturating_add(1),
            }
        }
        if items.is_empty() {
            Err(AdapterRenderError::NoValidNodes {
                capability_skips,
                name_skips,
            })
        } else {
            Ok((
                Self {
                    capability_skips,
                    name_skips,
                },
                items,
            ))
        }
    }

    /// Encode once: keep classification is the encoder's failure mode.
    pub(crate) fn encode<'a, T>(
        named_nodes: &[&'a ProxyNode],
        mut encode: impl FnMut(&'a ProxyNode) -> Result<T, NodeKeep>,
    ) -> Result<(Self, Vec<T>), AdapterRenderError> {
        Self::from_encoded(named_nodes.iter().copied().map(&mut encode))
    }
}

/// Keep-pass plus tag unzip shared by text/JSON adapters that encode `(tag, item)`.
pub(crate) fn keep_tagged<'a, T>(
    named_nodes: &[&'a ProxyNode],
    encode: impl FnMut(&'a ProxyNode) -> Result<(String, T), NodeKeep>,
) -> Result<(KeptNodes, Vec<String>, Vec<T>), AdapterRenderError> {
    let (kept, encoded) = KeptNodes::encode(named_nodes, encode)?;
    let mut tags = Vec::with_capacity(encoded.len());
    let mut items = Vec::with_capacity(encoded.len());
    for (tag, item) in encoded {
        tags.push(tag);
        items.push(item);
    }
    Ok((kept, tags, items))
}

/// Tag then capability: the `encode_node` shape shared by text/JSON adapters.
pub(crate) fn keep_named<'a, T>(
    tag: Option<&'a str>,
    encode: impl FnOnce(&'a str) -> Option<T>,
) -> Result<(String, T), NodeKeep> {
    let Some(tag) = tag else {
        return Err(NodeKeep::Name);
    };
    encode(tag)
        .map(|item| (tag.to_owned(), item))
        .ok_or(NodeKeep::Capability)
}

pub(crate) fn render_fn(target: OutputTarget) -> RenderFromPolicyFn {
    match target {
        OutputTarget::Mihomo => render_mihomo_from_policy_v1,
        OutputTarget::Quanx => render_quanx_from_policy_v1,
        OutputTarget::Singbox => render_singbox_from_policy_v1,
        OutputTarget::Loon => render_loon_from_policy_v1,
        OutputTarget::Egern => render_egern_from_policy_v1,
    }
}

pub(crate) fn accepted_nodes(named: &NamedSubscriptionSources) -> Vec<&ProxyNode> {
    named
        .occurrences()
        .iter()
        .filter_map(|occurrence| match occurrence {
            NamedNodeOccurrence::Accepted { node, .. } => Some(node.as_ref()),
            NamedNodeOccurrence::Rejected { .. } => None,
        })
        .collect()
}

/// Adapter spelling of compiled rules. `None` drops the rule; a dropped
/// `UrlRegex` increments the omitted count used by Keep-pass.
pub(crate) fn map_compiled_rules<T>(
    rules: &[CompiledRuleV1],
    mut spell: impl FnMut(&CompiledRuleV1) -> Result<Option<T>, AdapterRenderError>,
) -> Result<(Vec<T>, u8), AdapterRenderError> {
    let mut items = Vec::with_capacity(rules.len());
    let mut omitted_url_regex = 0_u8;
    for rule in rules {
        match spell(rule)? {
            Some(item) => items.push(item),
            None if matches!(rule.matcher(), RuleMatcherV1::UrlRegex(_)) => {
                omitted_url_regex = omitted_url_regex.saturating_add(1);
            }
            None => {}
        }
    }
    Ok((items, omitted_url_regex))
}

pub(crate) fn bounded_text(
    body: String,
    limit_bytes: usize,
    kept: &KeptNodes,
    omitted_url_regex: u8,
) -> Result<RenderedTargetV1, AdapterRenderError> {
    if body.len() > limit_bytes {
        return Err(AdapterRenderError::OutputTooLarge { limit_bytes });
    }
    Ok(RenderedTargetV1::from_parts(
        body.into_bytes(),
        kept,
        omitted_url_regex,
    ))
}

/// Shared tail of No remote config and Rule frontend: named nodes + policy → document.
pub(crate) fn render_named_policy(
    named: &NamedSubscriptionSources,
    policy: &CompiledPolicyV1,
    target: OutputTarget,
    limit_bytes: usize,
) -> Result<RenderedConfig, ConversionRenderError> {
    render_named_policy_with(named, policy, render_fn(target), limit_bytes)
}

fn render_named_policy_with(
    named: &NamedSubscriptionSources,
    policy: &CompiledPolicyV1,
    render: RenderFromPolicyFn,
    limit_bytes: usize,
) -> Result<RenderedConfig, ConversionRenderError> {
    let parse = named.parse_skip_count();
    let nodes = accepted_nodes(named);
    if nodes.is_empty() {
        return Err(ConversionRenderError::NoValidNodes {
            skips: SkipCountsV1::parse_only(parse),
        });
    }
    match render(&nodes, policy, limit_bytes) {
        Ok(rendered) => Ok(RenderedConfig::from_parts(
            rendered.bytes,
            SkipCountsV1 {
                parse,
                capability: rendered.capability_skips,
                name: rendered.name_skips,
            },
            rendered.omitted_url_regex,
        )),
        Err(error) => Err(ConversionRenderError::from_adapter(error, parse)),
    }
}

pub(crate) fn render_builtin_v1(
    parsed: ParsedSubscriptionSources,
    target: OutputTarget,
) -> Result<RenderedConfig, ConversionRenderError> {
    render_builtin_with_limit(parsed, render_fn(target), MAX_OUTPUT_BYTES)
}

/// Names the accepted nodes, compiles the builtin topology, and renders one target.
pub(crate) fn render_builtin_with_limit(
    parsed: ParsedSubscriptionSources,
    render: RenderFromPolicyFn,
    limit_bytes: usize,
) -> Result<RenderedConfig, ConversionRenderError> {
    let named = resolve_node_names(parsed, &["PROXY", "AUTO"])
        .map_err(|_| ConversionRenderError::Internal)?;
    let policy = compile_builtin_policy_v1(&accepted_nodes(&named));
    render_named_policy_with(&named, &policy, render, limit_bytes)
}

#[cfg(test)]
mod tests {
    use super::AdapterRenderError;

    #[test]
    fn keep_pass_counts_name_and_capability_and_rejects_all_dropped() {
        use super::{KeptNodes, NodeKeep, keep_named};

        let (kept, items) = KeptNodes::from_encoded([
            Ok("a"),
            Err(NodeKeep::Name),
            Err(NodeKeep::Capability),
            Ok("b"),
        ])
        .expect("two nodes survive");
        assert_eq!(items, ["a", "b"]);
        assert_eq!(kept.name_skips, 1);
        assert_eq!(kept.capability_skips, 1);

        assert_eq!(
            KeptNodes::from_encoded([Err::<&str, _>(NodeKeep::Name), Err(NodeKeep::Capability)])
                .unwrap_err(),
            AdapterRenderError::NoValidNodes {
                capability_skips: 1,
                name_skips: 1,
            }
        );
        assert_eq!(keep_named(None, |_| Some(1)), Err(NodeKeep::Name));
        assert_eq!(
            keep_named(Some("tag"), |_| None::<u8>),
            Err(NodeKeep::Capability)
        );
        assert_eq!(
            keep_named(Some("tag"), |tag| Some(tag.len())),
            Ok(("tag".to_owned(), 3))
        );
    }

    #[test]
    fn map_compiled_rules_counts_omitted_url_regex() {
        use crate::policy::{CompiledRuleV1, PolicyMemberV1, RuleMatcherV1};

        use super::map_compiled_rules;

        let rules = [
            CompiledRuleV1::new(RuleMatcherV1::Match, PolicyMemberV1::Direct),
            CompiledRuleV1::new(
                RuleMatcherV1::UrlRegex("a".to_owned()),
                PolicyMemberV1::Direct,
            ),
            CompiledRuleV1::new(
                RuleMatcherV1::UrlRegex("b".to_owned()),
                PolicyMemberV1::Reject,
            ),
            CompiledRuleV1::new(
                RuleMatcherV1::Domain("x.example".to_owned()),
                PolicyMemberV1::Reject,
            ),
        ];
        let (items, omitted) = map_compiled_rules(&rules, |rule| {
            Ok(match rule.matcher() {
                RuleMatcherV1::UrlRegex(_) => None,
                _ => Some(()),
            })
        })
        .expect("spell");
        assert_eq!(items.len(), 2);
        assert_eq!(omitted, 2);
    }
}
