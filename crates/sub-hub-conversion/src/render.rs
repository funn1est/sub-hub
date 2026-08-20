//! Target-neutral rendering seam shared by every client adapter.
//!
//! This module owns the closed adapter dispatch, the keep-pass shared by GET
//! and HEAD, the request-wide output limit, the bounded serializer,
//! the shared builtin (config-less) orchestration, and small formatting
//! helpers whose behavior must stay identical across adapters.

use std::{
    borrow::Cow,
    fmt,
    io::{self, Write},
};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::Serialize;

use crate::{
    OutputTarget,
    egern::render_egern_from_policy_v1,
    loon::render_loon_from_policy_v1,
    mihomo::render_mihomo_from_policy_v1,
    node::shadowsocks::{ShadowsocksCipher, ShadowsocksCredential},
    node::vless::{ClientFingerprint, RealityOptions},
    node::{Host, ProxyNode},
    node_name::{
        NamedNodeOccurrence, NamedSubscriptionSources, NodeNameDiagnostics, NodeNameError,
        resolve_node_names,
    },
    policy::{
        BUILTIN_AUTO_PROBE_URL, CompiledPolicyV1, CompiledRuleV1, GroupStrategyV1, PolicyMemberV1,
        RuleMatcherV1, compile_builtin_policy_v1,
    },
    quanx::render_quanx_from_policy_v1,
    share_uri::NodeRejection,
    singbox::render_singbox_from_policy_v1,
    skip::SkipCountsV1,
    subscription_source::{NodeOrigin, ParsedSubscriptionSources},
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

/// Signature shared by the five per-target policy renderers.
pub(crate) type RenderFromPolicyFn =
    fn(&[&ProxyNode], &CompiledPolicyV1, usize) -> Result<RenderedTargetV1, AdapterRenderError>;

/// Whether a named, parse-accepted node is kept by one target adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NodeKeep {
    /// Encoder must not return this as failure; [`KeptNodes::encode`] maps it to Internal.
    #[allow(
        dead_code,
        reason = "defensive: encode treats Keep-as-error as Internal"
    )]
    Keep,
    Name,
    Capability,
}

/// Keep accounting for one target adapter's encode pass.
pub(crate) struct KeptNodes {
    pub(crate) capability_skips: u32,
    pub(crate) name_skips: u32,
}

impl KeptNodes {
    /// Encode once: keep classification is the encoder's failure mode.
    pub(crate) fn encode<'a, T>(
        named_nodes: &[&'a ProxyNode],
        mut encode: impl FnMut(&'a ProxyNode) -> Result<T, NodeKeep>,
    ) -> Result<(Self, Vec<T>), AdapterRenderError> {
        let mut items = Vec::new();
        let mut capability_skips = 0_u32;
        let mut name_skips = 0_u32;
        for node in named_nodes {
            match encode(node) {
                Ok(item) => items.push(item),
                Err(NodeKeep::Name) => name_skips = name_skips.saturating_add(1),
                Err(NodeKeep::Capability) => capability_skips = capability_skips.saturating_add(1),
                Err(NodeKeep::Keep) => return Err(AdapterRenderError::Internal),
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

/// Named nodes plus compiled policy, rendered through the closed adapter module.
pub(crate) struct PolicyDocument {
    pub(crate) bytes: Vec<u8>,
    pub(crate) skips: SkipCountsV1,
    pub(crate) omitted_url_regex: u8,
}

#[derive(Clone, Copy)]
pub(crate) enum NamedPolicyError {
    NoValidNodes { skips: SkipCountsV1 },
    OutputTooLarge { limit_bytes: usize },
    Internal,
}

impl NamedPolicyError {
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
            AdapterRenderError::OutputTooLarge { limit_bytes } => {
                Self::OutputTooLarge { limit_bytes }
            }
            AdapterRenderError::Internal => Self::Internal,
        }
    }
}

/// Shared tail of No remote config and Rule frontend: named nodes + policy → document.
pub(crate) fn render_named_policy(
    named: &NamedSubscriptionSources,
    policy: &CompiledPolicyV1,
    target: OutputTarget,
    limit_bytes: usize,
) -> Result<PolicyDocument, NamedPolicyError> {
    render_named_policy_with(named, policy, render_fn(target), limit_bytes)
}

fn render_named_policy_with(
    named: &NamedSubscriptionSources,
    policy: &CompiledPolicyV1,
    render: RenderFromPolicyFn,
    limit_bytes: usize,
) -> Result<PolicyDocument, NamedPolicyError> {
    let parse = named.parse_skip_count();
    let nodes = accepted_nodes(named);
    if nodes.is_empty() {
        return Err(NamedPolicyError::NoValidNodes {
            skips: SkipCountsV1::parse_only(parse),
        });
    }
    match render(&nodes, policy, limit_bytes) {
        Ok(rendered) => Ok(PolicyDocument {
            bytes: rendered.bytes,
            skips: SkipCountsV1 {
                parse,
                capability: rendered.capability_skips,
                name: rendered.name_skips,
            },
            omitted_url_regex: rendered.omitted_url_regex,
        }),
        Err(error) => Err(NamedPolicyError::from_adapter(error, parse)),
    }
}

#[derive(PartialEq, Eq)]
pub(crate) struct BuiltinRenderOutput {
    config: Vec<u8>,
    diagnostics: BuiltinRenderDiagnostics,
}

impl BuiltinRenderOutput {
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "borrowing accessor kept for test assertions")
    )]
    pub(crate) fn config(&self) -> &[u8] {
        &self.config
    }

    pub(crate) fn into_rendered(self) -> (Vec<u8>, SkipCountsV1) {
        let skips = self.diagnostics.skip_counts();
        (self.config, skips)
    }

    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "diagnostics stay behind the application facade")
    )]
    pub(crate) const fn diagnostics(&self) -> &BuiltinRenderDiagnostics {
        &self.diagnostics
    }
}

impl fmt::Debug for BuiltinRenderOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BuiltinRenderOutput")
            .field("config", &"[REDACTED]")
            .field("config_len", &self.config.len())
            .field("diagnostics", &self.diagnostics)
            .finish()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct BuiltinRenderDiagnostics {
    rejections: Vec<BuiltinRenderRejection>,
    node_names: NodeNameDiagnostics,
    skips: SkipCountsV1,
}

impl BuiltinRenderDiagnostics {
    fn from_named(named: &NamedSubscriptionSources) -> Self {
        Self {
            rejections: named
                .occurrences()
                .iter()
                .filter_map(|occurrence| match occurrence {
                    NamedNodeOccurrence::Accepted { .. } => None,
                    NamedNodeOccurrence::Rejected { origin, rejection } => {
                        Some(BuiltinRenderRejection {
                            origin: *origin,
                            rejection: rejection.clone(),
                        })
                    }
                })
                .collect(),
            node_names: named.diagnostics().clone(),
            skips: SkipCountsV1::parse_only(named.parse_skip_count()),
        }
    }

    fn with_keep_counts(&mut self, capability_skips: u32, name_skips: u32) {
        self.skips.capability = capability_skips;
        self.skips.name = name_skips;
    }

    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "diagnostics stay behind the application facade")
    )]
    pub(crate) fn rejections(&self) -> &[BuiltinRenderRejection] {
        &self.rejections
    }

    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "diagnostics stay behind the application facade")
    )]
    pub(crate) const fn node_names(&self) -> &NodeNameDiagnostics {
        &self.node_names
    }

    /// Number of nodes dropped by the selected target's capability filter.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "diagnostics stay behind the application facade")
    )]
    pub(crate) const fn capability_skips(&self) -> u32 {
        self.skips.capability
    }

    pub(crate) fn skip_counts(&self) -> SkipCountsV1 {
        self.skips
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct BuiltinRenderRejection {
    origin: NodeOrigin,
    rejection: NodeRejection,
}

impl BuiltinRenderRejection {
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "diagnostics stay behind the application facade")
    )]
    pub(crate) const fn origin(&self) -> NodeOrigin {
        self.origin
    }

    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "diagnostics stay behind the application facade")
    )]
    pub(crate) const fn rejection(&self) -> &NodeRejection {
        &self.rejection
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum BuiltinRenderError {
    NodeNaming(NodeNameError),
    NoValidNodes {
        diagnostics: BuiltinRenderDiagnostics,
    },
    OutputTooLarge {
        limit_bytes: usize,
    },
    Serialization,
}

pub(crate) fn render_builtin_v1(
    parsed: ParsedSubscriptionSources,
    target: OutputTarget,
) -> Result<BuiltinRenderOutput, BuiltinRenderError> {
    render_builtin_with_limit(parsed, render_fn(target), MAX_OUTPUT_BYTES)
}

#[cfg(test)]
pub(crate) fn render_builtin_mihomo_v1(
    parsed: ParsedSubscriptionSources,
) -> Result<BuiltinRenderOutput, BuiltinRenderError> {
    render_builtin_v1(parsed, OutputTarget::Mihomo)
}

#[cfg(test)]
pub(crate) fn render_builtin_quanx_v1(
    parsed: ParsedSubscriptionSources,
) -> Result<BuiltinRenderOutput, BuiltinRenderError> {
    render_builtin_v1(parsed, OutputTarget::Quanx)
}

#[cfg(test)]
pub(crate) fn render_builtin_singbox_v1(
    parsed: ParsedSubscriptionSources,
) -> Result<BuiltinRenderOutput, BuiltinRenderError> {
    render_builtin_v1(parsed, OutputTarget::Singbox)
}

#[cfg(test)]
pub(crate) fn render_builtin_loon_v1(
    parsed: ParsedSubscriptionSources,
) -> Result<BuiltinRenderOutput, BuiltinRenderError> {
    render_builtin_v1(parsed, OutputTarget::Loon)
}

#[cfg(test)]
pub(crate) fn render_builtin_egern_v1(
    parsed: ParsedSubscriptionSources,
) -> Result<BuiltinRenderOutput, BuiltinRenderError> {
    render_builtin_v1(parsed, OutputTarget::Egern)
}

/// Names the accepted nodes, compiles the builtin topology, and renders one target.
pub(crate) fn render_builtin_with_limit(
    parsed: ParsedSubscriptionSources,
    render: RenderFromPolicyFn,
    limit_bytes: usize,
) -> Result<BuiltinRenderOutput, BuiltinRenderError> {
    let named =
        resolve_node_names(parsed, &["PROXY", "AUTO"]).map_err(BuiltinRenderError::NodeNaming)?;
    let mut diagnostics = BuiltinRenderDiagnostics::from_named(&named);
    let nodes = accepted_nodes(&named);
    if nodes.is_empty() {
        return Err(BuiltinRenderError::NoValidNodes { diagnostics });
    }

    let policy = compile_builtin_policy_v1(&nodes);
    match render_named_policy_with(&named, &policy, render, limit_bytes) {
        Ok(document) => {
            diagnostics.with_keep_counts(document.skips.capability, document.skips.name);
            Ok(BuiltinRenderOutput {
                config: document.bytes,
                diagnostics,
            })
        }
        Err(NamedPolicyError::NoValidNodes { skips }) => {
            diagnostics.with_keep_counts(skips.capability, skips.name);
            Err(BuiltinRenderError::NoValidNodes { diagnostics })
        }
        Err(NamedPolicyError::OutputTooLarge { limit_bytes }) => {
            Err(BuiltinRenderError::OutputTooLarge { limit_bytes })
        }
        Err(NamedPolicyError::Internal) => Err(BuiltinRenderError::Serialization),
    }
}

/// Renders an endpoint host with a bare (bracket-free) IPv6 form.
///
/// Used by targets whose host field is standalone (Mihomo, sing-box, Loon, Egern).
pub(crate) fn render_host_plain(host: &Host) -> String {
    match host {
        Host::Domain(domain) => domain.clone(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => address.to_string(),
    }
}

/// Renders an endpoint host with a bracketed IPv6 form.
///
/// Used by targets that join `host:port` in one field (Quantumult X).
pub(crate) fn render_host_bracketed(host: &Host) -> String {
    match host {
        Host::Domain(domain) => domain.clone(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => format!("[{address}]"),
    }
}

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

pub(crate) const fn shadowsocks_method(cipher: &ShadowsocksCipher) -> &'static str {
    match cipher {
        ShadowsocksCipher::Aes128Gcm => "aes-128-gcm",
        ShadowsocksCipher::Aes256Gcm => "aes-256-gcm",
        ShadowsocksCipher::Chacha20IetfPoly1305 => "chacha20-ietf-poly1305",
        ShadowsocksCipher::Blake3Aes128Gcm => "2022-blake3-aes-128-gcm",
        ShadowsocksCipher::Blake3Aes256Gcm => "2022-blake3-aes-256-gcm",
    }
}

/// Maps a policy member to a target token using that target's `DIRECT`/`REJECT`
/// spellings and group-name grammar.
///
/// Node members that did not survive the target's own tag/capability filter map
/// to `None` and are silently dropped by the caller.
pub(crate) fn policy_member_token(
    member: &PolicyMemberV1,
    direct_token: &'static str,
    reject_token: &'static str,
    group_token: impl FnOnce(&str) -> Result<Option<String>, AdapterRenderError>,
    valid_nodes: &[&str],
) -> Result<Option<String>, AdapterRenderError> {
    match member {
        PolicyMemberV1::Direct => Ok(Some(direct_token.to_owned())),
        PolicyMemberV1::Reject => Ok(Some(reject_token.to_owned())),
        PolicyMemberV1::Group(name) => group_token(name),
        PolicyMemberV1::Node(name) => Ok(valid_nodes
            .iter()
            .any(|candidate| *candidate == name)
            .then(|| name.clone())),
    }
}

/// Renders a Reality public key with the URL-safe unpadded Base64 spelling
/// shared by every target.
pub(crate) fn reality_public_key_base64(options: &RealityOptions) -> String {
    URL_SAFE_NO_PAD.encode(options.public_key().as_bytes())
}

/// Renders a Reality short id as lowercase hex, when one is present.
pub(crate) fn reality_short_id_hex(options: &RealityOptions) -> Option<String> {
    options
        .short_id()
        .map(|short_id| encode_hex(short_id.as_bytes()))
}

/// Renders a Shadowsocks credential as the password field shared by every
/// target: classic passwords verbatim, 2022 PSKs as standard Base64.
pub(crate) fn shadowsocks_password(credential: &ShadowsocksCredential) -> Cow<'_, str> {
    match credential {
        ShadowsocksCredential::Password(password) => Cow::Borrowed(password.expose()),
        ShadowsocksCredential::Psk(psk) => Cow::Owned(STANDARD.encode(psk.expose())),
    }
}

pub(crate) const fn render_fingerprint(fingerprint: ClientFingerprint) -> &'static str {
    match fingerprint {
        ClientFingerprint::Chrome => "chrome",
        ClientFingerprint::Firefox => "firefox",
        ClientFingerprint::Safari => "safari",
        ClientFingerprint::Ios => "ios",
        ClientFingerprint::Android => "android",
        ClientFingerprint::Edge => "edge",
        ClientFingerprint::ThreeSixty => "360",
        ClientFingerprint::Qq => "qq",
        ClientFingerprint::Random => "random",
    }
}

/// Injects the target's reject token when no member survived render-side filtering.
///
/// Compile-side empty groups are already degraded to `Select` + `Reject`; this
/// guard only covers members dropped by a target's own tag/capability rules.
pub(crate) fn reject_when_empty(members: &mut Vec<String>, reject_token: &str) {
    if members.is_empty() {
        members.push(reject_token.to_owned());
    }
}

/// Substitutes the builtin probe URL for an empty health-check URL.
pub(crate) fn probe_url_or_default(url: &str) -> &str {
    if url.is_empty() {
        BUILTIN_AUTO_PROBE_URL
    } else {
        url
    }
}

/// Returns the single health URL shared by every automatic group, if exactly one exists.
pub(crate) fn shared_probe_url(policy: &CompiledPolicyV1) -> Option<&str> {
    let mut urls = Vec::new();
    for group in policy.groups() {
        let url = match group.strategy() {
            GroupStrategyV1::UrlTest { url, .. }
            | GroupStrategyV1::Fallback { url, .. }
            | GroupStrategyV1::LoadBalance { url, .. } => probe_url_or_default(url),
            GroupStrategyV1::Select => continue,
        };
        if urls.iter().all(|seen: &&str| *seen != url) {
            urls.push(url);
        }
    }
    match urls.as_slice() {
        [url] => Some(*url),
        _ => None,
    }
}

/// Node-name validation shared by targets without their own separator grammar
/// (sing-box, Egern): rejects empty names, ASCII control characters, and the
/// reserved `direct`/`reject` policy tokens.
pub(crate) fn plain_node_tag(name: &str) -> Option<&str> {
    if name.is_empty()
        || name.chars().any(|character| character.is_ascii_control())
        || name.eq_ignore_ascii_case("direct")
        || name.eq_ignore_ascii_case("reject")
    {
        None
    } else {
        Some(name)
    }
}

/// Group-name validation counterpart of [`plain_node_tag`]; reserved or
/// malformed group names are internal errors because the compiler owns them.
pub(crate) fn plain_group_tag(name: &str) -> Result<&str, AdapterRenderError> {
    if name.is_empty() || name.chars().any(|character| character.is_ascii_control()) {
        return Err(AdapterRenderError::Internal);
    }
    if name.eq_ignore_ascii_case("direct") || name.eq_ignore_ascii_case("reject") {
        return Err(AdapterRenderError::Internal);
    }
    Ok(name)
}

struct BoundedVec {
    bytes: Vec<u8>,
    limit: usize,
    overflowed: bool,
}

impl BoundedVec {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            overflowed: false,
        }
    }

    fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for BoundedVec {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if self.overflowed {
            return Err(io::Error::other("output limit exceeded"));
        }
        let Some(next_len) = self.bytes.len().checked_add(input.len()) else {
            self.overflowed = true;
            return Err(io::Error::other("output limit exceeded"));
        };
        if next_len > self.limit {
            self.overflowed = true;
            return Err(io::Error::other("output limit exceeded"));
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.overflowed {
            Err(io::Error::other("output limit exceeded"))
        } else {
            Ok(())
        }
    }
}

/// Serializes a document as YAML while enforcing the inclusive byte limit atomically.
pub(crate) fn serialize_bounded<T: Serialize>(
    value: &T,
    limit_bytes: usize,
) -> Result<Vec<u8>, AdapterRenderError> {
    let mut sink = BoundedVec::new(limit_bytes);
    let serialization = serde_yaml_ng::to_writer(&mut sink, value);
    if sink.overflowed {
        return Err(AdapterRenderError::OutputTooLarge { limit_bytes });
    }
    serialization.map_err(|_| AdapterRenderError::Internal)?;
    Ok(sink.into_inner())
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use serde::{Serialize, Serializer, ser::Error as _};

    use super::{AdapterRenderError, BoundedVec, MAX_OUTPUT_BYTES, serialize_bounded};

    #[test]
    fn sixteen_mib_is_inclusive_and_a_crossing_chunk_is_never_partially_written() {
        let mut sink = BoundedVec::new(MAX_OUTPUT_BYTES);
        let exact = vec![b'x'; MAX_OUTPUT_BYTES];
        sink.write_all(&exact).expect("exactly 16 MiB is allowed");
        assert_eq!(sink.bytes.len(), MAX_OUTPUT_BYTES);

        assert!(sink.write_all(b"!").is_err());
        assert_eq!(sink.bytes.len(), MAX_OUTPUT_BYTES);
        assert!(sink.overflowed);
        assert!(sink.write(b"").is_err(), "overflow is sticky");
    }

    struct FailsToSerialize;

    impl Serialize for FailsToSerialize {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            Err(S::Error::custom("deliberate test failure"))
        }
    }

    #[test]
    fn serializer_failures_are_not_misclassified_as_size_failures() {
        assert_eq!(
            serialize_bounded(&FailsToSerialize, 1_024),
            Err(AdapterRenderError::Internal)
        );
    }
}
