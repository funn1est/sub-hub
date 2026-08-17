//! Stage 2: config fingerprint hashing, pinned profile policies, and
//! profile-gated capability validation.
//!
//! Owns the domain-separated wire encodings (config fingerprint and omitted
//! Rule Set evidence) plus the promoted digest table that gates them.

use super::{
    Acl4SsrPreparationError, Acl4SsrRenderError,
    ini::{Config, Directive, GroupMember, GroupType, RuleSource, TargetRef},
    sha256,
};

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

pub(super) fn hash_config_fingerprint(config: &Config) -> Result<(usize, [u8; 32]), ()> {
    let mut output = HashedWire::new();
    encode_config_fingerprint_into(config, &mut output)?;
    output.finish()
}

#[cfg(test)]
pub(super) fn encode_config_fingerprint(config: &Config) -> Result<Vec<u8>, ()> {
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
pub(super) enum ProfileKind {
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

pub(super) fn lookup_profile(preimage_bytes: usize, digest: &[u8; 32]) -> Option<ProfileKind> {
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

pub(super) fn validate_target_capability(
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

fn target_name(target: &TargetRef) -> &str {
    match target {
        TargetRef::Direct => "DIRECT",
        TargetRef::Reject => "REJECT",
        TargetRef::Group(name) => name,
    }
}

pub(super) struct OmittedEvidenceAccumulator {
    policy: &'static ProfilePolicy,
    output: HashedWire,
    expected_entry_count: usize,
    entry_count: usize,
    distribution: Vec<usize>,
}

impl OmittedEvidenceAccumulator {
    pub(super) fn new(
        profile: ProfileKind,
        config_fingerprint: [u8; 32],
    ) -> Result<Self, Acl4SsrRenderError> {
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

    pub(super) fn push(
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

    pub(super) fn finish(self) -> Result<usize, Acl4SsrRenderError> {
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
pub(super) struct OmittedEvidenceEntry {
    pub(super) remote_source_ordinal: u32,
    pub(super) url_regex_ordinal: u32,
    pub(super) target: TargetRef,
    pub(super) pattern: String,
}

#[cfg(test)]
pub(super) fn encode_omitted_evidence(
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

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::{
        super::{ini::Config, sha256},
        PROFILE_POLICIES, ProfileKind, encode_config_fingerprint, lookup_profile,
    };

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
