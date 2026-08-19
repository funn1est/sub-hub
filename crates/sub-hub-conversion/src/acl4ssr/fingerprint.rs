//! Stage 2: config fingerprint hashing and the promoted digest table.
//!
//! Owns the domain-separated wire encodings (config fingerprint and omitted
//! Rule Set evidence). Rendering no longer gates on these digests.

use super::{
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
#[allow(dead_code)]
pub(super) enum ProfileKind {
    Online,
    Full,
}

#[allow(dead_code)]
struct ProfilePolicy {
    kind: ProfileKind,
    config_preimage_bytes: usize,
    config_digest: [u8; 32],
}

// These values were promoted only after an independent parse of the pinned Git
// blob corpus agreed with the Rust encoder on all four preimage lengths and
// SHA-256 digests. This table intentionally cannot be changed by request,
// environment, KV, or runtime configuration.
#[allow(dead_code)]
const PROFILE_POLICIES: &[ProfilePolicy] = &[
    ProfilePolicy {
        kind: ProfileKind::Online,
        config_preimage_bytes: 2_419,
        config_digest: [
            0x6b, 0xa3, 0xcf, 0x43, 0xff, 0x20, 0xb8, 0x5a, 0xdd, 0x8d, 0x17, 0x29, 0x3a, 0x5e,
            0xbd, 0x30, 0x59, 0x2b, 0x17, 0x29, 0xa8, 0x93, 0xe6, 0xbf, 0x77, 0x6e, 0x14, 0x27,
            0x4b, 0x2d, 0xaf, 0x58,
        ],
    },
    ProfilePolicy {
        kind: ProfileKind::Full,
        config_preimage_bytes: 8_557,
        config_digest: [
            0x98, 0xfd, 0x7e, 0x18, 0x68, 0x74, 0xd7, 0x03, 0x57, 0x44, 0xa1, 0xb5, 0xc8, 0xb5,
            0x18, 0xdc, 0xc6, 0x22, 0xd1, 0x09, 0x0a, 0x20, 0x7f, 0x29, 0x93, 0xea, 0x3f, 0x9e,
            0xd2, 0x88, 0x57, 0x79,
        ],
    },
];

#[allow(dead_code)]
pub(super) fn lookup_profile(preimage_bytes: usize, digest: &[u8; 32]) -> Option<ProfileKind> {
    PROFILE_POLICIES
        .iter()
        .find(|entry| {
            entry.config_preimage_bytes == preimage_bytes && entry.config_digest == *digest
        })
        .map(|entry| entry.kind)
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
