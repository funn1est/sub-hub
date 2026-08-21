//! Adapter-adjacent spelling helpers shared by Client Format Adapters.
//!
//! Hop, host, password, Reality, and fingerprint spellings stay here, not on
//! the Node IR and not on the Keep-pass document.

use std::{
    borrow::Cow,
    io::{self, Write},
};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::Serialize;

use super::AdapterRenderError;
use crate::{
    node::Host,
    node::hysteria2::{Hysteria2Node, Hysteria2Obfs, Hysteria2Ports},
    node::shadowsocks::{ShadowsocksCipher, ShadowsocksCredential},
    node::vless::{ClientFingerprint, RealityOptions},
    policy::{BUILTIN_AUTO_PROBE_URL, CompiledPolicyV1, GroupStrategyV1, PolicyMemberV1},
};

/// Adapter-opt-in: gecko salamander is unspellable on Loon, Egern, and sing-box.
pub(crate) fn hysteria2_has_gecko(hysteria2: &Hysteria2Node) -> bool {
    hysteria2.obfs().is_some_and(Hysteria2Obfs::is_gecko)
}

/// Adapter-opt-in: pinSHA256 is unspellable on Loon and sing-box.
pub(crate) fn hysteria2_has_pin(hysteria2: &Hysteria2Node) -> bool {
    hysteria2.pin_sha256().is_some()
}

/// Official comma-hop spelling shared by Mihomo and Egern. `None` when not a hop.
pub(crate) fn hysteria2_official_ports(ports: &Hysteria2Ports) -> Option<String> {
    let atoms = ports.hop_atoms()?;
    let mut rendered = String::new();
    for (index, atom) in atoms.iter().enumerate() {
        if index > 0 {
            rendered.push(',');
        }
        let (start, end) = atom.bounds();
        rendered.push_str(&start.to_string());
        if atom.is_range() {
            rendered.push('-');
            rendered.push_str(&end.to_string());
        }
    }
    Some(rendered)
}

/// sing-box `server_ports` hop spelling. `None` when not a hop.
pub(crate) fn hysteria2_singbox_ports(ports: &Hysteria2Ports) -> Option<Vec<String>> {
    let atoms = ports.hop_atoms()?;
    Some(
        atoms
            .iter()
            .map(|atom| {
                let (start, end) = atom.bounds();
                format!("{start}:{end}")
            })
            .collect(),
    )
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

    use super::{AdapterRenderError, BoundedVec, serialize_bounded};
    use crate::render::MAX_OUTPUT_BYTES;

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

    #[test]
    fn hysteria2_hop_spelling_lives_on_the_adapter_helpers() {
        use std::num::NonZeroU16;

        use super::{hysteria2_official_ports, hysteria2_singbox_ports};
        use crate::node::hysteria2::{Hysteria2PortAtom, Hysteria2Ports};

        let port = |value: u16| NonZeroU16::new(value).expect("port");
        let ports = Hysteria2Ports::hop(vec![
            Hysteria2PortAtom::Single(port(123)),
            Hysteria2PortAtom::range(port(5000), port(6000)).expect("range"),
        ])
        .expect("hop");
        assert_eq!(
            hysteria2_official_ports(&ports).as_deref(),
            Some("123,5000-6000")
        );
        assert_eq!(
            hysteria2_singbox_ports(&ports),
            Some(vec!["123:123".to_owned(), "5000:6000".to_owned()])
        );
        assert_eq!(
            hysteria2_official_ports(&Hysteria2Ports::Single(port(443))),
            None
        );
    }
}
