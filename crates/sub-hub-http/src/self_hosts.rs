use std::fmt;

use url::Host;

/// Maximum number of unique self-host aliases in one binding.
pub const MAX_SELF_HOSTS: usize = 16;

/// Bounded set of deployment hostnames that remote loading must never target.
#[derive(Clone)]
pub struct SelfHosts {
    hosts: Vec<String>,
}

impl SelfHosts {
    /// An empty set: the inbound request hostname remains the only additive self-target.
    #[must_use]
    pub const fn empty() -> Self {
        Self { hosts: Vec::new() }
    }

    /// Builds the set from already-canonical ASCII DNS hostnames.
    ///
    /// # Errors
    ///
    /// Returns [`SelfHostError`] when the set has more than [`MAX_SELF_HOSTS`] entries or contains a
    /// value that is not a canonical ASCII DNS hostname. An empty set is valid when the host
    /// supplies the inbound request hostname as an additive self-target deny.
    pub fn new<I, S>(hosts: I) -> Result<Self, SelfHostError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let hosts = hosts
            .into_iter()
            .map(|host| host.as_ref().to_owned())
            .collect::<Vec<_>>();
        if hosts.len() > MAX_SELF_HOSTS || hosts.iter().any(|host| !is_canonical_dns_name(host)) {
            return Err(SelfHostError);
        }
        Ok(Self { hosts })
    }

    /// Parses a **present** environment or dashboard blob.
    ///
    /// An empty blob is an empty set. A present blob that contains only whitespace or separators
    /// is invalid.
    ///
    /// # Errors
    ///
    /// Returns [`SelfHostError`] when a non-empty blob yields zero unique hosts, contains a 17th
    /// unique host, or any item is not a canonical DNS hostname.
    pub fn parse_list(raw: &str) -> Result<Self, SelfHostError> {
        if raw.strip_prefix('\u{FEFF}').unwrap_or(raw).is_empty() {
            return Ok(Self::empty());
        }

        let mut hosts = Vec::new();
        for piece in crate::binding_list::binding_pieces(raw) {
            let host = parse_one_host(piece)?;
            if hosts.iter().any(|existing| existing == &host) {
                continue;
            }
            if hosts.len() >= MAX_SELF_HOSTS {
                return Err(SelfHostError);
            }
            hosts.push(host);
        }
        if hosts.is_empty() {
            return Err(SelfHostError);
        }
        Ok(Self { hosts })
    }

    /// `None` and `Some("")` are an empty set. Any other present blob is [`Self::parse_list`].
    ///
    /// # Errors
    ///
    /// Returns [`SelfHostError`] when a present non-empty blob fails [`Self::parse_list`].
    pub fn parse_optional(raw: Option<&str>) -> Result<Self, SelfHostError> {
        match raw {
            None | Some("") => Ok(Self::empty()),
            Some(raw) => Self::parse_list(raw),
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hosts.is_empty()
    }

    #[must_use]
    pub fn as_slice(&self) -> &[String] {
        &self.hosts
    }
}

impl fmt::Debug for SelfHosts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelfHosts")
            .field("host_count", &self.hosts.len())
            .finish()
    }
}

/// A deliberately detail-free self-host configuration error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SelfHostError;

impl fmt::Display for SelfHostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid self host configuration")
    }
}

impl std::error::Error for SelfHostError {}

pub(crate) fn is_canonical_dns_name(host: &str) -> bool {
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

fn parse_one_host(raw: &str) -> Result<String, SelfHostError> {
    let Host::Domain(host) = Host::parse(raw).map_err(|_| SelfHostError)? else {
        return Err(SelfHostError);
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if !is_canonical_dns_name(&host) {
        return Err(SelfHostError);
    }
    Ok(host)
}

#[cfg(test)]
mod tests {
    use super::{MAX_SELF_HOSTS, SelfHosts};

    #[test]
    fn parse_optional_absent_and_empty_string_are_empty_sets() {
        let absent = SelfHosts::parse_optional(None).expect("absent");
        assert!(absent.is_empty());
        assert_eq!(format!("{absent:?}"), "SelfHosts { host_count: 0 }");

        let empty = SelfHosts::parse_optional(Some("")).expect("empty string");
        assert!(empty.is_empty());
        assert!(SelfHosts::parse_list("").expect("empty list").is_empty());
    }

    #[test]
    fn parse_list_accepts_comma_or_newline_and_canonicalizes() {
        let comma = SelfHosts::parse_list("EDGE.EXAMPLE., sub.example").expect("comma list");
        assert_eq!(comma.as_slice(), ["edge.example", "sub.example"]);

        let lines = SelfHosts::parse_list("edge.example\nsub.example\n").expect("newline list");
        assert_eq!(lines.as_slice(), ["edge.example", "sub.example"]);

        let crlf = SelfHosts::parse_list("edge.example\r\nsub.example").expect("crlf list");
        assert_eq!(crlf.as_slice(), ["edge.example", "sub.example"]);

        let bom = SelfHosts::parse_list("\u{FEFF}EDGE.EXAMPLE.").expect("BOM stripped");
        assert_eq!(bom.as_slice(), ["edge.example"]);

        let skipped =
            SelfHosts::parse_list("edge.example,,sub.example").expect("empty pieces skipped");
        assert_eq!(skipped.as_slice(), ["edge.example", "sub.example"]);

        let deduped =
            SelfHosts::parse_list("edge.example, EDGE.EXAMPLE.").expect("first-seen dedupe");
        assert_eq!(deduped.as_slice(), ["edge.example"]);
        assert_eq!(format!("{deduped:?}"), "SelfHosts { host_count: 1 }");
    }

    #[test]
    fn parse_list_rejects_separator_only_ips_and_seventeenth_unique() {
        assert!(SelfHosts::parse_list("   ").is_err());
        assert!(SelfHosts::parse_list(",").is_err());
        assert!(SelfHosts::parse_list("\n").is_err());
        assert!(SelfHosts::parse_list("127.0.0.1").is_err());
        assert!(SelfHosts::parse_list("::1").is_err());
        assert!(SelfHosts::parse_list("-bad.example").is_err());

        let sixteen = (0..MAX_SELF_HOSTS)
            .map(|index| format!("h{index}.example"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(SelfHosts::parse_list(&sixteen).is_ok());
        assert!(SelfHosts::parse_list(&format!("{sixteen},h16.example")).is_err());
    }
}
