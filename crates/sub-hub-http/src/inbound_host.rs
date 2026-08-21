use url::Host;

use crate::self_hosts::is_canonical_dns_name;

/// Canonicalizes a host-only inbound name (no port).
///
/// Domains are trailing-dot-stripped and lowercased. IPv6 may be written with or without brackets.
/// Conversion share-URI DNS checks stay separate: they also reject numeric IPv4 lookalikes.
#[must_use]
pub fn canonicalize_inbound_host(raw_host: &str) -> Option<String> {
    if let Some(address) = raw_host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
    {
        return address
            .parse::<std::net::Ipv6Addr>()
            .ok()
            .map(|ip| ip.to_string());
    }
    match Host::parse(raw_host) {
        Ok(Host::Domain(host)) => {
            let host = host.trim_end_matches('.').to_ascii_lowercase();
            is_canonical_dns_name(&host).then_some(host)
        }
        Ok(Host::Ipv4(address)) => Some(address.to_string()),
        Ok(Host::Ipv6(address)) => Some(address.to_string()),
        Err(_) => raw_host
            .parse::<std::net::Ipv6Addr>()
            .ok()
            .map(|ip| ip.to_string()),
    }
}

/// Whether a already-canonical inbound host can be used as the self-target deny.
#[must_use]
pub(crate) fn is_valid_inbound_host(host: &str) -> bool {
    is_canonical_dns_name(host) || host.parse::<std::net::IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::canonicalize_inbound_host;

    #[test]
    fn canonicalizes_dns_and_literal_addresses() {
        assert_eq!(
            canonicalize_inbound_host("EDGE.EXAMPLE."),
            Some("edge.example".to_owned())
        );
        assert_eq!(
            canonicalize_inbound_host("127.0.0.1"),
            Some("127.0.0.1".to_owned())
        );
        assert_eq!(canonicalize_inbound_host("[::1]"), Some("::1".to_owned()));
        assert_eq!(canonicalize_inbound_host("::1"), Some("::1".to_owned()));
    }

    #[test]
    fn rejects_empty_and_non_dns_domains() {
        assert!(canonicalize_inbound_host("").is_none());
        assert!(canonicalize_inbound_host("-bad.example").is_none());
        assert!(canonicalize_inbound_host("example.com:443").is_none());
    }

    #[test]
    fn inbound_deny_hosts_are_canonical_dns_or_ip() {
        assert!(super::is_valid_inbound_host("edge.example"));
        assert!(super::is_valid_inbound_host("127.0.0.1"));
        assert!(super::is_valid_inbound_host("::1"));
        assert!(!super::is_valid_inbound_host("-bad.example"));
        assert!(!super::is_valid_inbound_host("example.com:443"));
    }
}
