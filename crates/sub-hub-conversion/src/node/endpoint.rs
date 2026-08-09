use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
    num::NonZeroU16,
};

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Endpoint {
    host: Host,
    port: NonZeroU16,
}

impl Endpoint {
    pub(crate) fn new(host: Host, port: u16) -> Option<Self> {
        let port = NonZeroU16::new(port)?;
        let host = match host {
            Host::Domain(domain) if is_dns_name(&domain) && !is_numeric_ipv4_lookalike(&domain) => {
                Host::Domain(domain.to_ascii_lowercase())
            }
            Host::Domain(_) => return None,
            Host::Ipv4(address) => Host::Ipv4(address),
            Host::Ipv6(address) => Host::Ipv6(address),
        };
        Some(Self { host, port })
    }

    pub(crate) const fn host(&self) -> &Host {
        &self.host
    }

    pub(crate) const fn port(&self) -> NonZeroU16 {
        self.port
    }
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let host_kind = match self.host() {
            Host::Domain(_) => "domain",
            Host::Ipv4(_) => "ipv4",
            Host::Ipv6(_) => "ipv6",
        };
        formatter
            .debug_struct("Endpoint")
            .field("host", &host_kind)
            .field("port", &self.port())
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Host {
    Domain(String),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}

fn is_numeric_ipv4_lookalike(input: &str) -> bool {
    input.contains('.')
        && input
            .split('.')
            .all(|label| !label.is_empty() && label.bytes().all(|byte| byte.is_ascii_digit()))
}

fn is_dns_name(input: &str) -> bool {
    !input.is_empty()
        && input.is_ascii()
        && input.len() <= 253
        && input.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}
