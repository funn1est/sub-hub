//! Outbound accept: lexical HTTPS destination policy for occurrence URLs and
//! every followed redirect. Native DNS + IANA reachability stays a host adapter.

use url::{Host, Url};

use crate::{MAX_GET_TARGET_BYTES, SelfHosts, self_hosts::is_canonical_dns_name};

pub(crate) fn accept_outbound_url(
    input: &str,
    self_hosts: &SelfHosts,
    inbound_host: &str,
    supports_https_port: impl FnOnce(u16) -> bool,
) -> Result<Url, ()> {
    let url = canonical_remote_url(input, self_hosts, inbound_host)?;
    if !supports_https_port(url.port_or_known_default().unwrap_or(443)) {
        return Err(());
    }
    Ok(url)
}

pub(crate) fn canonical_remote_url(
    input: &str,
    self_hosts: &SelfHosts,
    inbound_host: &str,
) -> Result<Url, ()> {
    if input.len() > MAX_GET_TARGET_BYTES
        || input
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ' || byte == 0x7f)
    {
        return Err(());
    }
    let scheme_end = input.find("://").ok_or(())?;
    if !input[..scheme_end].eq_ignore_ascii_case("https") {
        return Err(());
    }
    let authority = input[scheme_end + 3..]
        .split(['/', '?', '#'])
        .next()
        .ok_or(())?;
    if authority.contains('@') {
        return Err(());
    }
    let mut url = Url::parse(input).map_err(|_| ())?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.port() == Some(0)
    {
        return Err(());
    }
    let Host::Domain(host) = url.host().ok_or(())? else {
        return Err(());
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if !is_canonical_dns_name(&host)
        || is_lexically_forbidden_host(&host)
        || host == inbound_host
        || self_hosts
            .as_slice()
            .iter()
            .any(|candidate| candidate == &host)
    {
        return Err(());
    }
    url.set_host(Some(&host)).map_err(|_error| ())?;
    if url.port() == Some(443) {
        url.set_port(None)?;
    }
    if url.as_str().len() > MAX_GET_TARGET_BYTES {
        return Err(());
    }
    Ok(url)
}

fn is_lexically_forbidden_host(host: &str) -> bool {
    ["localhost", "local", "internal", "home.arpa"]
        .iter()
        .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
}

#[cfg(test)]
mod tests {
    use super::accept_outbound_url;
    use crate::SelfHosts;

    fn hosts() -> SelfHosts {
        SelfHosts::new(["service.example"]).expect("valid self hostname")
    }

    fn accept(input: &str) -> Result<String, ()> {
        accept_outbound_url(input, &hosts(), "inbound.example", |_| true)
            .map(|url| url.as_str().to_owned())
    }

    #[test]
    fn https_canonical_url_is_accepted() {
        assert_eq!(
            accept("https://upstream.example/sub"),
            Ok("https://upstream.example/sub".to_owned())
        );
        assert_eq!(
            accept("https://upstream.example:443/sub"),
            Ok("https://upstream.example/sub".to_owned())
        );
    }

    #[test]
    fn lexical_policy_rejects_before_a_port_gate() {
        for input in [
            "http://upstream.example/sub",
            "https://127.0.0.1/sub",
            "https://[2606:4700:4700::1111]/sub",
            "https://@upstream.example/sub",
            "https://user@upstream.example/sub",
            "https://upstream.example/sub#",
            "https://localhost/sub",
            "https://child.localhost/sub",
            "https://child.local/sub",
            "https://child.internal/sub",
            "https://child.home.arpa/sub",
            "https://inbound.example/sub",
            "https://service.example/sub",
            "https://upstream.example/sub ",
        ] {
            assert_eq!(accept(input), Err(()), "{input}");
        }
    }

    #[test]
    fn port_gate_runs_after_lexical_accept() {
        let accepted = accept_outbound_url(
            "https://upstream.example:8443/sub",
            &hosts(),
            "inbound.example",
            |port| port == 8443,
        )
        .map(|url| url.as_str().to_owned());
        assert_eq!(accepted, Ok("https://upstream.example:8443/sub".to_owned()));
        assert_eq!(
            accept_outbound_url(
                "https://upstream.example:8443/sub",
                &hosts(),
                "inbound.example",
                |port| port == 443
            ),
            Err(())
        );
    }
}
