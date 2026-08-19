use url::{Host, Url};

use crate::{MAX_GET_TARGET_BYTES, SelfHosts, self_hosts::is_canonical_dns_name};

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

pub(crate) fn is_valid_inbound_host(host: &str) -> bool {
    is_canonical_dns_name(host) || host.parse::<std::net::IpAddr>().is_ok()
}
