mod error;
mod hysteria2;
mod percent;
mod shadowsocks;
mod trojan;
mod vless;
mod vmess;

use std::{
    borrow::Cow,
    collections::BTreeSet,
    net::{Ipv4Addr, Ipv6Addr},
};

use crate::node::{Endpoint, Host, NodeNameInput, ProxyNodeDraft};

pub(crate) use error::{InvalidNodeReason, NodeRejection, UnsupportedCapability};

struct AuthorityUri<'a> {
    userinfo: &'a str,
    authority: &'a str,
    query: Option<&'a str>,
    name_input: NodeNameInput,
}

struct QueryPair<'a> {
    key: &'a str,
    value: Cow<'a, str>,
}

pub(crate) fn parse_share_uri(input: &str) -> Result<ProxyNodeDraft, NodeRejection> {
    if input.trim() != input {
        Err(NodeRejection::Invalid(InvalidNodeReason::Uri))
    } else if let Some(input) = input.strip_prefix("vless://") {
        vless::parse(input)
    } else if let Some(input) = input.strip_prefix("ss://") {
        shadowsocks::parse(input)
    } else if let Some(input) = input.strip_prefix("trojan://") {
        trojan::parse(input)
    } else if let Some(input) = input.strip_prefix("vmess://") {
        vmess::parse(input)
    } else if let Some(input) = input.strip_prefix("hysteria2://") {
        hysteria2::parse(input)
    } else if let Some(input) = input.strip_prefix("hy2://") {
        hysteria2::parse(input)
    } else if let Some((scheme, payload)) = input.split_once("://") {
        if payload.is_empty()
            || !is_valid_scheme(scheme)
            || scheme.eq_ignore_ascii_case("vless")
            || scheme.eq_ignore_ascii_case("ss")
            || scheme.eq_ignore_ascii_case("trojan")
            || scheme.eq_ignore_ascii_case("vmess")
            || scheme.eq_ignore_ascii_case("hysteria2")
            || scheme.eq_ignore_ascii_case("hy2")
        {
            Err(NodeRejection::Invalid(InvalidNodeReason::Uri))
        } else {
            Err(NodeRejection::Unsupported(UnsupportedCapability::Protocol))
        }
    } else {
        Err(NodeRejection::Invalid(InvalidNodeReason::Uri))
    }
}

fn is_valid_scheme(input: &str) -> bool {
    let mut bytes = input.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}

fn parse_endpoint(input: &str) -> Result<Endpoint, NodeRejection> {
    let invalid = || NodeRejection::Invalid(InvalidNodeReason::Endpoint);
    let (host, port) = if let Some(bracketed) = input.strip_prefix('[') {
        let (address, suffix) = bracketed.split_once(']').ok_or_else(invalid)?;
        if address.contains('%') {
            return Err(invalid());
        }
        let port = suffix.strip_prefix(':').ok_or_else(invalid)?;
        let address = address.parse::<Ipv6Addr>().map_err(|_| invalid())?;
        (Host::Ipv6(address), port)
    } else {
        let (host, port) = input.rsplit_once(':').ok_or_else(invalid)?;
        if host.contains(':') {
            return Err(invalid());
        }
        let host = if let Ok(address) = host.parse::<Ipv4Addr>() {
            Host::Ipv4(address)
        } else {
            Host::Domain(host.to_owned())
        };
        (host, port)
    };
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid());
    }
    let port = port.parse::<u16>().map_err(|_| invalid())?;

    Endpoint::new(host, port).ok_or_else(invalid)
}

fn parse_authority_uri(input: &str) -> Result<AuthorityUri<'_>, NodeRejection> {
    let invalid = || NodeRejection::Invalid(InvalidNodeReason::Uri);
    let (before_fragment, name_input) = if let Some((before, fragment)) = input.split_once('#') {
        if fragment.contains('#') {
            return Err(invalid());
        }
        let decoded = percent::decode(fragment)
            .map_err(|()| NodeRejection::Invalid(InvalidNodeReason::PercentEncoding))?;
        (before, NodeNameInput::Decoded(decoded.into_owned()))
    } else {
        (input, NodeNameInput::Missing)
    };

    let (userinfo_authority_path, query) = before_fragment
        .split_once('?')
        .map_or((before_fragment, None), |(value, query)| {
            (value, Some(query))
        });

    let (userinfo, remainder) = userinfo_authority_path
        .split_once('@')
        .ok_or_else(invalid)?;
    if userinfo.contains('/') || remainder.contains('@') {
        return Err(invalid());
    }
    let authority = if let Some(authority) = remainder.strip_suffix('/') {
        if authority.contains('/') {
            return Err(invalid());
        }
        authority
    } else if remainder.contains('/') {
        return Err(invalid());
    } else {
        remainder
    };

    Ok(AuthorityUri {
        userinfo,
        authority,
        query,
        name_input,
    })
}

fn scan_query(input: &str) -> Result<Vec<QueryPair<'_>>, NodeRejection> {
    let mut seen = BTreeSet::new();
    let mut pairs = Vec::new();

    for pair in input.split('&') {
        if pair.is_empty() {
            return Err(NodeRejection::Invalid(InvalidNodeReason::Parameter));
        }
        let (key, encoded_value) = pair
            .split_once('=')
            .ok_or(NodeRejection::Invalid(InvalidNodeReason::Parameter))?;
        if key.is_empty() || !key.is_ascii() || key.contains('%') || encoded_value.contains('=') {
            return Err(NodeRejection::Invalid(InvalidNodeReason::Parameter));
        }
        if !seen.insert(key) {
            return Err(NodeRejection::Invalid(
                InvalidNodeReason::DuplicateParameter,
            ));
        }
        let value = percent::decode(encoded_value)
            .map_err(|()| NodeRejection::Invalid(InvalidNodeReason::PercentEncoding))?;
        pairs.push(QueryPair { key, value });
    }

    Ok(pairs)
}

#[cfg(test)]
mod tests;
