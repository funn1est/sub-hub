use std::{
    borrow::Cow,
    collections::BTreeSet,
    net::{Ipv4Addr, Ipv6Addr},
};

use super::{
    Endpoint, Host, NodeNameInput, percent,
    rejection::{InvalidNodeReason, NodeRejection},
};

pub(crate) struct AuthorityUri<'a> {
    pub(crate) userinfo: &'a str,
    pub(crate) authority: &'a str,
    pub(crate) query: Option<&'a str>,
    pub(crate) name_input: NodeNameInput,
}

pub(crate) struct OptionalAuthUri<'a> {
    pub(crate) userinfo: Option<&'a str>,
    pub(crate) authority: &'a str,
    pub(crate) query: Option<&'a str>,
    pub(crate) name_input: NodeNameInput,
}

pub(crate) struct QueryPair<'a> {
    pub(crate) key: &'a str,
    pub(crate) value: Cow<'a, str>,
}

pub(crate) fn parse_endpoint(input: &str) -> Result<Endpoint, NodeRejection> {
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

pub(crate) fn parse_authority_uri(input: &str) -> Result<AuthorityUri<'_>, NodeRejection> {
    let uri = parse_authority_uri_optional(input)?;
    let userinfo = uri
        .userinfo
        .ok_or(NodeRejection::Invalid(InvalidNodeReason::Uri))?;
    Ok(AuthorityUri {
        userinfo,
        authority: uri.authority,
        query: uri.query,
        name_input: uri.name_input,
    })
}

pub(crate) fn parse_authority_uri_optional(
    input: &str,
) -> Result<OptionalAuthUri<'_>, NodeRejection> {
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

    let (userinfo, remainder) =
        if let Some((userinfo, remainder)) = userinfo_authority_path.split_once('@') {
            if userinfo.contains('/') || remainder.contains('@') {
                return Err(invalid());
            }
            (Some(userinfo), remainder)
        } else {
            (None, userinfo_authority_path)
        };

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
    if authority.is_empty() {
        return Err(invalid());
    }

    Ok(OptionalAuthUri {
        userinfo,
        authority,
        query,
        name_input,
    })
}

pub(crate) fn scan_query(input: &str) -> Result<Vec<QueryPair<'_>>, NodeRejection> {
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
