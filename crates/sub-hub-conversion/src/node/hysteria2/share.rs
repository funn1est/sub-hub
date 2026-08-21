use std::{
    net::{Ipv4Addr, Ipv6Addr},
    num::NonZeroU16,
};

use crate::node::{
    Endpoint, Host, InvalidNodeReason, NodeProtocol, NodeRejection, ProxyNodeDraft,
    UnsupportedCapability, percent,
    uri::{parse_authority_uri_optional, scan_query},
    vless::share as vless,
};

use super::{Hysteria2Auth, Hysteria2Node, Hysteria2Obfs, Hysteria2PortAtom, Hysteria2Ports};

pub(crate) fn parse(input: &str) -> Result<ProxyNodeDraft, NodeRejection> {
    let uri = parse_authority_uri_optional(input)?;
    let auth = parse_auth(uri.userinfo)?;
    let (endpoint, ports) = parse_hysteria2_authority(uri.authority)?;
    let parameters = parse_parameters(uri.query)?;
    let node = Hysteria2Node::new(
        auth,
        ports,
        parameters.sni,
        parameters.obfs,
        parameters.pin_sha256,
    )
    .ok_or(NodeRejection::Invalid(
        InvalidNodeReason::IncompatibleParameter,
    ))?;

    Ok(ProxyNodeDraft {
        endpoint,
        name_input: uri.name_input,
        protocol: NodeProtocol::Hysteria2(node),
    })
}

fn parse_auth(userinfo: Option<&str>) -> Result<Hysteria2Auth, NodeRejection> {
    let Some(userinfo) = userinfo else {
        return Hysteria2Auth::new(String::new())
            .ok_or(NodeRejection::Invalid(InvalidNodeReason::Credential));
    };
    let decoded = if let Some((username, password)) = userinfo.split_once(':') {
        let username = percent::decode(username)
            .map_err(|()| NodeRejection::Invalid(InvalidNodeReason::PercentEncoding))?;
        let password = percent::decode(password)
            .map_err(|()| NodeRejection::Invalid(InvalidNodeReason::PercentEncoding))?;
        format!("{username}:{password}")
    } else {
        percent::decode(userinfo)
            .map_err(|()| NodeRejection::Invalid(InvalidNodeReason::PercentEncoding))?
            .into_owned()
    };
    Hysteria2Auth::new(decoded).ok_or(NodeRejection::Invalid(InvalidNodeReason::Credential))
}

fn parse_hysteria2_authority(input: &str) -> Result<(Endpoint, Hysteria2Ports), NodeRejection> {
    let invalid = || NodeRejection::Invalid(InvalidNodeReason::Endpoint);
    let (host, port) = if let Some(bracketed) = input.strip_prefix('[') {
        let (address, suffix) = bracketed.split_once(']').ok_or_else(invalid)?;
        if address.contains('%') {
            return Err(invalid());
        }
        let address = address.parse::<Ipv6Addr>().map_err(|_| invalid())?;
        let port = if suffix.is_empty() {
            None
        } else {
            Some(suffix.strip_prefix(':').ok_or_else(invalid)?)
        };
        (Host::Ipv6(address), port)
    } else if let Some((host, port)) = input.rsplit_once(':') {
        if host.contains(':') {
            return Err(invalid());
        }
        let host = if let Ok(address) = host.parse::<Ipv4Addr>() {
            Host::Ipv4(address)
        } else {
            Host::Domain(host.to_owned())
        };
        (host, Some(port))
    } else {
        let host = if let Ok(address) = input.parse::<Ipv4Addr>() {
            Host::Ipv4(address)
        } else {
            Host::Domain(input.to_owned())
        };
        (host, None)
    };

    let ports = match port {
        None => Hysteria2Ports::Single(NonZeroU16::new(443).expect("443 is nonzero")),
        Some(port) => parse_port_union(port)?,
    };
    let endpoint = Endpoint::new(host, ports.first_port().get()).ok_or_else(invalid)?;
    Ok((endpoint, ports))
}

fn parse_port_union(input: &str) -> Result<Hysteria2Ports, NodeRejection> {
    let invalid = || NodeRejection::Invalid(InvalidNodeReason::Endpoint);
    if !(input.contains('-') || input.contains(',')) {
        let port = parse_single_port(input)?;
        return Ok(Hysteria2Ports::Single(port));
    }
    let mut atoms = Vec::new();
    for atom in input.split(',') {
        if atom.is_empty() {
            return Err(invalid());
        }
        if let Some((start, end)) = atom.split_once('-') {
            if end.contains('-') {
                return Err(invalid());
            }
            let start = parse_single_port(start)?;
            let end = parse_single_port(end)?;
            atoms.push(Hysteria2PortAtom::range(start, end).ok_or_else(invalid)?);
        } else {
            atoms.push(Hysteria2PortAtom::Single(parse_single_port(atom)?));
        }
    }
    Hysteria2Ports::hop(atoms).ok_or_else(invalid)
}

fn parse_single_port(input: &str) -> Result<NonZeroU16, NodeRejection> {
    let invalid = || NodeRejection::Invalid(InvalidNodeReason::Endpoint);
    if input.is_empty() || !input.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid());
    }
    let port = input.parse::<u16>().map_err(|_| invalid())?;
    NonZeroU16::new(port).ok_or_else(invalid)
}

struct Parameters {
    sni: Option<String>,
    obfs: Option<Hysteria2Obfs>,
    pin_sha256: Option<[u8; 32]>,
}

fn parse_parameters(query: Option<&str>) -> Result<Parameters, NodeRejection> {
    let Some(query) = query else {
        return Ok(Parameters {
            sni: None,
            obfs: None,
            pin_sha256: None,
        });
    };
    let pairs = scan_query(query)?;
    let mut sni = None;
    let mut obfs_type = None;
    let mut obfs_password = None;
    let mut pin_sha256 = None;

    for pair in &pairs {
        match pair.key {
            "obfs" => {
                vless::require_nonempty(pair.value.as_ref())?;
                obfs_type = Some(pair.value.as_ref());
            }
            "obfs-password" => {
                obfs_password = Some(vless::nonempty_owned(pair.value.clone())?);
            }
            "sni" => sni = Some(vless::nonempty_owned(pair.value.clone())?),
            "insecure" => parse_insecure_flag(pair.value.as_ref())?,
            "pinSHA256" => pin_sha256 = Some(parse_pin_sha256(pair.value.as_ref())?),
            "ech" => {
                return Err(NodeRejection::Unsupported(
                    UnsupportedCapability::ProtocolOption,
                ));
            }
            _ => {
                return Err(NodeRejection::Unsupported(
                    UnsupportedCapability::UnknownParameter,
                ));
            }
        }
    }

    let obfs = match (obfs_type, obfs_password) {
        (None, None) => None,
        (Some("salamander"), Some(password)) => Some(Hysteria2Obfs::salamander(password).ok_or(
            NodeRejection::Invalid(InvalidNodeReason::IncompatibleParameter),
        )?),
        (Some("gecko"), Some(password)) => Some(Hysteria2Obfs::gecko(password).ok_or(
            NodeRejection::Invalid(InvalidNodeReason::IncompatibleParameter),
        )?),
        (Some("salamander" | "gecko"), None) | (None, Some(_)) => {
            return Err(NodeRejection::Invalid(
                InvalidNodeReason::IncompatibleParameter,
            ));
        }
        (Some(_), _) => {
            return Err(NodeRejection::Unsupported(
                UnsupportedCapability::ProtocolOption,
            ));
        }
    };

    Ok(Parameters {
        sni,
        obfs,
        pin_sha256,
    })
}

fn parse_insecure_flag(value: &str) -> Result<(), NodeRejection> {
    match value {
        "0" | "false" => Ok(()),
        "1" | "true" => Err(NodeRejection::Unsupported(
            UnsupportedCapability::ProtocolOption,
        )),
        _ => Err(NodeRejection::Invalid(InvalidNodeReason::ParameterValue)),
    }
}

fn parse_pin_sha256(value: &str) -> Result<[u8; 32], NodeRejection> {
    let mut hex = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            ':' | '-' => {}
            '0'..='9' | 'a'..='f' | 'A'..='F' => hex.push(character.to_ascii_lowercase()),
            _ => {
                return Err(NodeRejection::Invalid(InvalidNodeReason::ParameterValue));
            }
        }
    }
    if hex.len() != 64 {
        return Err(NodeRejection::Invalid(InvalidNodeReason::ParameterValue));
    }
    let mut bytes = [0_u8; 32];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let digit = |byte| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        let high =
            digit(chunk[0]).ok_or(NodeRejection::Invalid(InvalidNodeReason::ParameterValue))?;
        let low =
            digit(chunk[1]).ok_or(NodeRejection::Invalid(InvalidNodeReason::ParameterValue))?;
        bytes[index] = (high << 4) | low;
    }
    Ok(bytes)
}
