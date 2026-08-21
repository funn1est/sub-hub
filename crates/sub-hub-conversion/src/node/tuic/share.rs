use uuid::Uuid;

use crate::node::{
    InvalidNodeReason, NodeProtocol, NodeRejection, ProxyNodeDraft, UnsupportedCapability, percent,
    uri::{parse_authority_uri, parse_endpoint, scan_query},
    vless::share as vless,
};

use super::{TuicCongestion, TuicId, TuicNode, TuicPassword, TuicUdpRelay};

pub(crate) fn parse(input: &str) -> Result<ProxyNodeDraft, NodeRejection> {
    let uri = parse_authority_uri(input)?;
    let (id, password) = parse_userinfo(uri.userinfo)?;
    let endpoint = parse_endpoint(uri.authority)?;
    let parameters = parse_parameters(uri.query)?;
    let node = TuicNode::new(
        id,
        password,
        parameters.congestion,
        parameters.udp_relay,
        parameters.sni,
        parameters.alpn,
    )
    .ok_or(NodeRejection::Invalid(
        InvalidNodeReason::IncompatibleParameter,
    ))?;

    Ok(ProxyNodeDraft {
        endpoint,
        name_input: uri.name_input,
        protocol: NodeProtocol::Tuic(node),
    })
}

fn parse_userinfo(userinfo: &str) -> Result<(TuicId, TuicPassword), NodeRejection> {
    let Some((uuid, password)) = userinfo.split_once(':') else {
        return Err(NodeRejection::Unsupported(UnsupportedCapability::Protocol));
    };
    let uuid = percent::decode(uuid)
        .map_err(|()| NodeRejection::Invalid(InvalidNodeReason::PercentEncoding))?;
    if !vless::is_canonical_uuid(uuid.as_ref()) {
        return Err(NodeRejection::Invalid(InvalidNodeReason::Credential));
    }
    let id = Uuid::parse_str(uuid.as_ref())
        .map(TuicId::new)
        .map_err(|_| NodeRejection::Invalid(InvalidNodeReason::Credential))?;
    let password = percent::decode(password)
        .map_err(|()| NodeRejection::Invalid(InvalidNodeReason::PercentEncoding))?;
    let password = TuicPassword::new(password.into_owned())
        .ok_or(NodeRejection::Invalid(InvalidNodeReason::Credential))?;
    Ok((id, password))
}

struct Parameters {
    congestion: TuicCongestion,
    udp_relay: TuicUdpRelay,
    sni: Option<String>,
    alpn: Option<Vec<String>>,
}

fn parse_parameters(query: Option<&str>) -> Result<Parameters, NodeRejection> {
    let mut parameters = Parameters {
        congestion: TuicCongestion::Cubic,
        udp_relay: TuicUdpRelay::Native,
        sni: None,
        alpn: None,
    };
    let Some(query) = query else {
        return Ok(parameters);
    };
    for pair in scan_query(query)? {
        match pair.key {
            "sni" => parameters.sni = Some(vless::nonempty_owned(pair.value)?),
            "alpn" => {
                vless::require_nonempty(pair.value.as_ref())?;
                parameters.alpn = Some(vless::parse_alpn(pair.value.as_ref())?);
            }
            "congestion_control" => {
                parameters.congestion = parse_congestion(pair.value.as_ref())?;
            }
            "udp_relay_mode" => {
                parameters.udp_relay = parse_udp_relay(pair.value.as_ref())?;
            }
            "allow_insecure" | "disable_sni" => parse_refused_flag(pair.value.as_ref())?,
            "udp_over_stream" => {
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
    Ok(parameters)
}

fn parse_congestion(value: &str) -> Result<TuicCongestion, NodeRejection> {
    if value.is_empty() {
        return Ok(TuicCongestion::Cubic);
    }
    match value {
        "cubic" => Ok(TuicCongestion::Cubic),
        "new_reno" => Ok(TuicCongestion::NewReno),
        "bbr" => Ok(TuicCongestion::Bbr),
        _ => Err(NodeRejection::Invalid(InvalidNodeReason::ParameterValue)),
    }
}

fn parse_udp_relay(value: &str) -> Result<TuicUdpRelay, NodeRejection> {
    if value.is_empty() {
        return Ok(TuicUdpRelay::Native);
    }
    match value {
        "native" => Ok(TuicUdpRelay::Native),
        "quic" => Ok(TuicUdpRelay::Quic),
        _ => Err(NodeRejection::Invalid(InvalidNodeReason::ParameterValue)),
    }
}

fn parse_refused_flag(value: &str) -> Result<(), NodeRejection> {
    match value {
        "0" | "false" => Ok(()),
        "1" | "true" => Err(NodeRejection::Unsupported(
            UnsupportedCapability::ProtocolOption,
        )),
        _ => Err(NodeRejection::Invalid(InvalidNodeReason::ParameterValue)),
    }
}
