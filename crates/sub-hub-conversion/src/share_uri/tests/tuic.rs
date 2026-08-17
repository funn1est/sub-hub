use super::{InvalidNodeReason, NodeRejection, UnsupportedCapability, parse_share_uri, rejection};
use crate::node::{
    Host, NodeNameInput, NodeProtocol,
    tuic::{TuicCongestion, TuicUdpRelay},
};

const UUID: &str = "01234567-89ab-cdef-0123-456789abcdef";

#[test]
fn tuic_v5_defaults_to_cubic_and_native() {
    let node = parse_share_uri(&format!("tuic://{UUID}:p%40ss@EXAMPLE.COM:443#Alpha"))
        .expect("valid default TUIC v5 URI");

    assert_eq!(node.endpoint.host(), &Host::Domain("example.com".into()));
    assert_eq!(node.endpoint.port().get(), 443);
    assert_eq!(node.name_input, NodeNameInput::Decoded("Alpha".into()));
    let NodeProtocol::Tuic(tuic) = node.protocol else {
        panic!("expected TUIC")
    };
    assert_eq!(tuic.id().as_uuid().hyphenated().to_string(), UUID);
    assert_eq!(tuic.password().expose(), "p@ss");
    assert_eq!(tuic.congestion(), TuicCongestion::Cubic);
    assert_eq!(tuic.udp_relay(), TuicUdpRelay::Native);
    assert_eq!(tuic.sni(), None);
    assert_eq!(tuic.alpn(), None);
}

#[test]
fn tuic_accepts_password_colon_and_closed_options() {
    let node = parse_share_uri(&format!(
        "tuic://{UUID}:a:b@example.com:8443/?sni=real.example&alpn=h3&congestion_control=bbr&udp_relay_mode=quic"
    ))
    .expect("valid optioned TUIC URI");
    let NodeProtocol::Tuic(tuic) = node.protocol else {
        panic!("expected TUIC")
    };
    assert_eq!(tuic.password().expose(), "a:b");
    assert_eq!(tuic.congestion(), TuicCongestion::Bbr);
    assert_eq!(tuic.udp_relay(), TuicUdpRelay::Quic);
    assert_eq!(tuic.sni(), Some("real.example"));
    assert_eq!(tuic.alpn(), Some(["h3".to_owned()].as_slice()));
}

#[test]
fn tuic_insecure_flags_and_closed_keys() {
    parse_share_uri(&format!(
        "tuic://{UUID}:pass@example.com:443/?allow_insecure=0"
    ))
    .expect("verify");
    parse_share_uri(&format!(
        "tuic://{UUID}:pass@example.com:443/?disable_sni=false"
    ))
    .expect("sni on");

    let rejected = [
        (
            format!("TUIC://{UUID}:pass@example.com:443"),
            NodeRejection::Invalid(InvalidNodeReason::Uri),
        ),
        (
            format!("tuic://{UUID}:pass@example.com"),
            NodeRejection::Invalid(InvalidNodeReason::Endpoint),
        ),
        (
            format!("tuic://{UUID}:@example.com:443"),
            NodeRejection::Invalid(InvalidNodeReason::Credential),
        ),
        (
            format!("tuic://{UUID}:%00@example.com:443"),
            NodeRejection::Invalid(InvalidNodeReason::Credential),
        ),
        (
            "tuic://NOT-A-UUID:pass@example.com:443".to_owned(),
            NodeRejection::Invalid(InvalidNodeReason::Credential),
        ),
        (
            format!("tuic://{UUID}:pass@example.com:443/?congestion_control=newreno"),
            NodeRejection::Invalid(InvalidNodeReason::ParameterValue),
        ),
        (
            format!("tuic://{UUID}:pass@example.com:443/?udp_relay_mode=datagram"),
            NodeRejection::Invalid(InvalidNodeReason::ParameterValue),
        ),
        (
            format!("tuic://{UUID}:pass@example.com:443/?allow_insecure=yes"),
            NodeRejection::Invalid(InvalidNodeReason::ParameterValue),
        ),
        (
            format!("tuic://{UUID}:pass@example.com:443/?allow_insecure=1"),
            NodeRejection::Unsupported(UnsupportedCapability::ProtocolOption),
        ),
        (
            format!("tuic://{UUID}:pass@example.com:443/?disable_sni=1"),
            NodeRejection::Unsupported(UnsupportedCapability::ProtocolOption),
        ),
        (
            format!("tuic://{UUID}:pass@example.com:443/?udp_over_stream=1"),
            NodeRejection::Unsupported(UnsupportedCapability::ProtocolOption),
        ),
        (
            format!("tuic://{UUID}:pass@example.com:443/?allowInsecure=0"),
            NodeRejection::Unsupported(UnsupportedCapability::UnknownParameter),
        ),
        (
            format!("tuic://{UUID}:pass@example.com:443/?peer=edge.example"),
            NodeRejection::Unsupported(UnsupportedCapability::UnknownParameter),
        ),
        (
            "tuic://token-only@example.com:443".to_owned(),
            NodeRejection::Unsupported(UnsupportedCapability::Protocol),
        ),
    ];
    for (uri, expected) in rejected {
        assert_eq!(rejection(&uri), expected, "fixture: {uri}");
    }
}
