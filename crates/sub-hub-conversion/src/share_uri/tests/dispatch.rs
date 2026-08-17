use super::{InvalidNodeReason, NodeRejection, UnsupportedCapability, parse_share_uri, rejection};
use crate::node::{NodeNameInput, NodeProtocol, vless::VlessTransport};

#[test]
fn query_and_fragment_use_strict_uri_decoding() {
    let base = "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443";
    let literal = parse_share_uri(&format!(
        "{base}?encryption=%6eone&type=%74cp&security=none#香港+A"
    ))
    .expect("percent-decoded parameter values and literal fragment");
    let encoded = parse_share_uri(&format!(
        "{base}?encryption=none&type=tcp&security=none#%E9%A6%99%E6%B8%AF+A"
    ))
    .expect("UTF-8 percent-encoded fragment");
    assert_eq!(literal.name_input, NodeNameInput::Decoded("香港+A".into()));
    assert_eq!(literal.name_input, encoded.name_input);

    let missing = parse_share_uri(base).expect("missing fragment");
    let empty = parse_share_uri(&format!("{base}#")).expect("explicit empty fragment");
    assert_eq!(missing.name_input, NodeNameInput::Missing);
    assert_eq!(empty.name_input, NodeNameInput::Decoded(String::new()));

    let rejected = [
        (
            format!("{base}?"),
            NodeRejection::Invalid(InvalidNodeReason::Parameter),
        ),
        (
            format!("{base}?type"),
            NodeRejection::Invalid(InvalidNodeReason::Parameter),
        ),
        (
            format!("{base}?=tcp"),
            NodeRejection::Invalid(InvalidNodeReason::Parameter),
        ),
        (
            format!("{base}?type=tcp&"),
            NodeRejection::Invalid(InvalidNodeReason::Parameter),
        ),
        (
            format!("{base}?type=tcp&&security=none"),
            NodeRejection::Invalid(InvalidNodeReason::Parameter),
        ),
        (
            format!("{base}?ty%70e=tcp"),
            NodeRejection::Invalid(InvalidNodeReason::Parameter),
        ),
        (
            format!("{base}?type=tcp&type=ws"),
            NodeRejection::Invalid(InvalidNodeReason::DuplicateParameter),
        ),
        (
            format!("{base}?mystery=one&mystery=two"),
            NodeRejection::Invalid(InvalidNodeReason::DuplicateParameter),
        ),
        (
            format!("{base}?udp=true&udp=false"),
            NodeRejection::Invalid(InvalidNodeReason::DuplicateParameter),
        ),
        (
            format!("{base}?mystery=canary&type=tcp&type=ws"),
            NodeRejection::Invalid(InvalidNodeReason::DuplicateParameter),
        ),
        (
            format!("{base}?mystery=canary&type=%"),
            NodeRejection::Invalid(InvalidNodeReason::PercentEncoding),
        ),
        (
            format!("{base}?udp=true&type=%"),
            NodeRejection::Invalid(InvalidNodeReason::PercentEncoding),
        ),
        (
            format!("{base}?Type=tcp"),
            NodeRejection::Unsupported(UnsupportedCapability::UnknownParameter),
        ),
        (
            format!("{base}?mystery=canary"),
            NodeRejection::Unsupported(UnsupportedCapability::UnknownParameter),
        ),
        (
            format!("{base}?type=%"),
            NodeRejection::Invalid(InvalidNodeReason::PercentEncoding),
        ),
        (
            format!("{base}?type="),
            NodeRejection::Invalid(InvalidNodeReason::ParameterValue),
        ),
        (
            format!("{base}#%"),
            NodeRejection::Invalid(InvalidNodeReason::PercentEncoding),
        ),
        (
            format!("{base}#%FF"),
            NodeRejection::Invalid(InvalidNodeReason::PercentEncoding),
        ),
        (
            format!("{base}#one#two"),
            NodeRejection::Invalid(InvalidNodeReason::Uri),
        ),
    ];

    for (uri, expected) in rejected {
        assert_eq!(rejection(&uri), expected, "fixture: {uri}");
    }
}

#[test]
fn raw_query_delimiters_are_structural_unless_percent_encoded() {
    let base = "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443";
    let encoded = parse_share_uri(&format!("{base}?type=ws&path=%2Fa%3Db%26c"))
        .expect("percent-encoded delimiters are query value data");
    let NodeProtocol::Vless(vless) = encoded.protocol else {
        panic!("expected VLESS")
    };
    assert_eq!(
        vless.transport(),
        &VlessTransport::WebSocket {
            path: "/a=b&c".into(),
            host: None,
        }
    );

    for uri in [
        format!("{base}?type=ws&path=/a=b"),
        format!("{base}?type=ws&path=/a&b"),
    ] {
        assert_eq!(
            rejection(&uri),
            NodeRejection::Invalid(InvalidNodeReason::Parameter),
            "fixture: {uri}"
        );
    }
}

#[test]
fn raw_outer_whitespace_is_rejected_without_trimming_encoded_data() {
    let base = "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443";
    let rejected = [
        format!(" {base}"),
        format!("\t{base}"),
        format!("{base} "),
        format!("{base}#remark\n"),
        format!("{base}?type=ws&path=%2Fchat\t"),
        format!("\u{2003}{base}"),
    ];
    for uri in rejected {
        assert_eq!(
            rejection(&uri),
            NodeRejection::Invalid(InvalidNodeReason::Uri),
            "fixture: {uri:?}"
        );
    }

    let fragment = parse_share_uri(&format!("{base}#remark%20"))
        .expect("encoded trailing fragment space is data");
    assert_eq!(
        fragment.name_input,
        NodeNameInput::Decoded("remark ".into())
    );

    let node = parse_share_uri(&format!("{base}?type=ws&path=%2Fchat%20"))
        .expect("encoded trailing query space is data");
    let NodeProtocol::Vless(vless) = node.protocol else {
        panic!("expected VLESS")
    };
    assert_eq!(
        vless.transport(),
        &VlessTransport::WebSocket {
            path: "/chat ".into(),
            host: None,
        }
    );
}

#[test]
fn supported_protocols_validate_shell_before_query_semantics() {
    let fixtures = [
        (
            "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:0?udp=true",
            NodeRejection::Invalid(InvalidNodeReason::Endpoint),
        ),
        (
            "ss://aes-128-gcm:password@example.com:0?plugin=v2ray-plugin",
            NodeRejection::Invalid(InvalidNodeReason::Endpoint),
        ),
        (
            "trojan://password@example.com:0?udp=true",
            NodeRejection::Invalid(InvalidNodeReason::Endpoint),
        ),
        (
            "hysteria2://letmein@example.com:0?sni=example.com",
            NodeRejection::Invalid(InvalidNodeReason::Endpoint),
        ),
    ];

    for (uri, expected) in fixtures {
        assert_eq!(rejection(uri), expected, "fixture: {uri}");
    }
}

#[test]
fn dispatch_distinguishes_malformed_shells_from_unsupported_protocols() {
    let malformed = [
        "",
        "vless:/payload",
        "vless:payload",
        "ss:/payload",
        "ss:payload",
        "VLESS://payload",
        "SS://payload",
        "TROJAN://payload",
        "VMESS://payload",
        "Hysteria2://payload",
        "HY2://payload",
        "://payload",
        "1scheme://payload",
        "unknown://",
    ];
    for input in malformed {
        assert_eq!(
            rejection(input),
            NodeRejection::Invalid(InvalidNodeReason::Uri),
            "fixture: {input:?}"
        );
    }

    for input in ["tuic://payload", "unknown+v1://payload"] {
        assert_eq!(
            rejection(input),
            NodeRejection::Unsupported(UnsupportedCapability::Protocol),
            "fixture: {input:?}"
        );
    }
}
