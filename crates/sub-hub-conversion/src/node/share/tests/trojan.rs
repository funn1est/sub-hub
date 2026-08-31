use super::{InvalidNodeReason, NodeRejection, UnsupportedCapability, parse_share_uri, rejection};
use crate::node::{
    Host, NodeNameInput, NodeProtocol,
    trojan::TrojanSecurity,
    vless::{ClientFingerprint, GrpcMode, RealityShortId, TlsOptions, VlessTransport},
};

const PBK: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[test]
fn trojan_without_query_defaults_to_tcp_tls() {
    let node = parse_share_uri("trojan://p%40ss:word@EXAMPLE.COM:443#Alpha")
        .expect("valid default Trojan URI");

    assert_eq!(node.endpoint.host(), &Host::Domain("example.com".into()));
    assert_eq!(node.endpoint.port().get(), 443);
    assert_eq!(node.name_input, NodeNameInput::Decoded("Alpha".into()));
    let NodeProtocol::Trojan(trojan) = node.protocol else {
        panic!("expected Trojan")
    };
    assert_eq!(trojan.password().expose(), "p@ss:word");
    assert_eq!(trojan.transport(), &VlessTransport::Tcp);
    assert_eq!(
        trojan.security(),
        &TrojanSecurity::Tls(
            TlsOptions::new("example.com".into(), None, ClientFingerprint::Chrome)
                .expect("valid TLS fixture")
        )
    );
}

#[test]
fn trojan_shell_and_password_grammar_is_strict() {
    let accepted = parse_share_uri("trojan://pass word@192.0.2.1:1").expect("space is data");
    let NodeProtocol::Trojan(trojan) = accepted.protocol else {
        panic!("expected Trojan")
    };
    assert_eq!(trojan.password().expose(), "pass word");

    let rejected = [
        (
            "TROJAN://password@example.com:443",
            NodeRejection::Invalid(InvalidNodeReason::Uri),
        ),
        (
            "Trojan://password@example.com:443",
            NodeRejection::Invalid(InvalidNodeReason::Uri),
        ),
        (
            " trojan://password@example.com:443",
            NodeRejection::Invalid(InvalidNodeReason::Uri),
        ),
        (
            "trojan://password@example.com:443 ",
            NodeRejection::Invalid(InvalidNodeReason::Uri),
        ),
        (
            "trojan://@example.com:443",
            NodeRejection::Invalid(InvalidNodeReason::Credential),
        ),
        (
            "trojan://%00@example.com:443",
            NodeRejection::Invalid(InvalidNodeReason::Credential),
        ),
        (
            "trojan://%0a@example.com:443",
            NodeRejection::Invalid(InvalidNodeReason::Credential),
        ),
        (
            "trojan://pass%ZZ@example.com:443",
            NodeRejection::Invalid(InvalidNodeReason::PercentEncoding),
        ),
        (
            "trojan://pass@word@example.com:443",
            NodeRejection::Invalid(InvalidNodeReason::Uri),
        ),
        (
            "trojan://password@example.com:0",
            NodeRejection::Invalid(InvalidNodeReason::Endpoint),
        ),
        (
            "trojan://password@example.com",
            NodeRejection::Invalid(InvalidNodeReason::Endpoint),
        ),
    ];
    for (uri, expected) in rejected {
        assert_eq!(rejection(uri), expected, "fixture: {uri}");
    }
}

#[test]
fn trojan_peer_is_a_clash_legacy_sni_alias() {
    let via_peer =
        parse_share_uri("trojan://password@example.com:443?allowInsecure=0&peer=edge.example")
            .expect("Clash-style peer SNI");
    let NodeProtocol::Trojan(via_peer) = via_peer.protocol else {
        panic!("expected Trojan")
    };
    let TrojanSecurity::Tls(options) = via_peer.security() else {
        panic!("expected TLS")
    };
    assert_eq!(options.server_name(), "edge.example");

    let matching =
        parse_share_uri("trojan://password@example.com:443?sni=edge.example&peer=edge.example")
            .expect("equal peer and sni");
    let NodeProtocol::Trojan(matching) = matching.protocol else {
        panic!("expected Trojan")
    };
    let TrojanSecurity::Tls(options) = matching.security() else {
        panic!("expected TLS")
    };
    assert_eq!(options.server_name(), "edge.example");

    assert_eq!(
        rejection("trojan://password@example.com:443?sni=one.example&peer=two.example"),
        NodeRejection::Invalid(InvalidNodeReason::IncompatibleParameter)
    );
}

#[test]
fn trojan_allow_insecure_is_closed() {
    parse_share_uri("trojan://password@example.com:443?allowInsecure=false")
        .expect("explicit verify");
    parse_share_uri("trojan://password@example.com:443?insecure=0").expect("legacy verify");
    parse_share_uri("trojan://password@example.com:443?udp=true&mux=0")
        .expect("default client flags");

    assert_eq!(
        rejection("trojan://password@example.com:443?allowInsecure=1"),
        NodeRejection::Unsupported(UnsupportedCapability::ProtocolOption)
    );
    assert_eq!(
        rejection("trojan://password@example.com:443?insecure=true"),
        NodeRejection::Unsupported(UnsupportedCapability::ProtocolOption)
    );
    assert_eq!(
        rejection("trojan://password@example.com:443?allowInsecure=yes"),
        NodeRejection::Invalid(InvalidNodeReason::ParameterValue)
    );
}

#[test]
fn trojan_ws_and_grpc_require_tls_or_reality() {
    let ws =
        parse_share_uri("trojan://password@example.com:443?type=ws&path=%2Fchat&host=cdn.example")
            .expect("WS defaults to TLS");
    let NodeProtocol::Trojan(ws) = ws.protocol else {
        panic!("expected Trojan")
    };
    assert_eq!(
        ws.transport(),
        &VlessTransport::WebSocket {
            path: "/chat".into(),
            host: Some("cdn.example".into()),
        }
    );
    assert!(matches!(ws.security(), TrojanSecurity::Tls(_)));

    let grpc = parse_share_uri("trojan://password@example.com:443?type=grpc&serviceName=svc")
        .expect("gRPC defaults to TLS");
    let NodeProtocol::Trojan(grpc) = grpc.protocol else {
        panic!("expected Trojan")
    };
    assert_eq!(
        grpc.transport(),
        &VlessTransport::Grpc {
            service_name: Some("svc".into()),
            mode: GrpcMode::Gun,
        }
    );

    assert_eq!(
        rejection("trojan://password@example.com:443?security=none"),
        NodeRejection::Unsupported(UnsupportedCapability::Security)
    );
    assert_eq!(
        rejection("trojan://password@example.com:443?type=ws&security=none"),
        NodeRejection::Unsupported(UnsupportedCapability::Security)
    );
}

#[test]
fn trojan_accepts_websocket_reality() {
    let node = parse_share_uri(&format!(
        "trojan://password@example.com:443?type=ws&path=%2Fws&security=reality&sni=edge.example&pbk={PBK}&sid=0a1b"
    ))
    .expect("WS + Reality is legal for Trojan");
    let NodeProtocol::Trojan(trojan) = node.protocol else {
        panic!("expected Trojan")
    };
    assert!(matches!(
        trojan.transport(),
        VlessTransport::WebSocket { .. }
    ));
    let TrojanSecurity::Reality(options) = trojan.security() else {
        panic!("expected Reality")
    };
    assert_eq!(options.tls().server_name(), "edge.example");
    assert_eq!(options.tls().fingerprint(), ClientFingerprint::Chrome);
    assert_eq!(options.short_id().map(RealityShortId::byte_len), Some(2));
}

#[test]
fn trojan_reality_fingerprint_defaults_to_chrome() {
    let node = parse_share_uri(&format!(
        "trojan://password@example.com:443?security=reality&pbk={PBK}"
    ))
    .expect("omitted fp defaults");
    let NodeProtocol::Trojan(trojan) = node.protocol else {
        panic!("expected Trojan")
    };
    let TrojanSecurity::Reality(options) = trojan.security() else {
        panic!("expected Reality")
    };
    assert_eq!(options.tls().fingerprint(), ClientFingerprint::Chrome);
    assert_eq!(options.tls().server_name(), "example.com");
}

#[test]
fn trojan_header_type_none_is_omitted_tcp_header() {
    let omitted = parse_share_uri("trojan://password@example.com:443")
        .expect("default Trojan without headerType");
    let none = parse_share_uri("trojan://password@example.com:443?headerType=none")
        .expect("headerType=none is a no-op");
    assert_eq!(none, omitted);
}

#[test]
fn trojan_spiderx_is_omitted_reality_path() {
    let omitted = parse_share_uri("trojan://password@example.com:443")
        .expect("default Trojan without spiderX");
    for uri in [
        "trojan://password@example.com:443?spx=%2F",
        "trojan://password@example.com:443?spiderx=%2F",
        "trojan://password@example.com:443?spiderX=%2F",
        "trojan://password@example.com:443?spx=",
    ] {
        let parsed = parse_share_uri(uri).expect("spiderX is a no-op");
        assert_eq!(parsed, omitted, "fixture: {uri}");
    }
}

#[test]
fn trojan_refuses_known_unsupported_options() {
    let rejected = [
        (
            "trojan://password@example.com:443?flow=xtls-rprx-vision",
            NodeRejection::Unsupported(UnsupportedCapability::ProtocolOption),
        ),
        (
            "trojan://password@example.com:443?type=http",
            NodeRejection::Unsupported(UnsupportedCapability::Transport),
        ),
        (
            "trojan://password@example.com:443?type=grpc&service-name=svc",
            NodeRejection::Unsupported(UnsupportedCapability::TransportOption),
        ),
        (
            "trojan://password@example.com:443?type=grpc&mode=multi",
            NodeRejection::Unsupported(UnsupportedCapability::TransportOption),
        ),
        (
            "trojan://password@example.com:443?mux=1",
            NodeRejection::Unsupported(UnsupportedCapability::ProtocolOption),
        ),
        (
            "trojan://password@example.com:443?headerType=http",
            NodeRejection::Unsupported(UnsupportedCapability::ProtocolOption),
        ),
        (
            "trojan://password@example.com:443?mystery=one",
            NodeRejection::Unsupported(UnsupportedCapability::UnknownParameter),
        ),
        (
            "trojan-go://password@example.com:443",
            NodeRejection::Unsupported(UnsupportedCapability::Protocol),
        ),
    ];
    for (uri, expected) in rejected {
        assert_eq!(rejection(uri), expected, "fixture: {uri}");
    }
}
