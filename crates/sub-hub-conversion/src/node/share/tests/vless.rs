use super::{InvalidNodeReason, NodeRejection, UnsupportedCapability, parse_share_uri, rejection};
use crate::node::{
    Host, NodeNameInput, NodeProtocol,
    vless::{
        ClientFingerprint, GrpcMode, RealityShortId, TlsOptions, VlessFlow, VlessSecurity,
        VlessTransport,
    },
};

#[test]
fn vless_tcp_without_security_is_accepted() {
    let uri = "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443";

    let node = parse_share_uri(uri).expect("valid default VLESS URI");

    assert_eq!(node.endpoint.host(), &Host::Domain("example.com".into()));
    assert_eq!(node.endpoint.port().get(), 443);
    assert_eq!(node.name_input, NodeNameInput::Missing);
    let NodeProtocol::Vless(vless) = node.protocol else {
        panic!("expected VLESS")
    };
    assert_eq!(vless.transport(), &VlessTransport::Tcp);
    assert_eq!(vless.security(), &VlessSecurity::None);
    assert_eq!(vless.flow(), None);
}

#[test]
fn vless_shell_and_endpoint_grammar_is_strict() {
    let uuid = "01234567-89ab-cdef-0123-456789abcdef";
    let accepted = [
        (
            format!("vless://{uuid}@EXAMPLE.COM:1"),
            Host::Domain("example.com".into()),
            1,
        ),
        (
            format!("vless://{uuid}@192.0.2.1:65535/"),
            Host::Ipv4("192.0.2.1".parse().expect("fixture IPv4")),
            65_535,
        ),
        (
            format!("vless://{uuid}@[2001:db8::1]:443"),
            Host::Ipv6("2001:db8::1".parse().expect("fixture IPv6")),
            443,
        ),
    ];

    for (uri, expected_host, expected_port) in accepted {
        let node = parse_share_uri(&uri).expect("accepted shell fixture");
        assert_eq!(node.endpoint.host(), &expected_host, "fixture: {uri}");
        assert_eq!(node.endpoint.port().get(), expected_port, "fixture: {uri}");
    }

    let rejected = [
        (
            format!("VLESS://{uuid}@example.com:443"),
            NodeRejection::Invalid(InvalidNodeReason::Uri),
        ),
        (
            format!(" vless://{uuid}@example.com:443"),
            NodeRejection::Invalid(InvalidNodeReason::Uri),
        ),
        (
            format!("vless://{uuid}@example.com:443 "),
            NodeRejection::Invalid(InvalidNodeReason::Uri),
        ),
        (
            "vless://01234567-89AB-cdef-0123-456789abcdef@example.com:443".into(),
            NodeRejection::Invalid(InvalidNodeReason::Credential),
        ),
        (
            "vless://0123456789abcdef0123456789abcdef@example.com:443".into(),
            NodeRejection::Invalid(InvalidNodeReason::Credential),
        ),
        (
            "vless://01234567%2d89ab-cdef-0123-456789abcdef@example.com:443".into(),
            NodeRejection::Invalid(InvalidNodeReason::Credential),
        ),
        (
            format!("vless://{uuid}:password@example.com:443"),
            NodeRejection::Invalid(InvalidNodeReason::Uri),
        ),
        (
            format!("vless://{uuid}@@example.com:443"),
            NodeRejection::Invalid(InvalidNodeReason::Uri),
        ),
        (
            format!("vless://{uuid}@例子.测试:443"),
            NodeRejection::Invalid(InvalidNodeReason::Endpoint),
        ),
        (
            format!("vless://{uuid}@example%2ecom:443"),
            NodeRejection::Invalid(InvalidNodeReason::Endpoint),
        ),
        (
            format!("vless://{uuid}@2001:db8::1:443"),
            NodeRejection::Invalid(InvalidNodeReason::Endpoint),
        ),
        (
            format!("vless://{uuid}@[fe80::1%25eth0]:443"),
            NodeRejection::Invalid(InvalidNodeReason::Endpoint),
        ),
        (
            format!("vless://{uuid}@example.com"),
            NodeRejection::Invalid(InvalidNodeReason::Endpoint),
        ),
        (
            format!("vless://{uuid}@example.com:0"),
            NodeRejection::Invalid(InvalidNodeReason::Endpoint),
        ),
        (
            format!("vless://{uuid}@example.com:65536"),
            NodeRejection::Invalid(InvalidNodeReason::Endpoint),
        ),
        (
            format!("vless://{uuid}@example.com:443/path"),
            NodeRejection::Invalid(InvalidNodeReason::Uri),
        ),
    ];

    for (uri, expected) in rejected {
        assert_eq!(rejection(&uri), expected, "fixture: {uri}");
    }
}

#[test]
fn vless_dns_names_observe_label_and_total_length_boundaries() {
    let uuid = "01234567-89ab-cdef-0123-456789abcdef";
    let label_63 = "a".repeat(63);
    let label_64 = "a".repeat(64);
    let domain_253 = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    let domain_254 = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(62)
    );

    for domain in [&label_63, &domain_253] {
        let uri = format!("vless://{uuid}@{domain}:443");
        let node = parse_share_uri(&uri).expect("DNS boundary fixture");
        assert_eq!(node.endpoint.host(), &Host::Domain(domain.clone()));
    }

    for domain in [&label_64, &domain_254] {
        let uri = format!("vless://{uuid}@{domain}:443");
        assert_eq!(
            rejection(&uri),
            NodeRejection::Invalid(InvalidNodeReason::Endpoint),
            "fixture length: {}",
            domain.len()
        );
    }
}

#[test]
fn vless_punycode_is_canonicalized_and_numeric_ipv4_lookalikes_are_rejected() {
    let uuid = "01234567-89ab-cdef-0123-456789abcdef";
    let node = parse_share_uri(&format!("vless://{uuid}@XN--FSQU00A.XN--0ZWM56D:443"))
        .expect("ASCII punycode domain");
    assert_eq!(
        node.endpoint.host(),
        &Host::Domain("xn--fsqu00a.xn--0zwm56d".into())
    );

    for host in ["192.0.2.01", "999.1.1.1", "127.1"] {
        let uri = format!("vless://{uuid}@{host}:443");
        assert_eq!(
            rejection(&uri),
            NodeRejection::Invalid(InvalidNodeReason::Endpoint),
            "fixture: {uri}"
        );
    }
}

#[test]
fn vless_ids_compare_by_canonical_uuid_value() {
    let same_id = "01234567-89ab-cdef-0123-456789abcdef";
    let first = parse_share_uri(&format!(
        "vless://{same_id}@EXAMPLE.COM:443?type=%74cp#literal"
    ))
    .expect("first URI spelling");
    let equivalent = parse_share_uri(&format!("vless://{same_id}@example.com:443/#%6citeral"))
        .expect("equivalent URI spelling");
    let changed = parse_share_uri("vless://01234567-89ab-cdef-0123-456789abcdee@example.com:443")
        .expect("different UUID");

    let NodeProtocol::Vless(first) = first.protocol else {
        panic!("expected VLESS")
    };
    let NodeProtocol::Vless(equivalent) = equivalent.protocol else {
        panic!("expected VLESS")
    };
    let NodeProtocol::Vless(changed) = changed.protocol else {
        panic!("expected VLESS")
    };
    assert_eq!(first.id(), equivalent.id());
    assert_ne!(first.id(), changed.id());
}

#[test]
fn vless_transport_options_are_typed_and_scoped() {
    let base = "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443/";

    let ws = parse_share_uri(&format!(
        "{base}?type=ws&path=%2Fchat%3Fa%3Db%26c%3Dd+tail&host=cdn+edge.example"
    ))
    .expect("WebSocket transport");
    let NodeProtocol::Vless(ws) = ws.protocol else {
        panic!("expected VLESS")
    };
    assert_eq!(
        ws.transport(),
        &VlessTransport::WebSocket {
            path: "/chat?a=b&c=d+tail".into(),
            host: Some("cdn+edge.example".into()),
        }
    );

    let ws_defaults = parse_share_uri(&format!("{base}?type=ws")).expect("WebSocket defaults");
    let NodeProtocol::Vless(ws_defaults) = ws_defaults.protocol else {
        panic!("expected VLESS")
    };
    assert_eq!(
        ws_defaults.transport(),
        &VlessTransport::WebSocket {
            path: "/".into(),
            host: None,
        }
    );

    let grpc = parse_share_uri(&format!("{base}?type=grpc&serviceName=svc+name&mode=gun"))
        .expect("gRPC transport");
    let NodeProtocol::Vless(grpc) = grpc.protocol else {
        panic!("expected VLESS")
    };
    assert_eq!(
        grpc.transport(),
        &VlessTransport::Grpc {
            service_name: Some("svc+name".into()),
            mode: GrpcMode::Gun,
        }
    );

    let grpc_defaults = parse_share_uri(&format!("{base}?type=grpc")).expect("gRPC defaults");
    let NodeProtocol::Vless(grpc_defaults) = grpc_defaults.protocol else {
        panic!("expected VLESS")
    };
    assert_eq!(
        grpc_defaults.transport(),
        &VlessTransport::Grpc {
            service_name: None,
            mode: GrpcMode::Gun,
        }
    );

    let rejected = [
        (
            format!("{base}?path=%2Fchat"),
            NodeRejection::Invalid(InvalidNodeReason::IncompatibleParameter),
        ),
        (
            format!("{base}?type=ws&serviceName=svc"),
            NodeRejection::Invalid(InvalidNodeReason::IncompatibleParameter),
        ),
        (
            format!("{base}?type=grpc&host=cdn.example"),
            NodeRejection::Invalid(InvalidNodeReason::IncompatibleParameter),
        ),
        (
            format!("{base}?type=ws&path="),
            NodeRejection::Invalid(InvalidNodeReason::ParameterValue),
        ),
        (
            format!("{base}?type=ws&host="),
            NodeRejection::Invalid(InvalidNodeReason::ParameterValue),
        ),
        (
            format!("{base}?type=grpc&serviceName="),
            NodeRejection::Invalid(InvalidNodeReason::ParameterValue),
        ),
        (
            format!("{base}?type=grpc&mode=multi"),
            NodeRejection::Unsupported(UnsupportedCapability::TransportOption),
        ),
        (
            format!("{base}?type=grpc&mode=guna"),
            NodeRejection::Unsupported(UnsupportedCapability::TransportOption),
        ),
        (
            format!("{base}?type=grpc&authority=cdn.example"),
            NodeRejection::Unsupported(UnsupportedCapability::TransportOption),
        ),
        (
            format!("{base}?type=grpc&service-name=svc"),
            NodeRejection::Unsupported(UnsupportedCapability::TransportOption),
        ),
        (
            format!("{base}?type=kcp"),
            NodeRejection::Unsupported(UnsupportedCapability::Transport),
        ),
    ];

    for (uri, expected) in rejected {
        assert_eq!(rejection(&uri), expected, "fixture: {uri}");
    }
}

#[test]
fn vless_dependent_parameters_may_precede_their_discriminators() {
    let base = "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443";
    let websocket = parse_share_uri(&format!("{base}?path=%2Fchat&host=cdn.example&type=ws"))
        .expect("WebSocket fields before type");
    let NodeProtocol::Vless(websocket) = websocket.protocol else {
        panic!("expected VLESS")
    };
    assert_eq!(
        websocket.transport(),
        &VlessTransport::WebSocket {
            path: "/chat".into(),
            host: Some("cdn.example".into()),
        }
    );

    let pbk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let reality = parse_share_uri(&format!(
        "{base}?sni=cdn.example&fp=chrome&pbk={pbk}&sid=0a&security=reality"
    ))
    .expect("Reality fields before security");
    let NodeProtocol::Vless(reality) = reality.protocol else {
        panic!("expected VLESS")
    };
    let VlessSecurity::Reality(options) = reality.security() else {
        panic!("expected Reality")
    };
    assert_eq!(options.tls().server_name(), "cdn.example");
    assert_eq!(options.public_key().byte_len(), 32);
    assert_eq!(options.short_id().map(RealityShortId::byte_len), Some(1));
}

#[test]
fn vless_tls_options_are_typed_and_scoped() {
    let uuid = "01234567-89ab-cdef-0123-456789abcdef";
    let tls = parse_share_uri(&format!("vless://{uuid}@EXAMPLE.COM:443?security=tls"))
        .expect("TLS defaults");
    let NodeProtocol::Vless(tls) = tls.protocol else {
        panic!("expected VLESS")
    };
    assert_eq!(
        tls.security(),
        &VlessSecurity::Tls(
            TlsOptions::new("example.com".into(), None, ClientFingerprint::Chrome)
                .expect("valid TLS fixture")
        )
    );

    let ws_tls = parse_share_uri(&format!(
        "vless://{uuid}@example.com:443?type=ws&security=tls&sni=cdn.example&alpn=h2%2Chttp%2F1.1&fp=firefox"
    ))
    .expect("WebSocket TLS options");
    let NodeProtocol::Vless(ws_tls) = ws_tls.protocol else {
        panic!("expected VLESS")
    };
    assert_eq!(
        ws_tls.security(),
        &VlessSecurity::Tls(
            TlsOptions::new(
                "cdn.example".into(),
                Some(vec!["h2".into(), "http/1.1".into()]),
                ClientFingerprint::Firefox,
            )
            .expect("valid TLS fixture")
        )
    );

    assert!(
        parse_share_uri(&format!(
            "vless://{uuid}@example.com:443?type=grpc&security=tls"
        ))
        .is_ok()
    );

    let fingerprints = [
        ("chrome", ClientFingerprint::Chrome),
        ("firefox", ClientFingerprint::Firefox),
        ("safari", ClientFingerprint::Safari),
        ("ios", ClientFingerprint::Ios),
        ("android", ClientFingerprint::Android),
        ("edge", ClientFingerprint::Edge),
        ("360", ClientFingerprint::ThreeSixty),
        ("qq", ClientFingerprint::Qq),
        ("random", ClientFingerprint::Random),
    ];
    for (spelling, expected) in fingerprints {
        let node = parse_share_uri(&format!(
            "vless://{uuid}@example.com:443?security=tls&fp={spelling}"
        ))
        .expect("approved fingerprint");
        let NodeProtocol::Vless(vless) = node.protocol else {
            panic!("expected VLESS")
        };
        let VlessSecurity::Tls(options) = vless.security() else {
            panic!("expected TLS")
        };
        assert_eq!(options.fingerprint(), expected);
    }

    let rejected = [
        (
            format!("vless://{uuid}@example.com:443?sni=cdn.example"),
            NodeRejection::Invalid(InvalidNodeReason::IncompatibleParameter),
        ),
        (
            format!("vless://{uuid}@example.com:443?alpn=h2"),
            NodeRejection::Invalid(InvalidNodeReason::IncompatibleParameter),
        ),
        (
            format!("vless://{uuid}@example.com:443?fp=chrome"),
            NodeRejection::Invalid(InvalidNodeReason::IncompatibleParameter),
        ),
        (
            format!("vless://{uuid}@example.com:443?security=tls&sni="),
            NodeRejection::Invalid(InvalidNodeReason::ParameterValue),
        ),
        (
            format!("vless://{uuid}@example.com:443?security=tls&alpn="),
            NodeRejection::Invalid(InvalidNodeReason::ParameterValue),
        ),
        (
            format!("vless://{uuid}@example.com:443?security=tls&alpn=h2,,http%2F1.1"),
            NodeRejection::Invalid(InvalidNodeReason::ParameterValue),
        ),
        (
            format!("vless://{uuid}@example.com:443?security=tls&alpn=h2,%20http%2F1.1"),
            NodeRejection::Invalid(InvalidNodeReason::ParameterValue),
        ),
        (
            format!("vless://{uuid}@example.com:443?security=tls&fp=opera"),
            NodeRejection::Invalid(InvalidNodeReason::ParameterValue),
        ),
    ];
    for (uri, expected) in rejected {
        assert_eq!(rejection(&uri), expected, "fixture: {uri}");
    }
}

#[test]
fn vless_reality_credentials_are_validated_and_scoped() {
    let uuid = "01234567-89ab-cdef-0123-456789abcdef";
    let pbk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let tcp = parse_share_uri(&format!(
        "vless://{uuid}@EXAMPLE.COM:443?security=reality&fp=chrome&pbk={pbk}&sid=0a1b"
    ))
    .expect("TCP Reality");
    let NodeProtocol::Vless(tcp) = tcp.protocol else {
        panic!("expected VLESS")
    };
    let VlessSecurity::Reality(options) = tcp.security() else {
        panic!("expected Reality")
    };
    assert_eq!(
        options.tls(),
        &TlsOptions::new("example.com".into(), None, ClientFingerprint::Chrome)
            .expect("valid TLS fixture")
    );
    assert_eq!(options.public_key().byte_len(), 32);
    assert_eq!(options.short_id().map(RealityShortId::byte_len), Some(2));

    let grpc = parse_share_uri(&format!(
        "vless://{uuid}@example.com:443?type=grpc&security=reality&sni=cdn.example&alpn=h2&fp=firefox&pbk={pbk}&sid="
    ))
    .expect("gRPC Reality with explicit empty short id");
    let NodeProtocol::Vless(grpc) = grpc.protocol else {
        panic!("expected VLESS")
    };
    let VlessSecurity::Reality(options) = grpc.security() else {
        panic!("expected Reality")
    };
    assert_eq!(
        options.tls(),
        &TlsOptions::new(
            "cdn.example".into(),
            Some(vec!["h2".into()]),
            ClientFingerprint::Firefox,
        )
        .expect("valid TLS fixture")
    );
    assert_eq!(options.short_id(), None);

    let rejected = [
        (
            format!("vless://{uuid}@example.com:443?security=reality&pbk={pbk}"),
            NodeRejection::Invalid(InvalidNodeReason::ParameterValue),
        ),
        (
            format!("vless://{uuid}@example.com:443?security=reality&fp=chrome"),
            NodeRejection::Invalid(InvalidNodeReason::Credential),
        ),
        (
            format!("vless://{uuid}@example.com:443?type=ws&security=reality&fp=chrome&pbk={pbk}"),
            NodeRejection::Invalid(InvalidNodeReason::IncompatibleParameter),
        ),
        (
            format!("vless://{uuid}@example.com:443?security=tls&pbk={pbk}"),
            NodeRejection::Invalid(InvalidNodeReason::IncompatibleParameter),
        ),
        (
            format!("vless://{uuid}@example.com:443?security=tls&sid=0a"),
            NodeRejection::Invalid(InvalidNodeReason::IncompatibleParameter),
        ),
        (
            format!(
                "vless://{uuid}@example.com:443?security=reality&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            ),
            NodeRejection::Invalid(InvalidNodeReason::Credential),
        ),
        (
            format!("vless://{uuid}@example.com:443?security=reality&fp=chrome&pbk={pbk}%3D"),
            NodeRejection::Invalid(InvalidNodeReason::Credential),
        ),
        (
            format!("vless://{uuid}@example.com:443?security=reality&fp=chrome&pbk={pbk}&sid=0A"),
            NodeRejection::Invalid(InvalidNodeReason::Credential),
        ),
    ];
    for (uri, expected) in rejected {
        assert_eq!(rejection(&uri), expected, "fixture: {uri}");
    }
}

#[test]
fn vless_reality_credentials_compare_decoded_values() {
    let base = "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443";
    let pbk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let encoded_pbk = format!("%41{}", "A".repeat(42));
    let changed_pbk = format!("B{}", "A".repeat(42));
    let parse_options = |query: &str| {
        let node =
            parse_share_uri(&format!("{base}?{query}")).expect("valid Reality credential fixture");
        let NodeProtocol::Vless(vless) = node.protocol else {
            panic!("expected VLESS")
        };
        let VlessSecurity::Reality(options) = vless.security() else {
            panic!("expected Reality")
        };
        options.clone()
    };

    let literal = parse_options(&format!("pbk={pbk}&sid=0a1b&security=reality&fp=chrome"));
    let equivalent = parse_options(&format!(
        "pbk={encoded_pbk}&sid=%30a1b&security=reality&fp=chrome"
    ));
    let changed_public_key = parse_options(&format!(
        "pbk={changed_pbk}&sid=0a1b&security=reality&fp=chrome"
    ));
    let changed_short_id = parse_options(&format!("pbk={pbk}&sid=0a1c&security=reality&fp=chrome"));

    assert_eq!(literal.public_key(), equivalent.public_key());
    assert_eq!(literal.short_id(), equivalent.short_id());
    assert_ne!(literal.public_key(), changed_public_key.public_key());
    assert_ne!(literal.short_id(), changed_short_id.short_id());
}

#[test]
fn vless_reality_short_id_observes_byte_boundaries() {
    let base = "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443";
    let pbk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    for (sid, expected_byte_len) in [("00", 1), ("0011223344556677", 8)] {
        let uri = format!("{base}?security=reality&fp=chrome&pbk={pbk}&sid={sid}");
        let node = parse_share_uri(&uri).expect("short-id boundary fixture");
        let NodeProtocol::Vless(vless) = node.protocol else {
            panic!("expected VLESS")
        };
        let VlessSecurity::Reality(options) = vless.security() else {
            panic!("expected Reality")
        };
        assert_eq!(
            options.short_id().map(RealityShortId::byte_len),
            Some(expected_byte_len),
            "fixture: {uri}"
        );
    }

    for sid in ["0", "001122334455667788"] {
        let uri = format!("{base}?security=reality&fp=chrome&pbk={pbk}&sid={sid}");
        assert_eq!(
            rejection(&uri),
            NodeRejection::Invalid(InvalidNodeReason::Credential),
            "fixture: {uri}"
        );
    }
}

#[test]
fn vless_vision_and_deferred_capabilities_are_closed() {
    let uuid = "01234567-89ab-cdef-0123-456789abcdef";
    let pbk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let base = format!("vless://{uuid}@example.com:443");

    let tls = parse_share_uri(&format!("{base}?security=tls&flow=xtls-rprx-vision"))
        .expect("Vision over TCP TLS");
    let NodeProtocol::Vless(tls) = tls.protocol else {
        panic!("expected VLESS")
    };
    assert_eq!(tls.flow(), Some(&VlessFlow::Vision));

    let reality = parse_share_uri(&format!(
        "{base}?security=reality&fp=chrome&pbk={pbk}&flow=xtls-rprx-vision"
    ))
    .expect("Vision over TCP Reality");
    let NodeProtocol::Vless(reality) = reality.protocol else {
        panic!("expected VLESS")
    };
    assert_eq!(reality.flow(), Some(&VlessFlow::Vision));

    let absent = parse_share_uri(&format!("{base}?flow=")).expect("explicit empty flow");
    let NodeProtocol::Vless(absent) = absent.protocol else {
        panic!("expected VLESS")
    };
    assert_eq!(absent.flow(), None);

    let incompatible = [
        format!("{base}?flow=xtls-rprx-vision"),
        format!("{base}?type=ws&security=tls&flow=xtls-rprx-vision"),
        format!("{base}?type=grpc&security=tls&flow=xtls-rprx-vision"),
        format!("{base}?type=grpc&security=reality&fp=chrome&pbk={pbk}&flow=xtls-rprx-vision"),
    ];
    for uri in incompatible {
        assert_eq!(
            rejection(&uri),
            NodeRejection::Invalid(InvalidNodeReason::IncompatibleParameter),
            "fixture: {uri}"
        );
    }

    let deferred_transports = ["kcp", "http", "h2", "httpupgrade", "xhttp"];
    for transport in deferred_transports {
        let uri = format!("{base}?type={transport}");
        assert_eq!(
            rejection(&uri),
            NodeRejection::Unsupported(UnsupportedCapability::Transport),
            "fixture: {uri}"
        );
    }

    let deferred_parameters = [
        "allowInsecure=1",
        "insecure=true",
        "udp=false",
        "mux=1",
        "packetEncoding=xudp",
        "packet-encoding=xudp",
        "headerType=http",
        "seed=canary",
        "request=canary",
        "response=canary",
        "ed=2048",
        "eh=Sec-WebSocket-Protocol",
        "pqv=canary",
        "ech=canary",
        "echConfig=canary",
        "echForceQuery=true",
    ];
    for parameter in deferred_parameters {
        let uri = format!("{base}?{parameter}");
        assert_eq!(
            rejection(&uri),
            NodeRejection::Unsupported(UnsupportedCapability::ProtocolOption),
            "fixture: {uri}"
        );
    }

    let rejected = [
        (
            format!("{base}?flow=xtls-rprx-direct"),
            NodeRejection::Unsupported(UnsupportedCapability::Flow),
        ),
        (
            format!("{base}?security=xtls"),
            NodeRejection::Unsupported(UnsupportedCapability::Security),
        ),
        (
            format!("{base}?encryption=mlkem768x25519plus"),
            NodeRejection::Unsupported(UnsupportedCapability::Encryption),
        ),
        (
            format!("{base}?encryption="),
            NodeRejection::Invalid(InvalidNodeReason::ParameterValue),
        ),
        (
            format!("{base}?headerType="),
            NodeRejection::Invalid(InvalidNodeReason::ParameterValue),
        ),
    ];
    for (uri, expected) in rejected {
        assert_eq!(rejection(&uri), expected, "fixture: {uri}");
    }
}

#[test]
fn vless_header_type_none_is_omitted_tcp_header() {
    let uuid = "01234567-89ab-cdef-0123-456789abcdef";
    let pbk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let base = format!("vless://{uuid}@example.com:443");
    let query = format!(
        "encryption=none&flow=xtls-rprx-vision&security=reality&sni=cdn.example&fp=chrome&pbk={pbk}&sid=0a1b&type=tcp"
    );
    let omitted =
        parse_share_uri(&format!("{base}?{query}")).expect("Reality Vision without headerType");
    let none = parse_share_uri(&format!("{base}?{query}&headerType=none"))
        .expect("headerType=none is a no-op");
    let decoded_none = parse_share_uri(&format!("{base}?{query}&headerType=%6eone"))
        .expect("percent-decoded headerType=none");

    assert_eq!(none, omitted);
    assert_eq!(decoded_none, omitted);

    let websocket_omitted = parse_share_uri(&format!("{base}?type=ws&security=tls&path=%2Fchat"))
        .expect("WebSocket without headerType");
    let websocket_none = parse_share_uri(&format!(
        "{base}?type=ws&security=tls&path=%2Fchat&headerType=none"
    ))
    .expect("WebSocket headerType=none is a no-op");
    assert_eq!(websocket_none, websocket_omitted);
}

#[test]
fn vless_spiderx_is_omitted_reality_path() {
    let uuid = "01234567-89ab-cdef-0123-456789abcdef";
    let pbk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let base = format!("vless://{uuid}@example.com:443");
    let query = format!(
        "encryption=none&flow=xtls-rprx-vision&security=reality&sni=cdn.example&fp=chrome&pbk={pbk}&sid=0a1b&type=tcp"
    );
    let omitted =
        parse_share_uri(&format!("{base}?{query}")).expect("Reality Vision without spiderX");
    for uri in [
        format!("{base}?{query}&spx=%2F"),
        format!("{base}?{query}&spiderx=%2F"),
        format!("{base}?{query}&spiderX=%2F"),
        format!("{base}?{query}&spx="),
    ] {
        let parsed = parse_share_uri(&uri).expect("spiderX is a no-op");
        assert_eq!(parsed, omitted, "fixture: {uri}");
    }

    let without_query = parse_share_uri(&base).expect("VLESS without query");
    assert_eq!(
        parse_share_uri(&format!("{base}?spx=%2F")).expect("spx alone is a no-op"),
        without_query
    );
}

#[test]
fn vless_default_client_flags_are_omitted() {
    let uuid = "01234567-89ab-cdef-0123-456789abcdef";
    let base = format!("vless://{uuid}@example.com:443");
    let omitted = parse_share_uri(&base).expect("bare VLESS");
    for uri in [
        format!("{base}?allowInsecure=0"),
        format!("{base}?allowInsecure=false"),
        format!("{base}?insecure=0"),
        format!("{base}?insecure=false"),
        format!("{base}?udp=true"),
        format!("{base}?udp=1"),
        format!("{base}?mux=0"),
        format!("{base}?mux=false"),
        format!(
            "{base}?security=tls&sni=cdn.example&fp=chrome&allowInsecure=0&insecure=0&udp=true"
        ),
    ] {
        let parsed = parse_share_uri(&uri).expect("default client flags are a no-op");
        if uri.contains("security=tls") {
            let NodeProtocol::Vless(vless) = parsed.protocol else {
                panic!("expected VLESS")
            };
            assert!(matches!(vless.security(), VlessSecurity::Tls(_)));
        } else {
            assert_eq!(parsed, omitted, "fixture: {uri}");
        }
    }

    assert_eq!(
        rejection(&format!("{base}?allowInsecure=")),
        NodeRejection::Invalid(InvalidNodeReason::ParameterValue)
    );
    assert_eq!(
        rejection(&format!("{base}?udp=")),
        NodeRejection::Invalid(InvalidNodeReason::ParameterValue)
    );
}

#[test]
fn vless_semantic_rejection_follows_query_declaration_order() {
    let base = "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443";
    let rejected = [
        (
            format!("{base}?security=bogus&type=kcp"),
            NodeRejection::Unsupported(UnsupportedCapability::Security),
        ),
        (
            format!("{base}?type=kcp&security=bogus"),
            NodeRejection::Unsupported(UnsupportedCapability::Transport),
        ),
        (
            format!("{base}?flow=xtls-rprx-direct&encryption=future"),
            NodeRejection::Unsupported(UnsupportedCapability::Flow),
        ),
        (
            format!("{base}?encryption=future&flow=xtls-rprx-direct"),
            NodeRejection::Unsupported(UnsupportedCapability::Encryption),
        ),
        (
            format!("{base}?ech=canary&type=kcp"),
            NodeRejection::Unsupported(UnsupportedCapability::ProtocolOption),
        ),
        (
            format!("{base}?type=kcp&ech=canary"),
            NodeRejection::Unsupported(UnsupportedCapability::Transport),
        ),
    ];

    for (uri, expected) in rejected {
        assert_eq!(rejection(&uri), expected, "fixture: {uri}");
    }
}

#[test]
fn vless_parameter_semantics_precede_global_compatibility() {
    let base = "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443";
    let pbk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    assert_eq!(
        rejection(&format!(
            "{base}?type=ws&security=reality&fp=chrome&pbk={pbk}&ech=canary"
        )),
        NodeRejection::Unsupported(UnsupportedCapability::ProtocolOption)
    );
    assert_eq!(
        rejection(&format!(
            "{base}?type=ws&security=reality&fp=chrome&pbk={pbk}"
        )),
        NodeRejection::Invalid(InvalidNodeReason::IncompatibleParameter)
    );
}
