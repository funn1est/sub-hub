use super::{InvalidNodeReason, NodeRejection, UnsupportedCapability, parse_share_uri, rejection};
use crate::node::{
    Host, NodeNameInput, NodeProtocol,
    vless::{ClientFingerprint, GrpcMode, TlsOptions, VlessTransport},
    vmess::{VmessCipher, VmessSecurity},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};

const ID: &str = "01234567-89ab-cdef-0123-456789abcdef";

fn uri(json: &str) -> String {
    format!("vmess://{}", STANDARD.encode(json.as_bytes()))
}

fn uri_url_safe_unpadded(json: &str) -> String {
    format!("vmess://{}", URL_SAFE_NO_PAD.encode(json.as_bytes()))
}

#[test]
fn vmess_json_v2_defaults_to_tcp_auto_and_no_tls() {
    let node = parse_share_uri(&uri(&format!(
        r#"{{"v":2,"ps":"Alpha","add":"EXAMPLE.COM","port":443,"id":"{ID}"}}"#
    )))
    .expect("valid default VMess URI");

    assert_eq!(node.endpoint.host(), &Host::Domain("example.com".into()));
    assert_eq!(node.endpoint.port().get(), 443);
    assert_eq!(node.name_input, NodeNameInput::Decoded("Alpha".into()));
    let NodeProtocol::Vmess(vmess) = node.protocol else {
        panic!("expected VMess")
    };
    assert_eq!(vmess.cipher(), VmessCipher::Auto);
    assert_eq!(vmess.transport(), &VlessTransport::Tcp);
    assert_eq!(vmess.security(), &VmessSecurity::None);
    assert_eq!(vmess.id().as_uuid().hyphenated().to_string(), ID);
}

#[test]
fn vmess_omitted_name_and_empty_ps_are_missing() {
    let omitted = parse_share_uri(&uri(&format!(
        r#"{{"add":"example.com","port":443,"id":"{ID}"}}"#
    )))
    .expect("omitted ps");
    assert_eq!(omitted.name_input, NodeNameInput::Missing);

    let empty = parse_share_uri(&uri(&format!(
        r#"{{"ps":"","add":"example.com","port":443,"id":"{ID}"}}"#
    )))
    .expect("empty ps");
    assert_eq!(empty.name_input, NodeNameInput::Missing);
}

#[test]
fn vmess_accepts_url_safe_unpadded_base64_and_string_numbers() {
    let encoded = uri_url_safe_unpadded(&format!(
        r#"{{"v":"2","add":"example.com","port":"443","id":"{ID}","aid":"0","scy":"aes-128-gcm"}}"#
    ));
    let node = parse_share_uri(&encoded).expect("url-safe unpadded");
    let NodeProtocol::Vmess(vmess) = node.protocol else {
        panic!("expected VMess")
    };
    assert_eq!(vmess.cipher(), VmessCipher::Aes128Gcm);
}

#[test]
fn vmess_ws_tls_and_grpc_are_typed() {
    let ws = parse_share_uri(&uri(&format!(
        r#"{{"add":"example.com","port":443,"id":"{ID}","net":"ws","host":"cdn.example","path":"/chat","tls":"tls","sni":"edge.example","alpn":"h2,http/1.1","fp":"firefox","scy":"none"}}"#
    )))
    .expect("WS TLS");
    let NodeProtocol::Vmess(ws) = ws.protocol else {
        panic!("expected VMess")
    };
    assert_eq!(
        ws.transport(),
        &VlessTransport::WebSocket {
            path: "/chat".into(),
            host: Some("cdn.example".into()),
        }
    );
    assert_eq!(
        ws.security(),
        &VmessSecurity::Tls(
            TlsOptions::new(
                "edge.example".into(),
                Some(vec!["h2".into(), "http/1.1".into()]),
                ClientFingerprint::Firefox,
            )
            .expect("tls")
        )
    );

    let grpc = parse_share_uri(&uri(&format!(
        r#"{{"add":"example.com","port":443,"id":"{ID}","net":"grpc","path":"svc","type":"gun","tls":"tls"}}"#
    )))
    .expect("gRPC TLS");
    let NodeProtocol::Vmess(grpc) = grpc.protocol else {
        panic!("expected VMess")
    };
    assert_eq!(
        grpc.transport(),
        &VlessTransport::Grpc {
            service_name: Some("svc".into()),
            mode: GrpcMode::Gun,
        }
    );
}

#[test]
fn vmess_rejects_std_uri_dialect_and_interior_whitespace() {
    assert_eq!(
        rejection(&format!("vmess://{ID}@example.com:443")),
        NodeRejection::Invalid(InvalidNodeReason::Uri)
    );
    assert_eq!(
        rejection("VMESS://eyJ9"),
        NodeRejection::Invalid(InvalidNodeReason::Uri)
    );
    let encoded =
        STANDARD.encode(format!(r#"{{"add":"example.com","port":443,"id":"{ID}"}}"#).as_bytes());
    let mut payload = encoded;
    payload.insert(4, ' ');
    assert_eq!(
        rejection(&format!("vmess://{payload}")),
        NodeRejection::Invalid(InvalidNodeReason::Uri)
    );
}

#[test]
fn vmess_refuses_legacy_reality_and_unknown_keys() {
    let rejected = [
        (
            uri(&format!(
                r#"{{"add":"example.com","port":443,"id":"{ID}","aid":64}}"#
            )),
            NodeRejection::Unsupported(UnsupportedCapability::ProtocolOption),
        ),
        (
            uri(&format!(
                r#"{{"add":"example.com","port":443,"id":"{ID}","tls":"reality"}}"#
            )),
            NodeRejection::Unsupported(UnsupportedCapability::Security),
        ),
        (
            uri(&format!(
                r#"{{"add":"example.com","port":443,"id":"{ID}","insecure":"1"}}"#
            )),
            NodeRejection::Unsupported(UnsupportedCapability::ProtocolOption),
        ),
        (
            uri(&format!(
                r#"{{"add":"example.com","port":443,"id":"{ID}","insecure":"true"}}"#
            )),
            NodeRejection::Invalid(InvalidNodeReason::ParameterValue),
        ),
        (
            uri(&format!(
                r#"{{"add":"example.com","port":443,"id":"{ID}","net":"kcp"}}"#
            )),
            NodeRejection::Unsupported(UnsupportedCapability::Transport),
        ),
        (
            uri(&format!(
                r#"{{"add":"example.com","port":443,"id":"{ID}","type":"http"}}"#
            )),
            NodeRejection::Unsupported(UnsupportedCapability::TransportOption),
        ),
        (
            uri(&format!(
                r#"{{"add":"example.com","port":443,"id":"{ID}","net":"grpc","host":"authority.example"}}"#
            )),
            NodeRejection::Unsupported(UnsupportedCapability::TransportOption),
        ),
        (
            uri(&format!(
                r#"{{"add":"example.com","port":443,"id":"{ID}","mystery":"x"}}"#
            )),
            NodeRejection::Unsupported(UnsupportedCapability::UnknownParameter),
        ),
        (
            uri(&format!(
                r#"{{"add":"example.com","port":443,"id":"{ID}","mux":"1"}}"#
            )),
            NodeRejection::Unsupported(UnsupportedCapability::ProtocolOption),
        ),
        (
            uri(&format!(
                r#"{{"add":"example.com","port":443,"id":"{ID}","v":1}}"#
            )),
            NodeRejection::Invalid(InvalidNodeReason::ParameterValue),
        ),
        (
            uri(r#"{"add":"example.com","port":443,"id":"NOT-A-UUID"}"#),
            NodeRejection::Invalid(InvalidNodeReason::Credential),
        ),
        (
            uri(&format!(
                r#"{{"add":"example.com","port":443,"id":"{ID}","sni":"edge.example"}}"#
            )),
            NodeRejection::Invalid(InvalidNodeReason::IncompatibleParameter),
        ),
        (
            uri(&format!(
                r#"{{"add":"example.com","port":443,"id":"{ID}","scy":"chacha20-ietf-poly1305"}}"#
            )),
            NodeRejection::Unsupported(UnsupportedCapability::Cipher),
        ),
    ];
    for (input, expected) in rejected {
        assert_eq!(rejection(&input), expected, "fixture: {input}");
    }
}

#[test]
fn vmess_duplicate_json_keys_are_rejected() {
    let json = format!(r#"{{"add":"example.com","port":443,"id":"{ID}","ps":"one","ps":"two"}}"#);
    assert_eq!(
        rejection(&uri(&json)),
        NodeRejection::Invalid(InvalidNodeReason::DuplicateParameter)
    );
}
