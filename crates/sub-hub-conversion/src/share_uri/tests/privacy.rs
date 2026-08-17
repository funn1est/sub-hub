use super::{InvalidNodeReason, NodeRejection, UnsupportedCapability, parse_share_uri, rejection};
use crate::node::{NodeProtocol, vless::VlessSecurity};

const PRIVACY_CANARIES: [&str; 13] = [
    "CANARY_UUID",
    "CANARY_PASSWORD",
    "CANARY_PBK",
    "CANARY_REMARK",
    "CANARY_HOST",
    "canary-host.example",
    "CANARY_QUERY_VALUE",
    "CANARY_UNKNOWN_KEY",
    "canary-protocol",
    "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAECAwQFBgcICQoLDA0ODw==",
    "0a1b",
];

fn assert_redacted(representations: impl IntoIterator<Item = String>) {
    for representation in representations {
        for canary in PRIVACY_CANARIES {
            assert!(
                !representation.contains(canary),
                "representation leaked attacker-controlled data"
            );
        }
    }
}

fn assert_rejections_redacted(failures: impl IntoIterator<Item = (String, NodeRejection)>) {
    for (uri, expected) in failures {
        let error = rejection(&uri);
        assert_eq!(error, expected, "fixture: {uri}");
        assert_redacted([format!("{error:?}"), error.to_string(), error.code().into()]);
    }
}

#[test]
fn invalid_rejection_output_redacts_attacker_controlled_values() {
    let uuid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let failures = [
        (
            format!(" vless://{uuid}@canary-host.example:443#CANARY_REMARK"),
            NodeRejection::Invalid(InvalidNodeReason::Uri),
        ),
        (
            "ss://aes-128-gcm:CANARY_PASSWORD@CANARY_HOST:0#CANARY_REMARK".to_owned(),
            NodeRejection::Invalid(InvalidNodeReason::Endpoint),
        ),
        (
            format!(
                "vless://{uuid}@canary-host.example:443?security=reality&fp=chrome&pbk=CANARY_PBK#CANARY_REMARK"
            ),
            NodeRejection::Invalid(InvalidNodeReason::Credential),
        ),
        (
            format!("vless://{uuid}@canary-host.example:443?CANARY_UNKNOWN_KEY#CANARY_REMARK"),
            NodeRejection::Invalid(InvalidNodeReason::Parameter),
        ),
        (
            format!("vless://{uuid}@canary-host.example:443?type=#CANARY_REMARK"),
            NodeRejection::Invalid(InvalidNodeReason::ParameterValue),
        ),
        (
            format!(
                "vless://{uuid}@canary-host.example:443?type=tcp&type=CANARY_QUERY_VALUE#CANARY_REMARK"
            ),
            NodeRejection::Invalid(InvalidNodeReason::DuplicateParameter),
        ),
        (
            format!("vless://{uuid}@canary-host.example:443?path=CANARY_QUERY_VALUE#CANARY_REMARK"),
            NodeRejection::Invalid(InvalidNodeReason::IncompatibleParameter),
        ),
        (
            format!("vless://{uuid}@canary-host.example:443#CANARY_REMARK%ZZ"),
            NodeRejection::Invalid(InvalidNodeReason::PercentEncoding),
        ),
    ];

    assert_rejections_redacted(failures);
}

#[test]
fn unsupported_rejection_output_redacts_attacker_controlled_values() {
    let uuid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let failures = [
        (
            "canary-protocol://CANARY_QUERY_VALUE#CANARY_REMARK".to_owned(),
            NodeRejection::Unsupported(UnsupportedCapability::Protocol),
        ),
        (
            format!(
                "vless://{uuid}@canary-host.example:443?CANARY_UNKNOWN_KEY=CANARY_QUERY_VALUE#CANARY_REMARK"
            ),
            NodeRejection::Unsupported(UnsupportedCapability::UnknownParameter),
        ),
        (
            format!(
                "vless://{uuid}@canary-host.example:443?encryption=CANARY_QUERY_VALUE#CANARY_REMARK"
            ),
            NodeRejection::Unsupported(UnsupportedCapability::Encryption),
        ),
        (
            format!("vless://{uuid}@canary-host.example:443?type=CANARY_QUERY_VALUE#CANARY_REMARK"),
            NodeRejection::Unsupported(UnsupportedCapability::Transport),
        ),
        (
            format!(
                "vless://{uuid}@canary-host.example:443?type=grpc&mode=CANARY_QUERY_VALUE#CANARY_REMARK"
            ),
            NodeRejection::Unsupported(UnsupportedCapability::TransportOption),
        ),
        (
            format!(
                "vless://{uuid}@canary-host.example:443?security=CANARY_QUERY_VALUE#CANARY_REMARK"
            ),
            NodeRejection::Unsupported(UnsupportedCapability::Security),
        ),
        (
            format!("vless://{uuid}@canary-host.example:443?flow=CANARY_QUERY_VALUE#CANARY_REMARK"),
            NodeRejection::Unsupported(UnsupportedCapability::Flow),
        ),
        (
            format!("vless://{uuid}@canary-host.example:443?udp=CANARY_QUERY_VALUE#CANARY_REMARK"),
            NodeRejection::Unsupported(UnsupportedCapability::ProtocolOption),
        ),
        (
            "ss://CANARY_QUERY_VALUE:CANARY_PASSWORD@canary-host.example:8388#CANARY_REMARK"
                .to_owned(),
            NodeRejection::Unsupported(UnsupportedCapability::Cipher),
        ),
    ];

    assert_rejections_redacted(failures);
}

#[test]
fn successful_node_debug_output_redacts_credentials_and_metadata() {
    let uuid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let pbk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let psk = "AAECAwQFBgcICQoLDA0ODw==";
    let sid = "0a1b";

    let ss =
        parse_share_uri("ss://aes-128-gcm:CANARY_PASSWORD@canary-host.example:8388#CANARY_REMARK")
            .expect("valid canary SS node");
    let NodeProtocol::Shadowsocks(ss_protocol) = &ss.protocol else {
        panic!("expected Shadowsocks")
    };
    let ss_representations = [
        format!("{ss:?}"),
        format!("{:?}", ss.protocol),
        format!("{ss_protocol:?}"),
        format!("{:?}", ss_protocol.credential()),
    ];

    let ss_2022 = parse_share_uri(&format!(
        "ss://2022-blake3-aes-128-gcm:{psk}@canary-host.example:8388#CANARY_REMARK"
    ))
    .expect("valid canary SS 2022 node");
    let NodeProtocol::Shadowsocks(ss_2022_protocol) = &ss_2022.protocol else {
        panic!("expected Shadowsocks")
    };
    let ss_2022_representations = [
        format!("{ss_2022:?}"),
        format!("{:?}", ss_2022.protocol),
        format!("{ss_2022_protocol:?}"),
        format!("{:?}", ss_2022_protocol.credential()),
    ];

    let reality = parse_share_uri(&format!(
        "vless://{uuid}@canary-host.example:443?security=reality&fp=chrome&pbk={pbk}&sid={sid}#CANARY_REMARK"
    ))
    .expect("valid canary Reality node");
    let NodeProtocol::Vless(vless) = &reality.protocol else {
        panic!("expected VLESS")
    };
    let VlessSecurity::Reality(options) = vless.security() else {
        panic!("expected Reality")
    };
    let short_id = options.short_id().expect("fixture short id");
    let secret_representations = [
        format!("{reality:?}"),
        format!("{:?}", reality.protocol),
        format!("{vless:?}"),
        format!("{:?}", vless.id()),
        format!("{:?}", options.public_key()),
        format!("{short_id:?}"),
    ];

    let trojan = parse_share_uri(
        "trojan://CANARY_PASSWORD@canary-host.example:443?security=reality&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0a1b#CANARY_REMARK",
    )
    .expect("valid canary Trojan node");
    let NodeProtocol::Trojan(trojan_protocol) = &trojan.protocol else {
        panic!("expected Trojan")
    };
    let trojan_representations = [
        format!("{trojan:?}"),
        format!("{:?}", trojan.protocol),
        format!("{trojan_protocol:?}"),
        format!("{:?}", trojan_protocol.password()),
    ];

    let json_v2 = r#"{"ps":"CANARY_REMARK","add":"canary-host.example","port":443,"id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}"#;
    let share = parse_share_uri(&format!(
        "vmess://{}",
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            json_v2.as_bytes()
        )
    ))
    .expect("valid canary VMess node");
    let NodeProtocol::Vmess(protocol) = &share.protocol else {
        panic!("expected VMess")
    };
    let vmess_representations = [
        format!("{share:?}"),
        format!("{:?}", share.protocol),
        format!("{protocol:?}"),
        format!("{:?}", protocol.id()),
    ];

    assert_redacted(
        ss_representations
            .into_iter()
            .chain(ss_2022_representations)
            .chain(secret_representations)
            .chain(trojan_representations)
            .chain(vmess_representations),
    );
}
