use super::{InvalidNodeReason, NodeRejection, UnsupportedCapability, parse_share_uri, rejection};
use crate::node::{
    Host, NodeNameInput, NodeProtocol,
    shadowsocks::{ShadowsocksCipher, ShadowsocksCredential, ShadowsocksObfsMode},
};

#[test]
fn shadowsocks_userinfo_rejects_raw_path_delimiters() {
    let uri = "ss://aes-128-gcm:pa/ss@example.com:8388";

    assert_eq!(
        rejection(uri),
        NodeRejection::Invalid(InvalidNodeReason::Uri)
    );
}

#[test]
fn shadowsocks_classic_sip002_userinfo_is_strict() {
    let ciphers = [
        (
            "aes-128-gcm",
            "YWVzLTEyOC1nY206cGFzc3dvcmQ",
            ShadowsocksCipher::Aes128Gcm,
        ),
        (
            "aes-256-gcm",
            "YWVzLTI1Ni1nY206cGFzc3dvcmQ",
            ShadowsocksCipher::Aes256Gcm,
        ),
        (
            "chacha20-ietf-poly1305",
            "Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA",
            ShadowsocksCipher::Chacha20IetfPoly1305,
        ),
    ];

    for (method, encoded_userinfo, expected_cipher) in ciphers {
        let plain = parse_share_uri(&format!(
            "ss://{method}:password@EXAMPLE.COM:8388#Hong%20Kong+1"
        ))
        .expect("plain classic SIP002 userinfo");
        let NodeProtocol::Shadowsocks(plain) = plain.protocol else {
            panic!("expected Shadowsocks")
        };
        assert_eq!(plain.cipher(), &expected_cipher);
        let ShadowsocksCredential::Password(password) = plain.credential() else {
            panic!("expected classic password")
        };
        assert_eq!(password.byte_len(), 8);

        let encoded = parse_share_uri(&format!("ss://{encoded_userinfo}@192.0.2.1:1/"))
            .expect("unpadded Base64URL classic userinfo");
        let NodeProtocol::Shadowsocks(encoded) = encoded.protocol else {
            panic!("expected Shadowsocks")
        };
        assert_eq!(encoded.cipher(), &expected_cipher);
    }

    let padded = parse_share_uri("ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@[2001:db8::1]:65535#")
        .expect("correctly padded Base64URL userinfo and IPv6 endpoint");
    assert_eq!(
        padded.endpoint.host(),
        &Host::Ipv6("2001:db8::1".parse().unwrap())
    );
    assert_eq!(padded.endpoint.port().get(), 65_535);
    assert_eq!(padded.name_input, NodeNameInput::Decoded(String::new()));

    let plus_password =
        parse_share_uri("ss://aes-128-gcm:pa%3Ass+word@example.com:8388#literal+plus")
            .expect("plain password uses strict percent decoding");
    assert_eq!(
        plus_password.name_input,
        NodeNameInput::Decoded("literal+plus".into())
    );

    let rejected = [
        (
            "SS://aes-128-gcm:password@example.com:8388",
            NodeRejection::Invalid(InvalidNodeReason::Uri),
        ),
        (
            "ss://YWVzLTEyOC1nY206cGFzc3dvcmRAZXhhbXBsZS5jb206ODM4OA",
            NodeRejection::Invalid(InvalidNodeReason::Uri),
        ),
        (
            "ss://aes-128-gcm@example.com:8388",
            NodeRejection::Invalid(InvalidNodeReason::Credential),
        ),
        (
            "ss://aes-128-gcm:@example.com:8388",
            NodeRejection::Invalid(InvalidNodeReason::Credential),
        ),
        (
            "ss://aes-128-gcm:pass%ZZ@example.com:8388",
            NodeRejection::Invalid(InvalidNodeReason::PercentEncoding),
        ),
        (
            "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ===@example.com:8388",
            NodeRejection::Invalid(InvalidNodeReason::Credential),
        ),
        (
            "ss://YWVzLTEyOC1nY206cGFzc3dvcm+@example.com:8388",
            NodeRejection::Invalid(InvalidNodeReason::Credential),
        ),
        (
            "ss://aes-128-cfb:password@example.com:8388",
            NodeRejection::Unsupported(UnsupportedCapability::Cipher),
        ),
        (
            "ss://aes-128-gcm:password@example.com:8388/path",
            NodeRejection::Invalid(InvalidNodeReason::Uri),
        ),
    ];
    for (uri, expected) in rejected {
        assert_eq!(rejection(uri), expected, "fixture: {uri}");
    }
}

#[test]
fn shadowsocks_credentials_compare_decoded_secret_values() {
    let plain = parse_share_uri("ss://aes-128-gcm:password@example.com:8388")
        .expect("plain classic credential");
    let percent_encoded = parse_share_uri("ss://aes-128-gcm:pass%77ord@example.com:8388")
        .expect("percent-encoded classic credential");
    let base64url = parse_share_uri("ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@example.com:8388")
        .expect("Base64URL classic credential");
    let changed = parse_share_uri("ss://aes-128-gcm:password2@example.com:8388")
        .expect("changed classic credential");

    let NodeProtocol::Shadowsocks(plain) = plain.protocol else {
        panic!("expected Shadowsocks")
    };
    let NodeProtocol::Shadowsocks(percent_encoded) = percent_encoded.protocol else {
        panic!("expected Shadowsocks")
    };
    let NodeProtocol::Shadowsocks(base64url) = base64url.protocol else {
        panic!("expected Shadowsocks")
    };
    let NodeProtocol::Shadowsocks(changed) = changed.protocol else {
        panic!("expected Shadowsocks")
    };
    assert_eq!(plain.credential(), percent_encoded.credential());
    assert_eq!(plain.credential(), base64url.credential());
    assert_ne!(plain.credential(), changed.credential());

    let padded =
        parse_share_uri("ss://2022-blake3-aes-128-gcm:AAECAwQFBgcICQoLDA0ODw==@example.com:8388")
            .expect("padded SS 2022 PSK");
    let unpadded =
        parse_share_uri("ss://2022-blake3-aes-128-gcm:AAECAwQFBgcICQoLDA0ODw@example.com:8388")
            .expect("unpadded SS 2022 PSK");
    let changed =
        parse_share_uri("ss://2022-blake3-aes-128-gcm:AAAAAAAAAAAAAAAAAAAAAA==@example.com:8388")
            .expect("changed SS 2022 PSK");
    let NodeProtocol::Shadowsocks(padded) = padded.protocol else {
        panic!("expected Shadowsocks")
    };
    let NodeProtocol::Shadowsocks(unpadded) = unpadded.protocol else {
        panic!("expected Shadowsocks")
    };
    let NodeProtocol::Shadowsocks(changed) = changed.protocol else {
        panic!("expected Shadowsocks")
    };
    assert_eq!(padded.credential(), unpadded.credential());
    assert_ne!(padded.credential(), changed.credential());
}

#[test]
fn shadowsocks_2022_psks_are_plain_and_length_checked() {
    let accepted = [
        (
            "2022-blake3-aes-128-gcm",
            "AAECAwQFBgcICQoLDA0ODw==",
            ShadowsocksCipher::Blake3Aes128Gcm,
            16,
        ),
        (
            "2022-blake3-aes-128-gcm",
            "AAECAwQFBgcICQoLDA0ODw",
            ShadowsocksCipher::Blake3Aes128Gcm,
            16,
        ),
        (
            "2022-blake3-aes-128-gcm",
            "+%2Fv7+%2Fv7+%2Fv7+%2Fv7+%2Fv7+w==",
            ShadowsocksCipher::Blake3Aes128Gcm,
            16,
        ),
        (
            "2022-blake3-aes-256-gcm",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            ShadowsocksCipher::Blake3Aes256Gcm,
            32,
        ),
    ];

    for (method, psk, expected_cipher, expected_len) in accepted {
        let node = parse_share_uri(&format!("ss://{method}:{psk}@example.com:8388#2022"))
            .expect("valid SS 2022 PSK");
        let NodeProtocol::Shadowsocks(node) = node.protocol else {
            panic!("expected Shadowsocks")
        };
        assert_eq!(node.cipher(), &expected_cipher);
        let ShadowsocksCredential::Psk(psk) = node.credential() else {
            panic!("expected validated PSK")
        };
        assert_eq!(psk.byte_len(), expected_len);
    }

    let rejected = [
        (
            "ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206QUFFQ0F3UUZCZ2NJQ1FvTERBME9Edz09@example.com:8388",
            NodeRejection::Invalid(InvalidNodeReason::Credential),
        ),
        (
            "ss://2022-blake3-aes-128-gcm:AAECAwQFBgcICQoLDA0O@example.com:8388",
            NodeRejection::Invalid(InvalidNodeReason::Credential),
        ),
        (
            "ss://2022-blake3-aes-256-gcm:AAECAwQFBgcICQoLDA0ODw==@example.com:8388",
            NodeRejection::Invalid(InvalidNodeReason::Credential),
        ),
        (
            "ss://2022-blake3-aes-128-gcm:AAECAwQFBgcICQoLDA0ODw===@example.com:8388",
            NodeRejection::Invalid(InvalidNodeReason::Credential),
        ),
        (
            "ss://2022-blake3-aes-128-gcm:_____________________w==@example.com:8388",
            NodeRejection::Invalid(InvalidNodeReason::Credential),
        ),
        (
            "ss://2022-blake3-aes-128-gcm:+/v7+/v7+/v7+/v7+/v7+w==@example.com:8388",
            NodeRejection::Invalid(InvalidNodeReason::Uri),
        ),
        (
            "ss://2022-blake3-chacha20-poly1305:AAECAwQFBgcICQoLDA0ODw==@example.com:8388",
            NodeRejection::Unsupported(UnsupportedCapability::Cipher),
        ),
    ];
    for (uri, expected) in rejected {
        assert_eq!(rejection(uri), expected, "fixture: {uri}");
    }
}

#[test]
fn shadowsocks_empty_query_is_absent_query() {
    let base = "ss://aes-256-gcm:password@example.com:8388";
    let absent = parse_share_uri(base).expect("no query");
    let empty = parse_share_uri(&format!("{base}?")).expect("empty query");
    let fragment_only = parse_share_uri(&format!("{base}#Alpha")).expect("fragment only");
    let empty_with_fragment =
        parse_share_uri(&format!("{base}?#Alpha")).expect("empty query with fragment");

    assert_eq!(empty, absent);
    assert_eq!(empty_with_fragment, fragment_only);
    assert_eq!(
        empty_with_fragment.name_input,
        NodeNameInput::Decoded("Alpha".into())
    );
}

#[test]
fn shadowsocks_obfs_local_http_is_accepted() {
    let node = parse_share_uri(
        "ss://aes-128-gcm:password@example.com:8388?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dobfs.example",
    )
    .expect("obfs-local http");
    let NodeProtocol::Shadowsocks(ss) = node.protocol else {
        panic!("expected Shadowsocks")
    };
    let obfs = ss.obfs().expect("obfs");
    assert_eq!(obfs.mode(), ShadowsocksObfsMode::Http);
    assert_eq!(obfs.host(), Some("obfs.example"));
}

#[test]
fn shadowsocks_query_capabilities_are_rejected_without_lossy_fallback() {
    let base = "ss://aes-128-gcm:password@example.com:8388";
    let known = [
        "plugin=v2ray-plugin",
        "plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-uri%3D%2F",
        "uot=true",
        "udp-over-tcp=true",
        "udp_over_tcp=true",
    ];
    for parameter in known {
        let uri = format!("{base}?{parameter}");
        assert_eq!(
            rejection(&uri),
            NodeRejection::Unsupported(UnsupportedCapability::ProtocolOption),
            "fixture: {uri}"
        );
    }

    let rejected = [
        (
            format!("{base}?mystery=canary"),
            NodeRejection::Unsupported(UnsupportedCapability::UnknownParameter),
        ),
        (
            format!("{base}?plugin=one&plugin=two"),
            NodeRejection::Invalid(InvalidNodeReason::DuplicateParameter),
        ),
        (
            format!("{base}?plugin=one&mystery=%"),
            NodeRejection::Invalid(InvalidNodeReason::PercentEncoding),
        ),
        (
            format!("{base}?plugin"),
            NodeRejection::Invalid(InvalidNodeReason::Parameter),
        ),
        (
            format!("{base}?plu%67in=value"),
            NodeRejection::Invalid(InvalidNodeReason::Parameter),
        ),
        (
            format!("{base}?plugin=%"),
            NodeRejection::Invalid(InvalidNodeReason::PercentEncoding),
        ),
    ];
    for (uri, expected) in rejected {
        assert_eq!(rejection(&uri), expected, "fixture: {uri}");
    }
}
