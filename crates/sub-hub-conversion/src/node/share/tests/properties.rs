use super::parse_share_uri;
use crate::node::{
    Host, NodeProtocol, ProxyNodeDraft,
    shadowsocks::{ShadowsocksCipher, ShadowsocksCredential},
    vless::{VlessFlow, VlessSecurity, VlessTransport},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use proptest::prelude::*;
use std::fmt::Write as _;
use uuid::Uuid;

fn selected_cross_field_invariants_hold(node: &ProxyNodeDraft) -> bool {
    let endpoint_is_valid = match node.endpoint.host() {
        Host::Domain(domain) => {
            !domain.is_empty() && domain.is_ascii() && *domain == domain.to_ascii_lowercase()
        }
        Host::Ipv4(_) | Host::Ipv6(_) => true,
    };
    if !endpoint_is_valid {
        return false;
    }

    match &node.protocol {
        NodeProtocol::Vless(vless) => {
            let security_is_compatible = !matches!(
                (vless.transport(), vless.security()),
                (VlessTransport::WebSocket { .. }, VlessSecurity::Reality(_))
            );
            let flow_is_compatible = vless.flow().is_none_or(|flow| {
                matches!(flow, VlessFlow::Vision)
                    && matches!(vless.transport(), VlessTransport::Tcp)
                    && matches!(
                        vless.security(),
                        VlessSecurity::Tls(_) | VlessSecurity::Reality(_)
                    )
            });
            security_is_compatible && flow_is_compatible
        }
        NodeProtocol::Shadowsocks(shadowsocks) => {
            match (shadowsocks.cipher(), shadowsocks.credential()) {
                (
                    ShadowsocksCipher::Aes128Gcm
                    | ShadowsocksCipher::Aes256Gcm
                    | ShadowsocksCipher::Chacha20IetfPoly1305,
                    ShadowsocksCredential::Password(_),
                ) => true,
                (ShadowsocksCipher::Blake3Aes128Gcm, ShadowsocksCredential::Psk(psk)) => {
                    psk.byte_len() == 16
                }
                (ShadowsocksCipher::Blake3Aes256Gcm, ShadowsocksCredential::Psk(psk)) => {
                    psk.byte_len() == 32
                }
                _ => false,
            }
        }
        NodeProtocol::Trojan(trojan) => {
            let password_ok = !trojan.password().expose().is_empty()
                && !trojan
                    .password()
                    .expose()
                    .chars()
                    .any(|character| character.is_ascii_control());
            let transport_ok = match trojan.transport() {
                crate::node::vless::VlessTransport::WebSocket { path, .. } => !path.is_empty(),
                _ => true,
            };
            password_ok && transport_ok
        }
        NodeProtocol::Vmess(vmess) => {
            let transport_ok = match vmess.transport() {
                crate::node::vless::VlessTransport::WebSocket { path, .. } => !path.is_empty(),
                _ => true,
            };
            transport_ok
                && !matches!(
                    vmess.security(),
                    crate::node::vmess::VmessSecurity::Tls(options) if options.server_name().is_empty()
                )
        }
        NodeProtocol::Hysteria2(hysteria2) => {
            !hysteria2
                .auth()
                .expose()
                .chars()
                .any(|character| character.is_ascii_control())
                && hysteria2.sni().is_none_or(|sni| !sni.is_empty())
                && hysteria2
                    .obfs()
                    .is_none_or(|obfs| !obfs.password().is_empty())
        }
        NodeProtocol::Tuic(tuic) => {
            !tuic.password().expose().is_empty()
                && !tuic
                    .password()
                    .expose()
                    .chars()
                    .any(|character| character.is_ascii_control())
                && tuic.sni().is_none_or(|sni| !sni.is_empty())
        }
    }
}

fn lowercase_token(max_len: usize) -> impl Strategy<Value = String> {
    prop::collection::vec(
        prop::sample::select(('a'..='z').collect::<Vec<_>>()),
        1..=max_len,
    )
    .prop_map(|characters| characters.into_iter().collect())
}

fn valid_share_uri_strategy() -> impl Strategy<Value = String> {
    let vless_tcp =
        (any::<[u8; 16]>(), lowercase_token(12), 1u16..=u16::MAX).prop_map(|(id, domain, port)| {
            format!(
                "vless://{}@{domain}.example:{port}",
                Uuid::from_bytes(id).hyphenated()
            )
        });
    let vless_websocket = (
        any::<[u8; 16]>(),
        lowercase_token(12),
        lowercase_token(24),
        1u16..=u16::MAX,
        any::<bool>(),
    )
        .prop_map(|(id, domain, path, port, fields_first)| {
            let query = if fields_first {
                format!("path=%2F{path}&host=cdn.example&type=ws")
            } else {
                format!("type=ws&path=%2F{path}&host=cdn.example")
            };
            format!(
                "vless://{}@{domain}.example:{port}?{query}",
                Uuid::from_bytes(id).hyphenated()
            )
        });
    let vless_reality = (
        any::<[u8; 16]>(),
        lowercase_token(12),
        any::<[u8; 32]>(),
        prop::collection::vec(any::<u8>(), 1..=8),
        1u16..=u16::MAX,
        any::<bool>(),
    )
        .prop_map(|(id, domain, public_key, short_id, port, fields_first)| {
            let public_key = URL_SAFE_NO_PAD.encode(public_key);
            let mut encoded_short_id = String::with_capacity(short_id.len() * 2);
            for byte in short_id {
                write!(&mut encoded_short_id, "{byte:02x}")
                    .expect("writing to a String cannot fail");
            }
            let query = if fields_first {
                format!("fp=chrome&pbk={public_key}&sid={encoded_short_id}&security=reality")
            } else {
                format!("security=reality&fp=chrome&pbk={public_key}&sid={encoded_short_id}")
            };
            format!(
                "vless://{}@{domain}.example:{port}?{query}",
                Uuid::from_bytes(id).hyphenated()
            )
        });
    let shadowsocks_classic = (lowercase_token(32), lowercase_token(12), 1u16..=u16::MAX).prop_map(
        |(password, domain, port)| format!("ss://aes-128-gcm:{password}@{domain}.example:{port}"),
    );
    let shadowsocks_2022 = (any::<[u8; 16]>(), lowercase_token(12), 1u16..=u16::MAX).prop_map(
        |(psk, domain, port)| {
            let psk = STANDARD.encode(psk).replace('/', "%2F");
            format!("ss://2022-blake3-aes-128-gcm:{psk}@{domain}.example:{port}")
        },
    );
    let json_v2_tcp =
        (any::<[u8; 16]>(), lowercase_token(12), 1u16..=u16::MAX).prop_map(|(id, domain, port)| {
            let json = format!(
                r#"{{"add":"{domain}.example","port":{port},"id":"{}"}}"#,
                Uuid::from_bytes(id).hyphenated()
            );
            format!("vmess://{}", STANDARD.encode(json.as_bytes()))
        });

    prop_oneof![
        vless_tcp,
        vless_websocket,
        vless_reality,
        shadowsocks_classic,
        shadowsocks_2022,
        trojan_uri_strategy(),
        json_v2_tcp,
        hysteria2_uri_strategy(),
        tuic_uri_strategy(),
    ]
}

fn trojan_uri_strategy() -> impl Strategy<Value = String> {
    let tcp = (lowercase_token(16), lowercase_token(12), 1u16..=u16::MAX).prop_map(
        |(password, domain, port)| format!("trojan://{password}@{domain}.example:{port}"),
    );
    let websocket = (
        lowercase_token(16),
        lowercase_token(12),
        lowercase_token(24),
        1u16..=u16::MAX,
    )
        .prop_map(|(password, domain, path, port)| {
            format!("trojan://{password}@{domain}.example:{port}?type=ws&path=%2F{path}")
        });
    let reality = (
        lowercase_token(16),
        lowercase_token(12),
        any::<[u8; 32]>(),
        1u16..=u16::MAX,
    )
        .prop_map(|(password, domain, public_key, port)| {
            let public_key = URL_SAFE_NO_PAD.encode(public_key);
            format!("trojan://{password}@{domain}.example:{port}?security=reality&pbk={public_key}")
        });
    prop_oneof![tcp, websocket, reality]
}

fn hysteria2_uri_strategy() -> impl Strategy<Value = String> {
    let tcp = (lowercase_token(16), lowercase_token(12), 1u16..=u16::MAX).prop_map(
        |(password, domain, port)| format!("hysteria2://{password}@{domain}.example:{port}"),
    );
    let salamander = (
        lowercase_token(16),
        lowercase_token(12),
        lowercase_token(16),
        1u16..=u16::MAX,
    )
        .prop_map(|(password, domain, obfs, port)| {
            format!(
                "hy2://{password}@{domain}.example:{port}/?obfs=salamander&obfs-password={obfs}"
            )
        });
    prop_oneof![tcp, salamander]
}

fn tuic_uri_strategy() -> impl Strategy<Value = String> {
    (
        any::<[u8; 16]>(),
        lowercase_token(16),
        lowercase_token(12),
        1u16..=u16::MAX,
    )
        .prop_map(|(id, password, domain, port)| {
            format!(
                "tuic://{}:{password}@{domain}.example:{port}",
                Uuid::from_bytes(id).hyphenated()
            )
        })
}

fn parser_input_strategy() -> impl Strategy<Value = String> {
    let valid = valid_share_uri_strategy();

    prop_oneof![
        2 => any::<String>(),
        2 => any::<String>().prop_map(|tail| format!("vless://{tail}")),
        2 => any::<String>().prop_map(|tail| format!("ss://{tail}")),
        2 => any::<String>().prop_map(|tail| format!("trojan://{tail}")),
        2 => any::<String>().prop_map(|tail| format!("vmess://{tail}")),
        2 => any::<String>().prop_map(|tail| format!("hysteria2://{tail}")),
        2 => any::<String>().prop_map(|tail| format!("hy2://{tail}")),
        2 => any::<String>().prop_map(|tail| format!("tuic://{tail}")),
        2 => (any::<String>(), any::<String>()).prop_map(|(query, fragment)| format!(
            "vless://01234567-89ab-cdef-0123-456789abcdef@example.com:443?{query}#{fragment}"
        )),
        2 => (any::<String>(), any::<String>()).prop_map(|(userinfo, tail)| {
            format!("ss://{userinfo}@example.com:8388#{tail}")
        }),
        4 => valid,
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn arbitrary_utf8_is_deterministic_and_never_panics(input in parser_input_strategy()) {
        let first = parse_share_uri(&input);
        let second = parse_share_uri(&input);

        prop_assert!(first == second);
        if let Ok(node) = first {
            prop_assert!(selected_cross_field_invariants_hold(&node));
        }
    }
}
