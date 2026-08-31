use super::{InvalidNodeReason, NodeRejection, UnsupportedCapability, parse_share_uri, rejection};
use crate::node::{Host, NodeNameInput, NodeProtocol, hysteria2::Hysteria2Obfs};

const PIN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn hysteria2_without_auth_or_port_defaults_to_empty_auth_and_443() {
    let node = parse_share_uri("hysteria2://EXAMPLE.COM#Alpha").expect("valid default Hy2 URI");

    assert_eq!(node.endpoint.host(), &Host::Domain("example.com".into()));
    assert_eq!(node.endpoint.port().get(), 443);
    assert_eq!(node.name_input, NodeNameInput::Decoded("Alpha".into()));
    let NodeProtocol::Hysteria2(hy2) = node.protocol else {
        panic!("expected Hysteria2")
    };
    assert_eq!(hy2.auth().expose(), "");
    assert!(!hy2.ports().is_hop());
    assert_eq!(hy2.sni(), None);
    assert!(hy2.obfs().is_none());
    assert!(hy2.pin_sha256().is_none());
}

#[test]
fn hy2_alias_and_userpass_are_accepted() {
    let via_alias =
        parse_share_uri("hy2://letmein@example.com:8443/?sni=real.example").expect("hy2 alias");
    let NodeProtocol::Hysteria2(via_alias) = via_alias.protocol else {
        panic!("expected Hysteria2")
    };
    assert_eq!(via_alias.auth().expose(), "letmein");
    assert_eq!(via_alias.sni(), Some("real.example"));

    let userpass =
        parse_share_uri("hysteria2://user:p%40ss@192.0.2.1:443/").expect("userpass auth");
    let NodeProtocol::Hysteria2(userpass) = userpass.protocol else {
        panic!("expected Hysteria2")
    };
    assert_eq!(userpass.auth().expose(), "user:p@ss");
}

#[test]
fn hysteria2_accepts_salamander_gecko_and_hop() {
    let salamander = parse_share_uri(
        "hysteria2://letmein@example.com:443/?obfs=salamander&obfs-password=gawrgura",
    )
    .expect("salamander");
    let NodeProtocol::Hysteria2(salamander) = salamander.protocol else {
        panic!("expected Hysteria2")
    };
    assert!(matches!(
        salamander.obfs(),
        Some(Hysteria2Obfs::Salamander { .. })
    ));
    assert_eq!(
        salamander.obfs().map(Hysteria2Obfs::password),
        Some("gawrgura")
    );

    let gecko = parse_share_uri("hysteria2://letmein@example.com/?obfs=gecko&obfs-password=secret")
        .expect("gecko");
    let NodeProtocol::Hysteria2(gecko) = gecko.protocol else {
        panic!("expected Hysteria2")
    };
    assert!(gecko.obfs().is_some_and(Hysteria2Obfs::is_gecko));

    let hop =
        parse_share_uri("hysteria2://letmein@example.com:123,5000-6000/").expect("official hop");
    assert_eq!(hop.endpoint.port().get(), 123);
    let NodeProtocol::Hysteria2(hop) = hop.protocol else {
        panic!("expected Hysteria2")
    };
    assert!(hop.ports().is_hop());
    let atoms = hop.ports().hop_atoms().expect("hop atoms");
    assert_eq!(atoms.len(), 2);
    assert_eq!(atoms[0].bounds(), (123, 123));
    assert!(!atoms[0].is_range());
    assert_eq!(atoms[1].bounds(), (5000, 6000));
    assert!(atoms[1].is_range());

    let ipv6 = parse_share_uri("hysteria2://@[2001:db8::1]:443,8443/").expect("IPv6 hop");
    assert_eq!(
        ipv6.endpoint.host(),
        &Host::Ipv6("2001:db8::1".parse().unwrap())
    );
    assert_eq!(ipv6.endpoint.port().get(), 443);
}

#[test]
fn hysteria2_pin_is_normalized_64_hex() {
    let colon = parse_share_uri(
        "hysteria2://letmein@example.com/?pinSHA256=01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef:01:23:45:67:89:ab:cd:ef",
    )
    .expect("colon pin");
    let NodeProtocol::Hysteria2(colon) = colon.protocol else {
        panic!("expected Hysteria2")
    };
    assert_eq!(
        colon.pin_sha256().map(<[u8; 32]>::as_slice),
        Some(
            &[
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
                0x89, 0xab, 0xcd, 0xef
            ][..]
        )
    );

    let bare = parse_share_uri(&format!("hysteria2://letmein@example.com/?pinSHA256={PIN}"))
        .expect("bare pin");
    let NodeProtocol::Hysteria2(bare) = bare.protocol else {
        panic!("expected Hysteria2")
    };
    assert!(bare.pin_sha256().is_some());
}

#[test]
fn hysteria2_insecure_and_closed_keys() {
    parse_share_uri("hysteria2://letmein@example.com/?insecure=0").expect("verify");
    parse_share_uri("hysteria2://letmein@example.com/?insecure=false").expect("verify false");
    parse_share_uri("hysteria2://letmein@example.com/?allowInsecure=0").expect("v2rayN alias");

    let rejected = [
        (
            "Hysteria2://letmein@example.com:443",
            NodeRejection::Invalid(InvalidNodeReason::Uri),
        ),
        (
            "HY2://letmein@example.com:443",
            NodeRejection::Invalid(InvalidNodeReason::Uri),
        ),
        (
            "hysteria2://letmein@example.com:443/extra",
            NodeRejection::Invalid(InvalidNodeReason::Uri),
        ),
        (
            "hysteria2://%00@example.com:443",
            NodeRejection::Invalid(InvalidNodeReason::Credential),
        ),
        (
            "hysteria2://letmein@example.com:0",
            NodeRejection::Invalid(InvalidNodeReason::Endpoint),
        ),
        (
            "hysteria2://letmein@example.com:6000-5000",
            NodeRejection::Invalid(InvalidNodeReason::Endpoint),
        ),
        (
            "hysteria2://letmein@example.com:123,",
            NodeRejection::Invalid(InvalidNodeReason::Endpoint),
        ),
        (
            "hysteria2://letmein@example.com/?obfs=salamander",
            NodeRejection::Invalid(InvalidNodeReason::IncompatibleParameter),
        ),
        (
            "hysteria2://letmein@example.com/?obfs-password=x",
            NodeRejection::Invalid(InvalidNodeReason::IncompatibleParameter),
        ),
        (
            "hysteria2://letmein@example.com/?insecure=yes",
            NodeRejection::Invalid(InvalidNodeReason::ParameterValue),
        ),
        (
            "hysteria2://letmein@example.com/?pinSHA256=deadbeef",
            NodeRejection::Invalid(InvalidNodeReason::ParameterValue),
        ),
        (
            "hysteria2://letmein@example.com/?insecure=1",
            NodeRejection::Unsupported(UnsupportedCapability::ProtocolOption),
        ),
        (
            "hysteria2://letmein@example.com/?insecure=true",
            NodeRejection::Unsupported(UnsupportedCapability::ProtocolOption),
        ),
        (
            "hysteria2://letmein@example.com/?ech=YQ%3D%3D",
            NodeRejection::Unsupported(UnsupportedCapability::ProtocolOption),
        ),
        (
            "hysteria2://letmein@example.com/?obfs=plain",
            NodeRejection::Unsupported(UnsupportedCapability::ProtocolOption),
        ),
        (
            "hysteria2://letmein@example.com/?mport=443",
            NodeRejection::Unsupported(UnsupportedCapability::UnknownParameter),
        ),
        (
            "hysteria://letmein@example.com:443",
            NodeRejection::Unsupported(UnsupportedCapability::Protocol),
        ),
        (
            "hysteria2+realm://token@rendezvous.example/cabin",
            NodeRejection::Unsupported(UnsupportedCapability::Protocol),
        ),
    ];
    for (uri, expected) in rejected {
        assert_eq!(rejection(uri), expected, "fixture: {uri}");
    }
}
