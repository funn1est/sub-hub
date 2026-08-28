use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Native host adapter: whether a resolved address is a unicast destination
/// the converter may connect to.
///
/// Outbound accept is lexical HTTPS in `sub-hub-http`. This check runs after DNS.
/// It is a closed refuse set for operator-local, CGNAT, metadata, and non-unicast
/// answers — not the IANA globally-reachable registry. `198.18.0.0/15` (Clash /
/// Mihomo Fake-IP default pool) is allowed. A custom Fake-IP pool inside RFC1918
/// is still refused.
#[must_use]
pub(crate) fn is_allowed_destination(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_allowed_destination_v4(address),
        IpAddr::V6(address) => is_allowed_destination_v6(address),
    }
}

fn is_allowed_destination_v4(address: Ipv4Addr) -> bool {
    // 224.0.0.0/3 is multicast (224/4) plus reserved Class E (240/4).
    if in_v4_prefix(address, [224, 0, 0, 0], 3) {
        return false;
    }

    !in_v4_prefix(address, [0, 0, 0, 0], 8)
        && !in_v4_prefix(address, [10, 0, 0, 0], 8)
        && !in_v4_prefix(address, [100, 64, 0, 0], 10)
        && !in_v4_prefix(address, [127, 0, 0, 0], 8)
        && !in_v4_prefix(address, [169, 254, 0, 0], 16)
        && !in_v4_prefix(address, [172, 16, 0, 0], 12)
        && !in_v4_prefix(address, [192, 168, 0, 0], 16)
}

fn is_allowed_destination_v6(address: Ipv6Addr) -> bool {
    if in_v6_prefix(address, [0xff00, 0, 0, 0, 0, 0, 0, 0], 8) {
        return false;
    }

    // IPv4-mapped and well-known NAT64 inherit the embedded IPv4 decision so a
    // Fake-IP v4 pool still passes when the resolver emits these forms.
    if in_v6_prefix(address, [0, 0, 0, 0, 0, 0xffff, 0, 0], 96)
        || in_v6_prefix(address, [0x64, 0xff9b, 0, 0, 0, 0, 0, 0], 96)
    {
        return is_allowed_destination_v4(embedded_ipv4(address));
    }

    !in_v6_prefix(address, [0x64, 0xff9b, 1, 0, 0, 0, 0, 0], 48)
        && !in_v6_prefix(address, [0xfc00, 0, 0, 0, 0, 0, 0, 0], 7)
        && !in_v6_prefix(address, [0xfe80, 0, 0, 0, 0, 0, 0, 0], 10)
        && !address.is_unspecified()
        && !address.is_loopback()
}

fn embedded_ipv4(address: Ipv6Addr) -> Ipv4Addr {
    let octets = address.octets();
    Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15])
}

fn in_v4_prefix(address: Ipv4Addr, network: [u8; 4], prefix_len: u32) -> bool {
    let shift = 32 - prefix_len;
    u32::from(address) >> shift == u32::from_be_bytes(network) >> shift
}

fn in_v6_prefix(address: Ipv6Addr, network: [u16; 8], prefix_len: u32) -> bool {
    let shift = 128 - prefix_len;
    u128::from(address) >> shift == u128::from(Ipv6Addr::from(network)) >> shift
}

#[cfg(test)]
mod tests {
    use super::is_allowed_destination;
    use std::net::IpAddr;

    #[test]
    fn ipv4_refuses_operator_local_cgnat_and_non_unicast() {
        // Independent literal oracle, not derived from the production prefixes.
        let cases = [
            ("0.0.0.0", false),
            ("0.255.255.255", false),
            ("1.0.0.0", true),
            ("8.8.8.8", true),
            ("9.255.255.255", true),
            ("10.0.0.0", false),
            ("10.1.2.3", false),
            ("10.255.255.255", false),
            ("11.0.0.0", true),
            ("100.63.255.255", true),
            ("100.64.0.0", false),
            ("100.127.255.255", false),
            ("100.128.0.0", true),
            ("126.255.255.255", true),
            ("127.0.0.0", false),
            ("127.255.255.255", false),
            ("128.0.0.0", true),
            ("169.253.255.255", true),
            ("169.254.0.0", false),
            ("169.254.169.254", false),
            ("169.254.255.255", false),
            ("169.255.0.0", true),
            ("172.15.255.255", true),
            ("172.16.0.0", false),
            ("172.31.255.255", false),
            ("172.32.0.0", true),
            ("191.255.255.255", true),
            ("192.0.0.0", true),
            ("192.0.0.8", true),
            ("192.0.0.9", true),
            ("192.0.0.10", true),
            ("192.0.0.170", true),
            ("192.0.2.0", true),
            ("192.0.2.255", true),
            ("192.88.99.0", true),
            ("192.167.255.255", true),
            ("192.168.0.0", false),
            ("192.168.255.255", false),
            ("192.169.0.0", true),
            ("198.17.255.255", true),
            ("198.18.0.0", true),
            ("198.18.111.193", true),
            ("198.19.255.255", true),
            ("198.20.0.0", true),
            ("198.51.100.0", true),
            ("203.0.113.0", true),
            ("223.255.255.255", true),
            ("224.0.0.0", false),
            ("239.255.255.255", false),
            ("240.0.0.0", false),
            ("255.255.255.255", false),
        ];

        assert_cases(&cases);
    }

    #[test]
    fn ipv6_refuses_operator_local_and_inherits_embedded_v4() {
        let cases = [
            ("::", false),
            ("::1", false),
            ("::2", true),
            ("::ffff:0:0", false),
            ("::ffff:8.8.8.8", true),
            ("::ffff:10.0.0.1", false),
            ("::ffff:127.0.0.1", false),
            ("::ffff:169.254.169.254", false),
            ("::ffff:192.0.2.1", true),
            ("::ffff:198.18.111.193", true),
            ("::ffff:224.0.0.1", false),
            ("::ffff:255.255.255.255", false),
            ("::1:0:0:0", true),
            ("64:ff9b::0.0.0.0", false),
            ("64:ff9b::8.8.8.8", true),
            ("64:ff9b::10.0.0.1", false),
            ("64:ff9b::192.0.2.1", true),
            ("64:ff9b::198.18.111.193", true),
            ("64:ff9b::224.0.0.1", false),
            ("64:ff9b::255.255.255.255", false),
            ("64:ff9b:1::", false),
            ("64:ff9b:1:ffff:ffff:ffff:ffff:ffff", false),
            ("64:ff9b:2::", true),
            ("100::", true),
            ("100:0:0:1::", true),
            ("2001::", true),
            ("2001:db8::", true),
            ("2002::", true),
            ("3fff::", true),
            ("5f00::", true),
            ("fc00::", false),
            ("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("fe00::", true),
            ("fe80::", false),
            ("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("fec0::", true),
            ("ff00::", false),
            ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
        ];

        assert_cases(&cases);
    }

    fn assert_cases(cases: &[(&str, bool)]) {
        for &(literal, expected) in cases {
            let address = literal.parse::<IpAddr>().expect("valid test address");
            assert_eq!(
                is_allowed_destination(address),
                expected,
                "unexpected decision for {literal}"
            );
        }
    }
}
