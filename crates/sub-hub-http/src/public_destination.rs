use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Returns whether `address` is a globally reachable unicast destination.
///
/// The special-purpose decisions are pinned to the IANA IPv4 and IPv6
/// registries last updated on 2025-10-09. Entries whose `Globally Reachable`
/// value is false, unavailable, or withdrawn are rejected. More-specific
/// globally reachable entries remain allowed.
#[must_use]
pub fn is_globally_reachable(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_globally_reachable_v4(address),
        IpAddr::V6(address) => is_globally_reachable_v6(address),
    }
}

fn is_globally_reachable_v4(address: Ipv4Addr) -> bool {
    // Multicast is outside the IANA special-purpose registry, but it is not a
    // unicast destination.
    if in_v4_prefix(address, [224, 0, 0, 0], 4) {
        return false;
    }

    // 192.0.0.0/24 is non-global except for its two more-specific anycast
    // assignments.
    if in_v4_prefix(address, [192, 0, 0, 0], 24) {
        return matches!(address.octets(), [192, 0, 0, 9 | 10]);
    }

    !in_v4_prefix(address, [0, 0, 0, 0], 8)
        && !in_v4_prefix(address, [10, 0, 0, 0], 8)
        && !in_v4_prefix(address, [100, 64, 0, 0], 10)
        && !in_v4_prefix(address, [127, 0, 0, 0], 8)
        && !in_v4_prefix(address, [169, 254, 0, 0], 16)
        && !in_v4_prefix(address, [172, 16, 0, 0], 12)
        && !in_v4_prefix(address, [192, 0, 2, 0], 24)
        // The parent allocation was withdrawn and its remaining /32 is also
        // explicitly non-global.
        && !in_v4_prefix(address, [192, 88, 99, 0], 24)
        && !in_v4_prefix(address, [192, 168, 0, 0], 16)
        && !in_v4_prefix(address, [198, 18, 0, 0], 15)
        && !in_v4_prefix(address, [198, 51, 100, 0], 24)
        && !in_v4_prefix(address, [203, 0, 113, 0], 24)
        && !in_v4_prefix(address, [240, 0, 0, 0], 4)
}

fn is_globally_reachable_v6(address: Ipv6Addr) -> bool {
    if in_v6_prefix(address, [0xff00, 0, 0, 0, 0, 0, 0, 0], 8) {
        return false;
    }

    // IPv4-mapped addresses never inherit the embedded IPv4 decision: IANA
    // marks the entire mapping prefix non-global.
    if in_v6_prefix(address, [0, 0, 0, 0, 0, 0xffff, 0, 0], 96) {
        return false;
    }

    // The well-known NAT64 prefix is global only when its embedded IPv4
    // destination is global under the same policy.
    if in_v6_prefix(address, [0x64, 0xff9b, 0, 0, 0, 0, 0, 0], 96) {
        let octets = address.octets();
        let embedded = Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]);
        return is_globally_reachable_v4(embedded);
    }

    // IETF Protocol Assignments is non-global unless a more-specific entry
    // says otherwise.
    if in_v6_prefix(address, [0x2001, 0, 0, 0, 0, 0, 0, 0], 23) {
        return matches!(address.segments(), [0x2001, 1, 0, 0, 0, 0, 0, 1..=3])
            || in_v6_prefix(address, [0x2001, 3, 0, 0, 0, 0, 0, 0], 32)
            || in_v6_prefix(address, [0x2001, 4, 0x112, 0, 0, 0, 0, 0], 48)
            || in_v6_prefix(address, [0x2001, 0x20, 0, 0, 0, 0, 0, 0], 28)
            || in_v6_prefix(address, [0x2001, 0x30, 0, 0, 0, 0, 0, 0], 28);
    }

    !in_v6_prefix(address, [0x64, 0xff9b, 1, 0, 0, 0, 0, 0], 48)
        && !in_v6_prefix(address, [0x100, 0, 0, 0, 0, 0, 0, 0], 64)
        && !in_v6_prefix(address, [0x100, 0, 0, 1, 0, 0, 0, 0], 64)
        && !in_v6_prefix(address, [0x2001, 0x0db8, 0, 0, 0, 0, 0, 0], 32)
        && !in_v6_prefix(address, [0x2002, 0, 0, 0, 0, 0, 0, 0], 16)
        && !in_v6_prefix(address, [0x3fff, 0, 0, 0, 0, 0, 0, 0], 20)
        && !in_v6_prefix(address, [0x5f00, 0, 0, 0, 0, 0, 0, 0], 16)
        && !in_v6_prefix(address, [0xfc00, 0, 0, 0, 0, 0, 0, 0], 7)
        && !in_v6_prefix(address, [0xfe80, 0, 0, 0, 0, 0, 0, 0], 10)
        // The two singleton entries precede all larger prefixes above.
        && !address.is_unspecified()
        && !address.is_loopback()
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
    use super::is_globally_reachable;
    use std::net::IpAddr;

    #[test]
    fn ipv4_registry_boundaries_and_exceptions() {
        // This is intentionally an independent literal oracle rather than a
        // table derived from the production prefixes.
        let cases = [
            ("0.0.0.0", false),
            ("0.255.255.255", false),
            ("1.0.0.0", true),
            ("8.8.8.8", true),
            ("9.255.255.255", true),
            ("10.0.0.0", false),
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
            ("169.254.255.255", false),
            ("169.255.0.0", true),
            ("172.15.255.255", true),
            ("172.16.0.0", false),
            ("172.31.255.255", false),
            ("172.32.0.0", true),
            ("191.255.255.255", true),
            ("192.0.0.0", false),
            ("192.0.0.8", false),
            ("192.0.0.9", true),
            ("192.0.0.10", true),
            ("192.0.0.11", false),
            ("192.0.0.169", false),
            ("192.0.0.170", false),
            ("192.0.0.171", false),
            ("192.0.0.255", false),
            ("192.0.1.0", true),
            ("192.0.1.255", true),
            ("192.0.2.0", false),
            ("192.0.2.255", false),
            ("192.0.3.0", true),
            ("192.31.196.0", true),
            ("192.52.193.255", true),
            ("192.88.98.255", true),
            ("192.88.99.0", false),
            ("192.88.99.2", false),
            ("192.88.99.255", false),
            ("192.88.100.0", true),
            ("192.167.255.255", true),
            ("192.168.0.0", false),
            ("192.168.255.255", false),
            ("192.169.0.0", true),
            ("192.175.48.1", true),
            ("198.17.255.255", true),
            ("198.18.0.0", false),
            ("198.19.255.255", false),
            ("198.20.0.0", true),
            ("198.51.99.255", true),
            ("198.51.100.0", false),
            ("198.51.100.255", false),
            ("198.51.101.0", true),
            ("203.0.112.255", true),
            ("203.0.113.0", false),
            ("203.0.113.255", false),
            ("203.0.114.0", true),
            ("223.255.255.255", true),
            ("224.0.0.0", false),
            ("239.255.255.255", false),
            ("240.0.0.0", false),
            ("255.255.255.255", false),
        ];

        assert_cases(&cases);
    }

    #[test]
    fn ipv6_registry_boundaries_and_exceptions() {
        // These literals independently spell out both sides of every policy
        // boundary, including the 2025 registry addition.
        let cases = [
            ("::", false),
            ("::1", false),
            ("::2", true),
            ("::fffe:ffff:ffff", true),
            ("::ffff:0:0", false),
            ("::ffff:192.0.2.1", false),
            ("::ffff:ffff:ffff", false),
            ("::1:0:0:0", true),
            ("64:ff9a:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("64:ff9b::0.0.0.0", false),
            ("64:ff9b::8.8.8.8", true),
            ("64:ff9b::10.0.0.1", false),
            ("64:ff9b::192.0.0.9", true),
            ("64:ff9b::192.0.2.1", false),
            ("64:ff9b::224.0.0.1", false),
            ("64:ff9b::255.255.255.255", false),
            ("64:ff9b::1:0:0", true),
            ("64:ff9b:0:ffff:ffff:ffff:ffff:ffff", true),
            ("64:ff9b:1::", false),
            ("64:ff9b:1:ffff:ffff:ffff:ffff:ffff", false),
            ("64:ff9b:2::", true),
            ("ff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("100::", false),
            ("100::ffff:ffff:ffff:ffff", false),
            ("100:0:0:1::", false),
            ("100:0:0:1:ffff:ffff:ffff:ffff", false),
            ("100:0:0:2::", true),
            ("2000:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("2001::", false),
            ("2001::ffff:ffff:ffff:ffff", false),
            ("2001:1::", false),
            ("2001:1::1", true),
            ("2001:1::2", true),
            ("2001:1::3", true),
            ("2001:1::4", false),
            ("2001:2:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("2001:3::", true),
            ("2001:3:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("2001:4::", false),
            ("2001:4:111:ffff:ffff:ffff:ffff:ffff", false),
            ("2001:4:112::", true),
            ("2001:4:112:ffff:ffff:ffff:ffff:ffff", true),
            ("2001:4:113::", false),
            ("2001:1f:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("2001:20::", true),
            ("2001:2f:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("2001:30::", true),
            ("2001:3f:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("2001:40::", false),
            ("2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("2001:200::", true),
            ("2001:db7:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("2001:db8::", false),
            ("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("2001:db9::", true),
            ("2001:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("2002::", false),
            ("2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("2003::", true),
            ("2620:4f:8000::", true),
            ("3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("3fff::", false),
            ("3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("3fff:1000::", true),
            ("5eff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("5f00::", false),
            ("5f00:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("6000::", true),
            ("fbff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("fc00::", false),
            ("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("fe00::", true),
            ("fe7f:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("fe80::", false),
            ("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("fec0::", true),
            ("feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("ff00::", false),
            ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
        ];

        assert_cases(&cases);
    }

    fn assert_cases(cases: &[(&str, bool)]) {
        for &(literal, expected) in cases {
            let address = literal.parse::<IpAddr>().expect("valid test address");
            assert_eq!(
                is_globally_reachable(address),
                expected,
                "unexpected decision for {literal}"
            );
        }
    }
}
