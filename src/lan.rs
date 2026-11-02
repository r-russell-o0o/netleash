//! What counts as "local network" for internet-only blocks: the private,
//! link-local, loopback and multicast/broadcast address ranges. A program
//! blocked "from the internet" can still reach these.
//!
//! Limitation: this is by address range, not by the adapter's actual subnet.
//! A home network that uses public addresses (rare) counts as internet, and a
//! carrier-grade NAT range (100.64.0.0/10) counts as internet too.

use std::net::{Ipv4Addr, Ipv6Addr};

/// (network, prefix length)
pub const V4: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(169, 254, 0, 0), 16), // link-local
    (Ipv4Addr::new(127, 0, 0, 0), 8),    // loopback
    (Ipv4Addr::new(224, 0, 0, 0), 4),    // multicast (SSDP, mDNS, ...)
    (Ipv4Addr::new(255, 255, 255, 255), 32),
];

pub const V6: &[(Ipv6Addr, u8)] = &[
    (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10), // link-local
    (Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7),  // unique local
    (Ipv6Addr::LOCALHOST, 128),
    (Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0), 16), // link-local multicast
];

pub fn mask_v4(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

pub fn is_local_v4(a: Ipv4Addr) -> bool {
    V4.iter()
        .any(|&(net, p)| u32::from(a) & mask_v4(p) == u32::from(net))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        for a in [
            "192.168.1.20",
            "10.1.2.3",
            "172.31.255.1",
            "127.0.0.1",
            "239.255.255.250",
        ] {
            assert!(is_local_v4(a.parse().unwrap()), "{a}");
        }
        for a in ["8.8.8.8", "172.32.0.1", "100.64.0.1", "1.1.1.1"] {
            assert!(!is_local_v4(a.parse().unwrap()), "{a}");
        }
        assert_eq!(mask_v4(12), 0xFFF0_0000);
    }
}
