//! ICMPv4 echo (ping) — just enough to answer `ping 10.0.0.2` end to end.
//!
//! [`echo_reply`] is pure and device-agnostic: given a parsed received IPv4 packet, if it is
//! an ICMP echo request it builds the complete IPv4 + ICMP echo reply into `out` and returns
//! the length. The reply echoes the identifier, sequence number, **and the entire data
//! payload unaltered** (RFC 1122 §3.2.2.6), bounded by the IPv4 `total_len` rather than the
//! raw device read count, and recomputes both checksums.

use super::checksum::{self, IPPROTO_ICMP};
use super::ipv4::{Ipv4Packet, Ipv4Repr};

pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_ECHO_REQUEST: u8 = 8;

/// type(1) + code(1) + checksum(2) + identifier(2) + sequence(2).
const ICMP_ECHO_MIN_LEN: usize = 8;

/// If `ip` carries an ICMP echo request, write the full IPv4 + ICMP echo reply into `out` and
/// return its total length. Returns `None` for anything that is not an echo request, or if
/// `out` is too small.
pub fn echo_reply(ip: &Ipv4Packet<'_>, out: &mut [u8]) -> Option<usize> {
    if ip.protocol() != IPPROTO_ICMP {
        return None;
    }
    // `payload()` is already trimmed to total_len, so trailing device slack can't leak in.
    let request = ip.payload();
    if request.len() < ICMP_ECHO_MIN_LEN || request[0] != ICMP_ECHO_REQUEST {
        return None;
    }

    let icmp_len = request.len();
    let total = Ipv4Repr::HEADER_LEN + icmp_len;
    if out.len() < total {
        return None;
    }

    // IPv4 header for the reply: source/destination swapped.
    Ipv4Repr {
        src: ip.dst(),
        dst: ip.src(),
        protocol: IPPROTO_ICMP,
        payload_len: icmp_len as u16,
        ttl: 64,
    }
    .emit(out);

    // ICMP echo reply body.
    let body = &mut out[Ipv4Repr::HEADER_LEN..total];
    body[0] = ICMP_ECHO_REPLY;
    body[1] = 0; // code
    body[2..4].copy_from_slice(&[0, 0]); // checksum zeroed for computation
    body[4..icmp_len].copy_from_slice(&request[4..icmp_len]); // id + seq + data, verbatim
    let csum = checksum::checksum(body);
    body[2..4].copy_from_slice(&csum.to_be_bytes());

    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Build an IPv4 packet carrying an ICMP echo request with the given id/seq/data.
    fn echo_request(src: Ipv4Addr, dst: Ipv4Addr, id: u16, seq: u16, data: &[u8]) -> Vec<u8> {
        let icmp_len = ICMP_ECHO_MIN_LEN + data.len();
        let repr = Ipv4Repr {
            src,
            dst,
            protocol: IPPROTO_ICMP,
            payload_len: icmp_len as u16,
            ttl: 64,
        };
        let mut pkt = vec![0u8; repr.total_len()];
        repr.emit(&mut pkt);
        let body = &mut pkt[Ipv4Repr::HEADER_LEN..];
        body[0] = ICMP_ECHO_REQUEST;
        body[1] = 0;
        body[4..6].copy_from_slice(&id.to_be_bytes());
        body[6..8].copy_from_slice(&seq.to_be_bytes());
        body[8..].copy_from_slice(data);
        let csum = checksum::checksum(body);
        body[2..4].copy_from_slice(&csum.to_be_bytes());
        pkt
    }

    #[test]
    fn replies_to_echo_request() {
        let host = Ipv4Addr::new(10, 0, 0, 1);
        let us = Ipv4Addr::new(10, 0, 0, 2);
        let req = echo_request(host, us, 0xABCD, 7, b"ping payload");
        let parsed = Ipv4Packet::new_checked(&req).unwrap();

        let mut out = [0u8; 1500];
        let n = echo_reply(&parsed, &mut out).expect("should reply");
        let reply = Ipv4Packet::new_checked(&out[..n]).unwrap();

        assert!(reply.checksum_valid());
        assert_eq!(reply.src(), us); // src/dst swapped
        assert_eq!(reply.dst(), host);
        assert_eq!(reply.protocol(), IPPROTO_ICMP);

        let body = reply.payload();
        assert_eq!(body[0], ICMP_ECHO_REPLY);
        // ICMP checksum over the whole body must verify.
        assert_eq!(checksum::fold(checksum::accumulate(0, body)), 0xffff);
        // Identifier, sequence and data echoed verbatim.
        assert_eq!(&body[4..6], &0xABCDu16.to_be_bytes());
        assert_eq!(&body[6..8], &7u16.to_be_bytes());
        assert_eq!(&body[8..], b"ping payload");
    }

    #[test]
    fn ignores_non_echo_and_non_icmp() {
        let a = Ipv4Addr::new(10, 0, 0, 1);
        let b = Ipv4Addr::new(10, 0, 0, 2);
        let mut out = [0u8; 1500];

        // Not ICMP at all.
        let mut tcp = echo_request(a, b, 1, 1, b"x");
        tcp[9] = checksum::IPPROTO_TCP;
        // (checksum now stale, but new_checked doesn't verify L4; protocol gate fires first)
        let p = Ipv4Packet::new_checked(&tcp).unwrap();
        assert_eq!(echo_reply(&p, &mut out), None);

        // ICMP but an echo *reply*, not a request.
        let mut rep = echo_request(a, b, 1, 1, b"x");
        rep[Ipv4Repr::HEADER_LEN] = ICMP_ECHO_REPLY;
        let p = Ipv4Packet::new_checked(&rep).unwrap();
        assert_eq!(echo_reply(&p, &mut out), None);
    }
}
