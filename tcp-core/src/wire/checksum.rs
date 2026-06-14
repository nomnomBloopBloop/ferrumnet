//! The Internet checksum (RFC 1071): a 16-bit one's-complement sum with end-around carry.
//!
//! Used for the IPv4 header checksum, the ICMP checksum, and the TCP checksum (the last over
//! a pseudo-header). The subtle, much-fumbled details — all enforced and tested here:
//!
//! - The checksum **field must be zero** while summing. The emitters in [`super::ipv4`] /
//!   [`super::icmp`] zero it for you before computing.
//! - A trailing **odd byte is the high byte** of the final 16-bit word (`(b as u16) << 8`),
//!   not the low byte.
//! - Carries are folded back in until none remain (folding once can leave a carry-of-carry).
//! - The TCP/UDP pseudo-header length is the **L4 segment length**, never the IPv4 total length.
//! - We do **not** apply UDP's `0x0000 -> 0xFFFF` transmit rule to IPv4/ICMP/TCP.

use std::net::Ipv4Addr;

/// IANA protocol numbers carried in the IPv4 `protocol` field.
pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;

/// Accumulate the one's-complement sum of `data` into `acc`, treating `data` as a sequence
/// of big-endian 16-bit words. A trailing odd byte is the **high** byte of the last word.
///
/// The accumulator is returned **unfolded**, so several `accumulate` calls can be chained
/// (e.g. a TCP pseudo-header followed by the segment) and folded exactly once at the end
/// with [`fold`].
///
/// No overflow is possible for Internet packets: an IPv4 datagram is at most 65 535 bytes
/// (< 2^15 words), so the running `u32` stays below `2^15 * 2^16 = 2^31`.
#[must_use]
pub fn accumulate(mut acc: u32, data: &[u8]) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for pair in &mut chunks {
        acc += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        acc += (*last as u32) << 8;
    }
    acc
}

/// Fold a 32-bit accumulator down to 16 bits with end-around carry, repeating until no
/// carry remains (a single fold can leave a carry-of-carry).
#[must_use]
pub fn fold(mut acc: u32) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    acc as u16
}

/// The finished Internet checksum over a single buffer whose checksum field is already zero.
#[must_use]
pub fn checksum(data: &[u8]) -> u16 {
    !fold(accumulate(0, data))
}

/// The one's-complement sum of the IPv4 TCP/UDP pseudo-header, returned **unfolded** so it
/// can seed [`accumulate`] over the L4 segment.
///
/// `l4_len` is the length of the L4 header **plus** its payload (the TCP segment length) —
/// *not* the IPv4 total length, and *not* including the 12 pseudo-header bytes.
#[must_use]
pub fn pseudo_header(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, l4_len: u16) -> u32 {
    let mut acc = 0u32;
    acc = accumulate(acc, &src.octets());
    acc = accumulate(acc, &dst.octets());
    acc = accumulate(acc, &[0, protocol, (l4_len >> 8) as u8, l4_len as u8]);
    acc
}

/// Compute the TCP checksum over `segment` (whose own checksum field must be zero), using the
/// IPv4 pseudo-header. `segment` must be exactly the TCP segment (header + payload).
#[must_use]
pub fn tcp_checksum(src: Ipv4Addr, dst: Ipv4Addr, segment: &[u8]) -> u16 {
    let acc = pseudo_header(src, dst, IPPROTO_TCP, segment.len() as u16);
    !fold(accumulate(acc, segment))
}

/// Verify a received TCP segment's checksum (the field is left in place). Returns `true` if
/// valid.
///
/// The caller owns the checksum-offload exception: a segment whose on-wire checksum field is
/// `0x0000` (locally-originated traffic with TX offload enabled) is accepted *without*
/// calling this — see `docs/DESIGN.md`, `device-icmp/N2`.
#[must_use]
pub fn tcp_checksum_valid(src: Ipv4Addr, dst: Ipv4Addr, segment: &[u8]) -> bool {
    let acc = pseudo_header(src, dst, IPPROTO_TCP, segment.len() as u16);
    fold(accumulate(acc, segment)) == 0xffff
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Canonical IPv4 header from the Wikipedia "IPv4 header checksum" worked example;
    /// the correct checksum is 0xB861.
    const WIKI_HDR_NO_CSUM: [u8; 20] = [
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
        0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
    ];

    #[test]
    fn ipv4_header_known_vector() {
        assert_eq!(checksum(&WIKI_HDR_NO_CSUM), 0xb861);
        // With the field filled in, the verification sum is all-ones.
        let mut full = WIKI_HDR_NO_CSUM;
        full[10] = 0xb8;
        full[11] = 0x61;
        assert_eq!(fold(accumulate(0, &full)), 0xffff);
    }

    #[test]
    fn odd_trailing_byte_is_high_byte() {
        // 0x1234 as a word, then 0x56 as the HIGH byte of the last word => + 0x5600.
        assert_eq!(accumulate(0, &[0x12, 0x34, 0x56]), 0x1234 + 0x5600);
    }

    #[test]
    fn fold_handles_carry_of_carry() {
        // 0x1FFFF -> 0xFFFF + 1 = 0x10000 -> 0x0000 + 1 = 0x0001.
        assert_eq!(fold(0x1_FFFF), 0x0001);
    }

    #[test]
    fn negative_zero_is_not_normalized() {
        // Data that sums to 0xFFFF yields a transmitted checksum of 0x0000 (NOT 0xFFFF);
        // that is the legal TCP/IP value — only UDP flips it.
        assert_eq!(checksum(&[0xff, 0xff]), 0x0000);
    }

    #[test]
    fn tcp_checksum_round_trips() {
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        // Minimal 20-byte TCP header + 3-byte payload; checksum field (16..18) zeroed.
        let mut seg = vec![
            0x1f, 0x90, 0x00, 0x50, // src port 8080, dst port 80
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x50, 0x02, 0xff, 0xff, // data offset 5, SYN, window 0xffff
            0x00, 0x00, 0x00, 0x00, // checksum (zeroed), urgent ptr
            b'h', b'i', b'!', // odd-length payload exercises the trailing-byte path
        ];
        let c = tcp_checksum(src, dst, &seg);
        seg[16] = (c >> 8) as u8;
        seg[17] = c as u8;
        assert!(tcp_checksum_valid(src, dst, &seg));
        // A corrupted byte must fail verification.
        seg[20] ^= 0xff;
        assert!(!tcp_checksum_valid(src, dst, &seg));
    }
}
