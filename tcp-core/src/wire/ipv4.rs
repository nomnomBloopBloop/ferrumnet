//! Zero-copy IPv4 parsing ([`Ipv4Packet`]) and a single-entry-point emitter ([`Ipv4Repr`]).
//!
//! Parsing never copies and never panics once [`Ipv4Packet::new_checked`] succeeds: that
//! constructor validates the version, the header length window (20..=60), that the buffer
//! actually contains `total_len` bytes, and that the datagram is not a fragment. Fields are
//! decoded with [`u16::from_be_bytes`] at fixed offsets — never by casting the byte slice to
//! a `#[repr(C)]` struct, which would be an alignment/endianness bug.

use std::net::Ipv4Addr;

use super::checksum;

pub const IPV4_MIN_HEADER_LEN: usize = 20;
pub const IPV4_MAX_HEADER_LEN: usize = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Buffer shorter than the header, or shorter than the declared `total_len`.
    Truncated,
    /// IP version field is not 4.
    BadVersion,
    /// IHL outside the legal 20..=60 byte range.
    BadHeaderLen,
    /// More-Fragments set or a non-zero fragment offset — we do not reassemble.
    Fragmented,
}

/// A read-only, zero-copy view over a received IPv4 packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Packet<'a> {
    buf: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    /// Bind a view and validate every invariant the accessors rely on. After this returns
    /// `Ok`, all accessors are panic-free.
    pub fn new_checked(buf: &'a [u8]) -> Result<Self, ParseError> {
        if buf.len() < IPV4_MIN_HEADER_LEN {
            return Err(ParseError::Truncated);
        }
        let p = Ipv4Packet { buf };
        if p.version() != 4 {
            return Err(ParseError::BadVersion);
        }
        let ihl = p.header_len();
        if !(IPV4_MIN_HEADER_LEN..=IPV4_MAX_HEADER_LEN).contains(&ihl) {
            return Err(ParseError::BadHeaderLen);
        }
        let total = p.total_len() as usize;
        // `total_len` must cover at least the header and must fit in the buffer the device
        // handed us (which may be larger than the datagram — trailing bytes are slack).
        if total < ihl || total > buf.len() {
            return Err(ParseError::Truncated);
        }
        if p.is_fragment() {
            return Err(ParseError::Fragmented);
        }
        Ok(p)
    }

    #[inline]
    pub fn version(&self) -> u8 {
        self.buf[0] >> 4
    }

    #[inline]
    pub fn header_len(&self) -> usize {
        (self.buf[0] & 0x0f) as usize * 4
    }

    #[inline]
    pub fn total_len(&self) -> u16 {
        u16::from_be_bytes([self.buf[2], self.buf[3]])
    }

    #[inline]
    pub fn ttl(&self) -> u8 {
        self.buf[8]
    }

    #[inline]
    pub fn protocol(&self) -> u8 {
        self.buf[9]
    }

    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.buf[10], self.buf[11]])
    }

    #[inline]
    pub fn src(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.buf[12], self.buf[13], self.buf[14], self.buf[15])
    }

    #[inline]
    pub fn dst(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.buf[16], self.buf[17], self.buf[18], self.buf[19])
    }

    /// More-Fragments bit set, or a non-zero fragment offset.
    #[inline]
    pub fn is_fragment(&self) -> bool {
        let flags_frag = u16::from_be_bytes([self.buf[6], self.buf[7]]);
        (flags_frag & 0x2000) != 0 || (flags_frag & 0x1fff) != 0
    }

    /// True if the header checksum is valid (sums to all-ones over `header_len` bytes).
    pub fn checksum_valid(&self) -> bool {
        checksum::fold(checksum::accumulate(0, &self.buf[..self.header_len()])) == 0xffff
    }

    /// The L4 payload: bytes `[header_len, total_len)`. Trimmed to `total_len`, so any
    /// trailing slack the device handed us is excluded (never folded into an L4 checksum).
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.buf[self.header_len()..self.total_len() as usize]
    }
}

/// A description of an IPv4 header to emit. The single [`Ipv4Repr::emit`] entry point writes
/// every field in the correct order and fills the checksum last, so the field-ordering
/// hazards (computing the checksum before `total_len`/`src`/`dst` are set) cannot occur.
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Repr {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub protocol: u8,
    /// Length of the L4 payload that will follow the 20-byte header.
    pub payload_len: u16,
    pub ttl: u8,
}

impl Ipv4Repr {
    /// We never emit IP options, so the emitted header is always the minimum 20 bytes.
    pub const HEADER_LEN: usize = IPV4_MIN_HEADER_LEN;

    #[inline]
    pub fn total_len(&self) -> usize {
        Self::HEADER_LEN + self.payload_len as usize
    }

    /// Write the 20-byte header into `buf[..20]`; the caller writes the payload into
    /// `buf[20..20 + payload_len]`. Returns the header length (always 20).
    ///
    /// Panics if `buf` is shorter than 20 bytes — a programming error on the TX path, where
    /// buffers are always sized to `total_len`.
    pub fn emit(&self, buf: &mut [u8]) -> usize {
        let total = self.total_len() as u16;
        buf[0] = (4 << 4) | 5; // version 4, IHL 5 (20 bytes, no options)
        buf[1] = 0; // DSCP / ECN
        buf[2..4].copy_from_slice(&total.to_be_bytes());
        buf[4..6].copy_from_slice(&[0, 0]); // identification (0; we never fragment)
        buf[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // Don't Fragment
        buf[8] = self.ttl;
        buf[9] = self.protocol;
        buf[10..12].copy_from_slice(&[0, 0]); // checksum zeroed for computation
        buf[12..16].copy_from_slice(&self.src.octets());
        buf[16..20].copy_from_slice(&self.dst.octets());
        let csum = checksum::checksum(&buf[..Self::HEADER_LEN]);
        buf[10..12].copy_from_slice(&csum.to_be_bytes());
        Self::HEADER_LEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn emit_packet(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload: &[u8]) -> Vec<u8> {
        let repr = Ipv4Repr {
            src,
            dst,
            protocol,
            payload_len: payload.len() as u16,
            ttl: 64,
        };
        let mut buf = vec![0u8; repr.total_len()];
        repr.emit(&mut buf);
        buf[Ipv4Repr::HEADER_LEN..].copy_from_slice(payload);
        buf
    }

    #[test]
    fn emit_then_parse_round_trips() {
        let src = Ipv4Addr::new(10, 0, 0, 2);
        let dst = Ipv4Addr::new(10, 0, 0, 1);
        let pkt = emit_packet(src, dst, super::checksum::IPPROTO_TCP, b"payload");
        let parsed = Ipv4Packet::new_checked(&pkt).unwrap();
        assert_eq!(parsed.version(), 4);
        assert_eq!(parsed.header_len(), 20);
        assert_eq!(parsed.protocol(), super::checksum::IPPROTO_TCP);
        assert_eq!(parsed.src(), src);
        assert_eq!(parsed.dst(), dst);
        assert_eq!(parsed.ttl(), 64);
        assert!(parsed.checksum_valid());
        assert_eq!(parsed.payload(), b"payload");
    }

    #[test]
    fn payload_excludes_trailing_slack() {
        let pkt = emit_packet(
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::LOCALHOST,
            super::checksum::IPPROTO_ICMP,
            b"abcd",
        );
        // Hand the parser a buffer with 8 bytes of trailing slack appended.
        let mut padded = pkt.clone();
        padded.extend_from_slice(&[0xff; 8]);
        let parsed = Ipv4Packet::new_checked(&padded).unwrap();
        assert_eq!(parsed.payload(), b"abcd"); // slack is not part of the payload
    }

    #[test]
    fn rejects_truncated() {
        assert_eq!(Ipv4Packet::new_checked(&[0x45; 10]), Err(ParseError::Truncated));
        // Declares total_len larger than the buffer.
        let mut pkt = emit_packet(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, 6, b"xyz");
        pkt[2..4].copy_from_slice(&999u16.to_be_bytes());
        assert_eq!(Ipv4Packet::new_checked(&pkt), Err(ParseError::Truncated));
    }

    #[test]
    fn rejects_bad_version_and_ihl() {
        let mut pkt = emit_packet(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, 6, b"xyz");
        let saved = pkt[0];
        pkt[0] = 0x55; // version 5
        assert_eq!(Ipv4Packet::new_checked(&pkt), Err(ParseError::BadVersion));
        pkt[0] = 0x44; // version 4, IHL 4 => 16-byte header, below the minimum
        assert_eq!(Ipv4Packet::new_checked(&pkt), Err(ParseError::BadHeaderLen));
        pkt[0] = saved;
        assert!(Ipv4Packet::new_checked(&pkt).is_ok());
    }

    #[test]
    fn rejects_fragments() {
        let mut pkt = emit_packet(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, 6, b"xyz");
        pkt[6] |= 0x20; // set the More-Fragments bit
        assert_eq!(Ipv4Packet::new_checked(&pkt), Err(ParseError::Fragmented));
    }
}
