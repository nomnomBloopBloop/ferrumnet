//! Zero-copy TCP parsing ([`TcpPacket`]) and a single-entry-point emitter ([`TcpRepr`]).
//!
//! As with IPv4, reading hands out a borrowed view validated by [`TcpPacket::new_checked`]
//! (after which accessors never panic), and writing goes through [`TcpRepr::emit`], which
//! lays the header + options + payload down in the correct order and fills the checksum last
//! — so the data-offset/payload/checksum ordering hazards cannot occur.

use std::net::Ipv4Addr;

use super::checksum;
use crate::seq::SeqNumber;

pub const TCP_MIN_HEADER_LEN: usize = 20;
pub const TCP_MAX_HEADER_LEN: usize = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Buffer shorter than the header, or shorter than the declared data offset.
    Truncated,
    /// Data offset outside the legal 20..=60 byte range.
    BadDataOffset,
}

/// TCP control flags (byte 13 of the header).
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpFlags(pub u8);

impl TcpFlags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
    pub const ECE: u8 = 0x40;
    pub const CWR: u8 = 0x80;

    #[inline]
    pub fn has(self, bit: u8) -> bool {
        self.0 & bit != 0
    }
    #[inline]
    pub fn with(mut self, bit: u8) -> Self {
        self.0 |= bit;
        self
    }
    #[inline]
    pub fn fin(self) -> bool {
        self.has(Self::FIN)
    }
    #[inline]
    pub fn syn(self) -> bool {
        self.has(Self::SYN)
    }
    #[inline]
    pub fn rst(self) -> bool {
        self.has(Self::RST)
    }
    #[inline]
    pub fn ack(self) -> bool {
        self.has(Self::ACK)
    }
    #[inline]
    pub fn psh(self) -> bool {
        self.has(Self::PSH)
    }
}

impl core::fmt::Debug for TcpFlags {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut first = true;
        let mut put = |name: &str, on: bool, f: &mut core::fmt::Formatter<'_>| -> core::fmt::Result {
            if on {
                if !first {
                    write!(f, "|")?;
                }
                first = false;
                write!(f, "{name}")?;
            }
            Ok(())
        };
        write!(f, "TcpFlags(")?;
        put("SYN", self.syn(), f)?;
        put("ACK", self.ack(), f)?;
        put("FIN", self.fin(), f)?;
        put("RST", self.rst(), f)?;
        put("PSH", self.psh(), f)?;
        put("URG", self.has(Self::URG), f)?;
        write!(f, ")")
    }
}

/// A read-only, zero-copy view over a received TCP segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpPacket<'a> {
    buf: &'a [u8],
}

impl<'a> TcpPacket<'a> {
    pub fn new_checked(buf: &'a [u8]) -> Result<Self, ParseError> {
        if buf.len() < TCP_MIN_HEADER_LEN {
            return Err(ParseError::Truncated);
        }
        let p = TcpPacket { buf };
        let data_off = p.data_offset();
        if !(TCP_MIN_HEADER_LEN..=TCP_MAX_HEADER_LEN).contains(&data_off) {
            return Err(ParseError::BadDataOffset);
        }
        if buf.len() < data_off {
            return Err(ParseError::Truncated);
        }
        Ok(p)
    }

    #[inline]
    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes([self.buf[0], self.buf[1]])
    }
    #[inline]
    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes([self.buf[2], self.buf[3]])
    }
    #[inline]
    pub fn seq(&self) -> SeqNumber {
        SeqNumber::new(u32::from_be_bytes([self.buf[4], self.buf[5], self.buf[6], self.buf[7]]))
    }
    #[inline]
    pub fn ack(&self) -> SeqNumber {
        SeqNumber::new(u32::from_be_bytes([
            self.buf[8],
            self.buf[9],
            self.buf[10],
            self.buf[11],
        ]))
    }
    #[inline]
    pub fn data_offset(&self) -> usize {
        (self.buf[12] >> 4) as usize * 4
    }
    #[inline]
    pub fn flags(&self) -> TcpFlags {
        TcpFlags(self.buf[13])
    }
    #[inline]
    pub fn window(&self) -> u16 {
        u16::from_be_bytes([self.buf[14], self.buf[15]])
    }
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.buf[16], self.buf[17]])
    }
    #[inline]
    pub fn options(&self) -> &'a [u8] {
        &self.buf[TCP_MIN_HEADER_LEN..self.data_offset()]
    }
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.buf[self.data_offset()..]
    }
    /// The whole segment bytes (header + options + payload), as received.
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.buf
    }

    /// Parse the Maximum Segment Size option, if present (kind 2, length 4).
    pub fn mss_option(&self) -> Option<u16> {
        let opts = self.options();
        let mut i = 0;
        while i < opts.len() {
            match opts[i] {
                0 => break,            // End of Option List
                1 => i += 1,           // No-Operation (single byte)
                2 => {
                    // MSS: kind(1) len(1)==4 value(2)
                    if i + 4 > opts.len() || opts[i + 1] != 4 {
                        break;
                    }
                    return Some(u16::from_be_bytes([opts[i + 2], opts[i + 3]]));
                }
                _ => {
                    // Generic TLV option: kind(1) len(1) value(len-2).
                    if i + 1 >= opts.len() {
                        break;
                    }
                    let len = opts[i + 1] as usize;
                    if len < 2 || i + len > opts.len() {
                        break;
                    }
                    i += len;
                }
            }
        }
        None
    }
}

/// A description of a TCP segment to emit. `ack` is meaningful only when `flags` includes ACK;
/// `mss` emits the MSS option (used on SYN / SYN-ACK).
#[derive(Debug, Clone, Copy)]
pub struct TcpRepr {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: SeqNumber,
    pub ack: SeqNumber,
    pub flags: TcpFlags,
    pub window: u16,
    pub mss: Option<u16>,
}

impl TcpRepr {
    /// Header length including options, always a multiple of 4 (the only option we emit, MSS,
    /// is itself 4 bytes).
    #[inline]
    pub fn header_len(&self) -> usize {
        TCP_MIN_HEADER_LEN + if self.mss.is_some() { 4 } else { 0 }
    }

    /// Write the complete TCP segment (header + options + `payload`) into `buf`, using the IP
    /// addresses for the checksum pseudo-header, and return the segment length.
    ///
    /// Panics if `buf` is shorter than `header_len() + payload.len()` — a TX-path programming
    /// error (segments are always emitted into buffers sized to fit).
    pub fn emit(&self, src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8], buf: &mut [u8]) -> usize {
        let hlen = self.header_len();
        let total = hlen + payload.len();

        buf[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        buf[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        buf[4..8].copy_from_slice(&self.seq.raw().to_be_bytes());
        buf[8..12].copy_from_slice(&self.ack.raw().to_be_bytes());
        buf[12] = ((hlen / 4) as u8) << 4; // data offset in 32-bit words; reserved = 0
        buf[13] = self.flags.0;
        buf[14..16].copy_from_slice(&self.window.to_be_bytes());
        buf[16..18].copy_from_slice(&[0, 0]); // checksum zeroed for computation
        buf[18..20].copy_from_slice(&[0, 0]); // urgent pointer

        if let Some(mss) = self.mss {
            buf[20] = 2; // kind: MSS
            buf[21] = 4; // length
            buf[22..24].copy_from_slice(&mss.to_be_bytes());
        }

        buf[hlen..total].copy_from_slice(payload);

        let csum = checksum::tcp_checksum(src, dst, &buf[..total]);
        buf[16..18].copy_from_slice(&csum.to_be_bytes());
        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const B: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

    #[test]
    fn emit_then_parse_syn_ack_with_mss() {
        let repr = TcpRepr {
            src_port: 8080,
            dst_port: 54321,
            seq: SeqNumber::new(0x1000),
            ack: SeqNumber::new(0x2001),
            flags: TcpFlags::default().with(TcpFlags::SYN).with(TcpFlags::ACK),
            window: 64240,
            mss: Some(1460),
        };
        let mut buf = [0u8; 40];
        let n = repr.emit(B, A, b"", &mut buf);
        assert_eq!(n, 24); // 20-byte header + 4-byte MSS option

        let pkt = TcpPacket::new_checked(&buf[..n]).unwrap();
        assert_eq!(pkt.src_port(), 8080);
        assert_eq!(pkt.dst_port(), 54321);
        assert_eq!(pkt.seq(), SeqNumber::new(0x1000));
        assert_eq!(pkt.ack(), SeqNumber::new(0x2001));
        assert_eq!(pkt.data_offset(), 24);
        assert!(pkt.flags().syn() && pkt.flags().ack());
        assert!(!pkt.flags().fin());
        assert_eq!(pkt.window(), 64240);
        assert_eq!(pkt.mss_option(), Some(1460));
        assert!(pkt.payload().is_empty());
        assert!(checksum::tcp_checksum_valid(B, A, pkt.as_bytes()));
    }

    #[test]
    fn emit_then_parse_data_segment() {
        let repr = TcpRepr {
            src_port: 8080,
            dst_port: 40000,
            seq: SeqNumber::new(100),
            ack: SeqNumber::new(200),
            flags: TcpFlags::default().with(TcpFlags::ACK).with(TcpFlags::PSH),
            window: 1000,
            mss: None,
        };
        let payload = b"GET / HTTP/1.0\r\n\r\n";
        let mut buf = [0u8; 80];
        let n = repr.emit(B, A, payload, &mut buf);
        assert_eq!(n, 20 + payload.len());

        let pkt = TcpPacket::new_checked(&buf[..n]).unwrap();
        assert_eq!(pkt.data_offset(), 20);
        assert_eq!(pkt.payload(), payload);
        assert!(pkt.mss_option().is_none());
        assert!(checksum::tcp_checksum_valid(B, A, pkt.as_bytes()));
    }

    #[test]
    fn rejects_truncated_and_bad_data_offset() {
        assert_eq!(TcpPacket::new_checked(&[0u8; 10]), Err(ParseError::Truncated));
        let mut buf = [0u8; 20];
        buf[12] = 0x40; // data offset 4 words = 16 bytes, below the 20-byte minimum
        assert_eq!(TcpPacket::new_checked(&buf), Err(ParseError::BadDataOffset));
        buf[12] = 0x60; // data offset 6 words = 24 bytes, but only 20 present
        assert_eq!(TcpPacket::new_checked(&buf), Err(ParseError::Truncated));
    }

    #[test]
    fn mss_option_after_nop_padding() {
        // Hand-build options: NOP, NOP, MSS=536.
        let repr = TcpRepr {
            src_port: 1,
            dst_port: 2,
            seq: SeqNumber::new(0),
            ack: SeqNumber::new(0),
            flags: TcpFlags::default().with(TcpFlags::SYN),
            window: 0,
            mss: None,
        };
        let mut buf = [0u8; 28];
        repr.emit(A, B, b"", &mut buf);
        // Rewrite as a 28-byte header carrying NOP, NOP, MSS=536, then EOL padding.
        buf[12] = (7u8) << 4; // 28-byte header (8 option bytes)
        buf[20] = 1; // NOP
        buf[21] = 1; // NOP
        buf[22] = 2; // MSS
        buf[23] = 4;
        buf[24..26].copy_from_slice(&536u16.to_be_bytes());
        buf[26] = 0; // End of Option List
        buf[27] = 0;
        let pkt = TcpPacket::new_checked(&buf[..28]).unwrap();
        assert_eq!(pkt.mss_option(), Some(536));
    }
}
