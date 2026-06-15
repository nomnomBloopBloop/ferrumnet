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

/// Maximum SACK blocks we parse or emit. With no TCP-timestamps option in play, four 8-byte
/// blocks plus the 2-byte option header and 2 NOP-pad bytes is 36 bytes — within the 40-byte
/// TCP options limit. (RFC 2018 §3.)
pub const MAX_SACK_BLOCKS: usize = 4;

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

    /// Walk the TCP options, invoking `f(kind, value)` for every well-formed TLV option.
    /// EOL (kind 0) ends the walk; NOP (kind 1) is skipped; a truncated or malformed length
    /// silently ends the walk (the segment view is already bounds-checked, so this never
    /// panics). This single audited walker backs every option accessor below.
    fn for_each_option(&self, mut f: impl FnMut(u8, &[u8])) {
        let opts = self.options();
        let mut i = 0;
        while i < opts.len() {
            match opts[i] {
                0 => break,      // End of Option List
                1 => i += 1,     // No-Operation (single byte, no length/value)
                _ => {
                    // Generic TLV option: kind(1) len(1) value(len-2).
                    if i + 1 >= opts.len() {
                        break;
                    }
                    let len = opts[i + 1] as usize;
                    if len < 2 || i + len > opts.len() {
                        break;
                    }
                    f(opts[i], &opts[i + 2..i + len]);
                    i += len;
                }
            }
        }
    }

    /// Parse the Maximum Segment Size option, if present (kind 2, length 4 => 2-byte value).
    pub fn mss_option(&self) -> Option<u16> {
        let mut mss = None;
        self.for_each_option(|kind, value| {
            if kind == 2 && value.len() == 2 && mss.is_none() {
                mss = Some(u16::from_be_bytes([value[0], value[1]]));
            }
        });
        mss
    }

    /// Parse the Timestamps option (kind 8, length 10 => `(TSval, TSecr)`). Sent on every segment
    /// once negotiated on the handshake (RFC 7323 §3).
    pub fn timestamps(&self) -> Option<(u32, u32)> {
        let mut ts = None;
        self.for_each_option(|kind, value| {
            if kind == 8 && value.len() == 8 && ts.is_none() {
                let tsval = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                let tsecr = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
                ts = Some((tsval, tsecr));
            }
        });
        ts
    }

    /// Parse the Window Scale option (kind 3, length 3 => 1-byte shift count), clamped to the
    /// RFC 7323 maximum of 14. Sent only on SYN/SYN-ACK; enables windows beyond 64 KiB.
    pub fn window_scale(&self) -> Option<u8> {
        let mut scale = None;
        self.for_each_option(|kind, value| {
            if kind == 3 && value.len() == 1 && scale.is_none() {
                scale = Some(value[0].min(14));
            }
        });
        scale
    }

    /// True if the peer offered the SACK-Permitted option (kind 4, length 2 — an empty value).
    /// Sent only on SYN; a server echoes it on its SYN-ACK to enable SACK for the connection.
    pub fn sack_permitted(&self) -> bool {
        let mut permitted = false;
        self.for_each_option(|kind, value| {
            if kind == 4 && value.is_empty() {
                permitted = true;
            }
        });
        permitted
    }

    /// Parse the SACK option (kind 5): up to [`MAX_SACK_BLOCKS`] `(left_edge, right_edge)`
    /// sequence-number pairs reporting blocks of data the peer has buffered out of order.
    /// Fills `out` and returns the number of blocks parsed; extra blocks beyond the array and
    /// any trailing partial pair are ignored. (RFC 2018 §3.)
    pub fn sack_blocks(&self, out: &mut [(SeqNumber, SeqNumber); MAX_SACK_BLOCKS]) -> usize {
        let mut n = 0;
        self.for_each_option(|kind, value| {
            if kind != 5 {
                return;
            }
            let mut j = 0;
            while j + 8 <= value.len() && n < MAX_SACK_BLOCKS {
                let left = u32::from_be_bytes([value[j], value[j + 1], value[j + 2], value[j + 3]]);
                let right =
                    u32::from_be_bytes([value[j + 4], value[j + 5], value[j + 6], value[j + 7]]);
                out[n] = (SeqNumber::new(left), SeqNumber::new(right));
                n += 1;
                j += 8;
            }
        });
        n
    }
}

/// Up to [`MAX_SACK_BLOCKS`] `(left, right)` SACK blocks to emit (kind 5). Inline and `Copy`, so
/// [`TcpRepr`] stays `Copy`. `(SeqNumber, SeqNumber)` is not `Default` (`SeqNumber` has no
/// `Default`), so the `Default` impl is hand-written rather than derived.
#[derive(Debug, Clone, Copy)]
pub struct SackBlocks {
    pub blocks: [(SeqNumber, SeqNumber); MAX_SACK_BLOCKS],
    pub len: u8,
}

impl Default for SackBlocks {
    fn default() -> Self {
        SackBlocks {
            blocks: [(SeqNumber::new(0), SeqNumber::new(0)); MAX_SACK_BLOCKS],
            len: 0,
        }
    }
}

impl SackBlocks {
    #[inline]
    pub fn len(&self) -> usize {
        self.len as usize
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// Append a block, silently capped at [`MAX_SACK_BLOCKS`].
    pub fn push(&mut self, left: SeqNumber, right: SeqNumber) {
        if (self.len as usize) < MAX_SACK_BLOCKS {
            self.blocks[self.len as usize] = (left, right);
            self.len += 1;
        }
    }
}

/// A description of a TCP segment to emit. `ack` is meaningful only when `flags` includes ACK;
/// `mss` emits the MSS option (used on SYN / SYN-ACK); `sack_permitted` emits the SACK-Permitted
/// option (SYN-ACK only); a non-empty `sack` emits the SACK option (kind 5) on data/pure ACKs.
#[derive(Debug, Clone, Copy)]
pub struct TcpRepr {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: SeqNumber,
    pub ack: SeqNumber,
    pub flags: TcpFlags,
    pub window: u16,
    pub mss: Option<u16>,
    pub sack_permitted: bool,
    pub sack: SackBlocks,
    /// Window Scale shift to advertise (SYN-ACK only); the window field is the *scaled* value.
    pub window_scale: Option<u8>,
    /// RFC 7323 Timestamps `(TSval, TSecr)`, emitted on every segment once negotiated. When this
    /// is set alongside SACK blocks the option area would exceed 40 bytes, so the emitter caps the
    /// SACK blocks at 3 (12 bytes for timestamps + 4 + 8·3 = 40).
    pub timestamps: Option<(u32, u32)>,
}

impl TcpRepr {
    /// Header length including options, always a multiple of 4. Each emitted option is padded to
    /// a 4-byte boundary: MSS is 4 bytes; SACK-Permitted is 2 NOPs + 2 bytes = 4; Timestamps is
    /// 2 NOPs + 2 header bytes + 8 = 12; the SACK block option is 2 NOPs + 2 header bytes + 8·n.
    /// MSS (SYN-ACK only) and SACK blocks (data ACKs only) never coexist; the contended worst case
    /// is Timestamps + SACK, which [`TcpRepr::sack_blocks_to_emit`] caps at 3 blocks so the option
    /// area is `12 + 4 + 8·3 = 40`, exactly the limit.
    #[inline]
    pub fn header_len(&self) -> usize {
        let mut opt = 0;
        if self.mss.is_some() {
            opt += 4;
        }
        if self.sack_permitted {
            opt += 4;
        }
        if self.window_scale.is_some() {
            opt += 4; // NOP + kind3 + len3 + shift
        }
        if self.timestamps.is_some() {
            opt += 12; // NOP + NOP + kind8 + len10 + TSval(4) + TSecr(4)
        }
        let n = self.sack_blocks_to_emit();
        if n > 0 {
            opt += 4 + 8 * n;
        }
        debug_assert!(opt <= 40, "TCP options exceed the 40-byte limit");
        debug_assert_eq!(opt % 4, 0, "TCP options must be 4-byte aligned");
        TCP_MIN_HEADER_LEN + opt
    }

    /// SACK blocks that fit the option budget. With timestamps present (12 bytes) at most 3 blocks
    /// fit (12 + 4 + 8·3 = 40); without them, up to [`MAX_SACK_BLOCKS`]. MSS (SYN-only) and SACK
    /// blocks (data-ACK-only) never coexist, so this is the only contended case.
    #[inline]
    fn sack_blocks_to_emit(&self) -> usize {
        let cap = if self.timestamps.is_some() { 3 } else { MAX_SACK_BLOCKS };
        self.sack.len().min(cap)
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

        // Options, in a fixed order. Each is laid down 4-byte aligned (NOP padding where the
        // option's own length is not a multiple of 4); `header_len()` accounts for exactly this.
        let mut o = TCP_MIN_HEADER_LEN;
        if let Some(mss) = self.mss {
            buf[o] = 2; // kind: MSS
            buf[o + 1] = 4; // length
            buf[o + 2..o + 4].copy_from_slice(&mss.to_be_bytes());
            o += 4;
        }
        if self.sack_permitted {
            buf[o] = 1; // NOP
            buf[o + 1] = 1; // NOP (align the option to 4 bytes)
            buf[o + 2] = 4; // kind: SACK-Permitted
            buf[o + 3] = 2; // length
            o += 4;
        }
        if let Some(shift) = self.window_scale {
            buf[o] = 1; // NOP (align the 3-byte option to 4 bytes)
            buf[o + 1] = 3; // kind: Window Scale
            buf[o + 2] = 3; // length
            buf[o + 3] = shift; // shift count
            o += 4;
        }
        if let Some((tsval, tsecr)) = self.timestamps {
            buf[o] = 1; // NOP
            buf[o + 1] = 1; // NOP (align the 10-byte option to 4 bytes)
            buf[o + 2] = 8; // kind: Timestamps
            buf[o + 3] = 10; // length
            buf[o + 4..o + 8].copy_from_slice(&tsval.to_be_bytes());
            buf[o + 8..o + 12].copy_from_slice(&tsecr.to_be_bytes());
            o += 12;
        }
        let n = self.sack_blocks_to_emit();
        if n > 0 {
            buf[o] = 1; // NOP
            buf[o + 1] = 1; // NOP
            buf[o + 2] = 5; // kind: SACK
            buf[o + 3] = (2 + 8 * n) as u8; // length
            o += 4;
            for &(left, right) in &self.sack.blocks[..n] {
                buf[o..o + 4].copy_from_slice(&left.raw().to_be_bytes());
                buf[o + 4..o + 8].copy_from_slice(&right.raw().to_be_bytes());
                o += 8;
            }
        }
        debug_assert_eq!(o, hlen, "emitted option bytes must match header_len()");

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
            sack_permitted: false,
            window_scale: None,
            sack: SackBlocks::default(),
            timestamps: None,
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
            sack_permitted: false,
            window_scale: None,
            sack: SackBlocks::default(),
            timestamps: None,
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
            sack_permitted: false,
            window_scale: None,
            sack: SackBlocks::default(),
            timestamps: None,
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

    /// Build a minimal TCP segment whose options area is exactly `opts` (must be 4-byte
    /// aligned). The checksum is irrelevant for option parsing, which `new_checked` does not
    /// verify.
    fn seg_with_options(opts: &[u8]) -> Vec<u8> {
        assert_eq!(opts.len() % 4, 0, "TCP options must be 4-byte aligned");
        let hlen = TCP_MIN_HEADER_LEN + opts.len();
        let mut buf = vec![0u8; hlen];
        buf[12] = ((hlen / 4) as u8) << 4; // data offset in 32-bit words
        buf[13] = TcpFlags::ACK;
        buf[TCP_MIN_HEADER_LEN..].copy_from_slice(opts);
        buf
    }

    #[test]
    fn sack_permitted_option_parsed() {
        // NOP, NOP, kind=4 (SACK-Permitted), len=2.
        let seg = seg_with_options(&[1, 1, 4, 2]);
        let pkt = TcpPacket::new_checked(&seg).unwrap();
        assert!(pkt.sack_permitted());
        assert!(pkt.mss_option().is_none());
        // A header with no options does not claim SACK-Permitted.
        let plain = seg_with_options(&[]);
        assert!(!TcpPacket::new_checked(&plain).unwrap().sack_permitted());
    }

    #[test]
    fn sack_blocks_parsed_in_order() {
        // NOP, NOP, kind=5, len=18 (header + two 8-byte blocks), then the two blocks.
        let mut opts = vec![1u8, 1, 5, 18];
        opts.extend_from_slice(&1000u32.to_be_bytes());
        opts.extend_from_slice(&2000u32.to_be_bytes());
        opts.extend_from_slice(&3000u32.to_be_bytes());
        opts.extend_from_slice(&4000u32.to_be_bytes()); // 4 + 16 = 20 bytes, 4-aligned
        let seg = seg_with_options(&opts);
        let pkt = TcpPacket::new_checked(&seg).unwrap();
        let mut blocks = [(SeqNumber::new(0), SeqNumber::new(0)); MAX_SACK_BLOCKS];
        assert_eq!(pkt.sack_blocks(&mut blocks), 2);
        assert_eq!(blocks[0], (SeqNumber::new(1000), SeqNumber::new(2000)));
        assert_eq!(blocks[1], (SeqNumber::new(3000), SeqNumber::new(4000)));
    }

    #[test]
    fn sack_blocks_absent_or_malformed_are_safe() {
        let mut blocks = [(SeqNumber::new(0), SeqNumber::new(0)); MAX_SACK_BLOCKS];

        // Only an MSS option present: no SACK blocks, MSS still parses.
        let mss_seg = seg_with_options(&[2, 4, 0x05, 0xb4]);
        let pkt = TcpPacket::new_checked(&mss_seg).unwrap();
        assert_eq!(pkt.sack_blocks(&mut blocks), 0);
        assert_eq!(pkt.mss_option(), Some(0x05b4));

        // A SACK option whose declared length (18) overruns the options area is rejected by the
        // walker's bound check — no panic, zero blocks.
        let seg = seg_with_options(&[5, 18, 0, 0, 0, 0, 0, 0]);
        assert_eq!(TcpPacket::new_checked(&seg).unwrap().sack_blocks(&mut blocks), 0);
    }

    #[test]
    fn emit_sack_permitted_on_syn_ack() {
        let repr = TcpRepr {
            src_port: 8080,
            dst_port: 40000,
            seq: SeqNumber::new(1),
            ack: SeqNumber::new(2),
            flags: TcpFlags::default().with(TcpFlags::SYN).with(TcpFlags::ACK),
            window: 64000,
            mss: Some(1460),
            sack_permitted: true,
            window_scale: None,
            sack: SackBlocks::default(),
            timestamps: None,
        };
        let mut buf = [0u8; 60];
        let n = repr.emit(B, A, b"", &mut buf);
        assert_eq!(n, 28); // 20-byte header + MSS(4) + SACK-Permitted(4)
        let pkt = TcpPacket::new_checked(&buf[..n]).unwrap();
        assert_eq!(pkt.data_offset(), 28);
        assert_eq!(pkt.mss_option(), Some(1460));
        assert!(pkt.sack_permitted());
        assert!(checksum::tcp_checksum_valid(B, A, pkt.as_bytes()));
    }

    #[test]
    fn emit_four_sack_blocks_round_trip_within_limit() {
        let mut sack = SackBlocks::default();
        sack.push(SeqNumber::new(10), SeqNumber::new(20));
        sack.push(SeqNumber::new(30), SeqNumber::new(40));
        sack.push(SeqNumber::new(50), SeqNumber::new(60));
        sack.push(SeqNumber::new(70), SeqNumber::new(80));
        let repr = TcpRepr {
            src_port: 8080,
            dst_port: 40000,
            seq: SeqNumber::new(1),
            ack: SeqNumber::new(2),
            flags: TcpFlags::default().with(TcpFlags::ACK),
            window: 1000,
            mss: None,
            sack_permitted: false,
            window_scale: None,
            sack,
            timestamps: None,
        };
        let mut buf = [0u8; 80];
        let n = repr.emit(B, A, b"", &mut buf);
        assert_eq!(n, 20 + 4 + 8 * 4); // 56-byte header (NOP,NOP,kind5,len + four 8-byte blocks)
        let pkt = TcpPacket::new_checked(&buf[..n]).unwrap();
        assert_eq!(pkt.data_offset(), 56);
        assert!(pkt.data_offset() <= TCP_MAX_HEADER_LEN, "within the 60-byte header limit");
        let mut blocks = [(SeqNumber::new(0), SeqNumber::new(0)); MAX_SACK_BLOCKS];
        assert_eq!(pkt.sack_blocks(&mut blocks), 4);
        assert_eq!(blocks[0], (SeqNumber::new(10), SeqNumber::new(20)));
        assert_eq!(blocks[3], (SeqNumber::new(70), SeqNumber::new(80)));
        assert!(checksum::tcp_checksum_valid(B, A, pkt.as_bytes()));
    }

    #[test]
    fn emit_then_parse_window_scale_on_syn_ack() {
        // A SYN-ACK carrying MSS + SACK-Permitted + Window Scale = 12 option bytes (header 32).
        let repr = TcpRepr {
            src_port: 8080,
            dst_port: 40000,
            seq: SeqNumber::new(1),
            ack: SeqNumber::new(2),
            flags: TcpFlags::default().with(TcpFlags::SYN).with(TcpFlags::ACK),
            window: 65535,
            mss: Some(1460),
            sack_permitted: true,
            window_scale: Some(7),
            sack: SackBlocks::default(),
            timestamps: None,
        };
        let mut buf = [0u8; 60];
        let n = repr.emit(B, A, b"", &mut buf);
        assert_eq!(n, 20 + 4 + 4 + 4); // 32-byte header
        let pkt = TcpPacket::new_checked(&buf[..n]).unwrap();
        assert_eq!(pkt.data_offset(), 32);
        assert_eq!(pkt.window_scale(), Some(7));
        assert_eq!(pkt.mss_option(), Some(1460));
        assert!(pkt.sack_permitted());
        assert!(checksum::tcp_checksum_valid(B, A, pkt.as_bytes()));
        // A header with no WScale option parses to None.
        let plain = seg_with_options(&[]);
        assert_eq!(TcpPacket::new_checked(&plain).unwrap().window_scale(), None);
    }

    #[test]
    fn emit_then_parse_timestamps() {
        let repr = TcpRepr {
            src_port: 8080,
            dst_port: 40000,
            seq: SeqNumber::new(1),
            ack: SeqNumber::new(2),
            flags: TcpFlags::default().with(TcpFlags::ACK),
            window: 1000,
            mss: None,
            sack_permitted: false,
            window_scale: None,
            sack: SackBlocks::default(),
            timestamps: Some((0x1122_3344, 0x5566_7788)),
        };
        let mut buf = [0u8; 60];
        let n = repr.emit(B, A, b"", &mut buf);
        assert_eq!(n, 20 + 12); // header + NOP,NOP,kind8,len10 + TSval(4) + TSecr(4)
        let pkt = TcpPacket::new_checked(&buf[..n]).unwrap();
        assert_eq!(pkt.data_offset(), 32);
        assert_eq!(pkt.timestamps(), Some((0x1122_3344, 0x5566_7788)));
        assert!(checksum::tcp_checksum_valid(B, A, pkt.as_bytes()));
        // Absent option parses to None.
        let plain = seg_with_options(&[]);
        assert_eq!(TcpPacket::new_checked(&plain).unwrap().timestamps(), None);
    }

    #[test]
    fn timestamps_cap_sack_to_three_blocks_within_limit() {
        // Timestamps (12 bytes) + 4 SACK blocks would be 12 + 4 + 32 = 48 > 40; the emitter caps
        // the SACK blocks at 3 so the option area stays within the 40-byte limit.
        let mut sack = SackBlocks::default();
        sack.push(SeqNumber::new(10), SeqNumber::new(20));
        sack.push(SeqNumber::new(30), SeqNumber::new(40));
        sack.push(SeqNumber::new(50), SeqNumber::new(60));
        sack.push(SeqNumber::new(70), SeqNumber::new(80));
        let repr = TcpRepr {
            src_port: 8080,
            dst_port: 40000,
            seq: SeqNumber::new(1),
            ack: SeqNumber::new(2),
            flags: TcpFlags::default().with(TcpFlags::ACK),
            window: 1000,
            mss: None,
            sack_permitted: false,
            window_scale: None,
            sack,
            timestamps: Some((1, 2)),
        };
        assert_eq!(repr.header_len(), 20 + 12 + 4 + 8 * 3); // 60-byte header, exactly the max
        let mut buf = [0u8; 80];
        let n = repr.emit(B, A, b"", &mut buf);
        let pkt = TcpPacket::new_checked(&buf[..n]).unwrap();
        assert!(pkt.data_offset() <= TCP_MAX_HEADER_LEN);
        assert_eq!(pkt.timestamps(), Some((1, 2)));
        let mut blocks = [(SeqNumber::new(0), SeqNumber::new(0)); MAX_SACK_BLOCKS];
        assert_eq!(pkt.sack_blocks(&mut blocks), 3, "the 4th SACK block is dropped under timestamps");
        assert!(checksum::tcp_checksum_valid(B, A, pkt.as_bytes()));
    }
}
