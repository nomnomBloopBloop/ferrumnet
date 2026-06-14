//! The Transmission Control Block: one connection's state machine.
//!
//! M1 scope: passive open through `Established`, RFC 5961 RST handling with a per-connection
//! challenge-ACK rate limiter, the four-case segment-acceptability test, in-order data receipt
//! with cumulative ACKs, and a basic peer-FIN transition to `CloseWait`. Reliable sending,
//! retransmission, flow control, and the closing handshake arrive in M2 — those code paths do
//! not exist yet (they are not stubs).
//!
//! All transitions take `&mut self` and run on a single thread; the sequence variables are
//! never exposed for interior mutation, so the "all transitions on one thread" invariant the
//! sans-IO design promises is enforced by the type system.

use crate::iface::{build_segment, Endpoint};
use crate::seq::SeqNumber;
use crate::state::State;
use crate::time::Instant;
use crate::wire::{TcpFlags, TcpPacket, TcpRepr};

/// MSS we advertise: our link MTU (1500) − IPv4 (20) − TCP (20).
const MSS_ADVERTISE: u16 = 1460;
/// The RFC 9293 default MSS to assume when the peer sends no MSS option.
const MSS_DEFAULT: u16 = 536;
/// Fixed receive window for M1 (real, buffer-derived flow control lands in M2).
const RECV_WINDOW: u16 = 65535;
/// RFC 5961 challenge-ACK budget per connection per second.
const CHALLENGE_ACK_LIMIT: u32 = 100;

/// A queue of fully-built outbound IP datagrams. M1 uses owned buffers for simplicity; M2
/// replaces this with the tx ring + retransmission queue.
pub type Egress = Vec<Vec<u8>>;

pub struct Tcb {
    pub state: State,
    local: Endpoint,
    remote: Endpoint,

    // Send sequence space (RFC 793 §3.3).
    iss: SeqNumber,
    snd_una: SeqNumber,
    snd_nxt: SeqNumber,
    #[allow(dead_code)] // M2: drives the send window
    snd_wnd: u16,
    #[allow(dead_code)] // M2: caps outbound segment size
    snd_mss: u16,

    // Receive sequence space.
    irs: SeqNumber,
    rcv_nxt: SeqNumber,
    rcv_wnd: u16,

    /// Bytes received in order and delivered to the application (M2 makes this a ring buffer).
    pub rx: Vec<u8>,

    // RFC 5961 challenge-ACK rate limiter (per connection — NOT global; CVE-2016-5696).
    challenge_window_start: Instant,
    challenge_count: u32,
}

impl Tcb {
    /// Passive open: a SYN arrived for our listening endpoint. Build the connection in
    /// `SynReceived` and emit the SYN-ACK.
    pub fn new_syn_received(
        local: Endpoint,
        remote: Endpoint,
        syn: &TcpPacket<'_>,
        iss: SeqNumber,
        now: Instant,
        out: &mut Egress,
    ) -> Self {
        let snd_mss = syn.mss_option().unwrap_or(MSS_DEFAULT).min(MSS_ADVERTISE);
        let irs = syn.seq();
        let tcb = Tcb {
            state: State::SynReceived,
            local,
            remote,
            iss,
            snd_una: iss,
            snd_nxt: iss + 1, // our SYN consumes one sequence number
            snd_wnd: syn.window(),
            snd_mss,
            irs,
            rcv_nxt: irs + 1, // the peer's SYN consumes one sequence number
            rcv_wnd: RECV_WINDOW,
            rx: Vec::new(),
            challenge_window_start: now,
            challenge_count: 0,
        };
        // SYN-ACK: seq = ISS, ack = RCV.NXT, advertise our MSS.
        tcb.emit(out, tcb.iss, TcpFlags::SYN | TcpFlags::ACK, Some(MSS_ADVERTISE), b"");
        tcb
    }

    /// Process one received segment for an existing connection.
    pub fn on_segment(&mut self, now: Instant, tcp: &TcpPacket<'_>, out: &mut Egress) {
        let seg_seq = tcp.seq();
        let seg_ack = tcp.ack();
        let flags = tcp.flags();
        let payload = tcp.payload();
        let seg_len = payload.len() as u32
            + u32::from(flags.syn())
            + u32::from(flags.fin());

        // (1) RST — RFC 5961 §3.2: only the in-window check applies; never ACK an out-of-window
        // RST, never reply to a RST with a RST.
        if flags.rst() {
            if self.seq_in_window(seg_seq) {
                if seg_seq == self.rcv_nxt {
                    self.state = State::Closed; // exact match: accept the reset
                } else {
                    self.challenge_ack(now, out); // in-window but not next: challenge only
                }
            }
            return;
        }

        // (2) SYN on an existing connection.
        if flags.syn() {
            if self.state == State::SynReceived && seg_seq == self.irs {
                // Retransmitted SYN (our SYN-ACK was lost) — resend it.
                self.emit(out, self.iss, TcpFlags::SYN | TcpFlags::ACK, Some(MSS_ADVERTISE), b"");
            } else if self.seq_in_window(seg_seq) {
                // In-window SYN on a synchronized connection is illegal — challenge (RFC 5961).
                self.challenge_ack(now, out);
            }
            return;
        }

        // (3) Acceptability (four-case test, RFC 793 §3.9).
        if !self.segment_acceptable(seg_seq, seg_len) {
            // Unacceptable, non-RST segment: reply with a current ACK and drop it.
            self.emit(out, self.snd_nxt, TcpFlags::ACK, None, b"");
            return;
        }

        // (4) ACK — after the handshake every segment must carry it.
        if !flags.ack() {
            return;
        }
        match self.state {
            State::SynReceived => {
                // The ACK must acknowledge our SYN: SND.UNA < SEG.ACK <= SND.NXT.
                if seg_ack.gt(self.snd_una) && seg_ack.le(self.snd_nxt) {
                    self.snd_una = seg_ack;
                    self.snd_wnd = tcp.window();
                    self.state = State::Established;
                } else {
                    // Bad ACK while half-open: reset (RFC 793).
                    self.send_rst_seq(out, seg_ack);
                    self.state = State::Closed;
                    return;
                }
            }
            _ => {
                if seg_ack.gt(self.snd_una) && seg_ack.le(self.snd_nxt) {
                    self.snd_una = seg_ack;
                }
                self.snd_wnd = tcp.window();
            }
        }

        // (5) In-order data (no reassembly in M1).
        if !payload.is_empty() && self.state == State::Established {
            if seg_seq == self.rcv_nxt {
                self.rx.extend_from_slice(payload);
                self.rcv_nxt += payload.len() as u32;
            }
            // Acknowledge — cumulatively for in-order data, or a duplicate ACK for the gap.
            self.emit(out, self.snd_nxt, TcpFlags::ACK, None, b"");
        }

        // (6) Peer FIN (basic half-close; our-side close + TIME-WAIT is M2).
        if flags.fin() && self.state == State::Established {
            // Accept the FIN only once everything before it is in order.
            if seg_seq + (payload.len() as u32) == self.rcv_nxt {
                self.rcv_nxt += 1; // FIN consumes one sequence number
                self.emit(out, self.snd_nxt, TcpFlags::ACK, None, b"");
                self.state = State::CloseWait;
            }
        }
    }

    // ── helpers ─────────────────────────────────────────────────────────────────────────

    /// `RCV.NXT <= seq < RCV.NXT + RCV.WND`.
    fn seq_in_window(&self, seq: SeqNumber) -> bool {
        let right = self.rcv_nxt + self.rcv_wnd as u32;
        seq.ge(self.rcv_nxt) && seq.lt(right)
    }

    /// The four-case acceptability test (RFC 793 §3.9, "Segment Arrives").
    fn segment_acceptable(&self, seq: SeqNumber, seg_len: u32) -> bool {
        let wnd = self.rcv_wnd as u32;
        let right = self.rcv_nxt + wnd;
        match (seg_len == 0, wnd == 0) {
            (true, true) => seq == self.rcv_nxt,
            (true, false) => seq.ge(self.rcv_nxt) && seq.lt(right),
            (false, true) => false, // data with a closed window is never acceptable
            (false, false) => {
                let last = seq + (seg_len - 1);
                (seq.ge(self.rcv_nxt) && seq.lt(right))
                    || (last.ge(self.rcv_nxt) && last.lt(right))
            }
        }
    }

    /// Send a challenge ACK, rate-limited per RFC 5961 with a per-connection token budget.
    fn challenge_ack(&mut self, now: Instant, out: &mut Egress) {
        if now.saturating_micros_since(self.challenge_window_start) >= 1_000_000 {
            self.challenge_window_start = now;
            self.challenge_count = 0;
        }
        if self.challenge_count < CHALLENGE_ACK_LIMIT {
            self.challenge_count += 1;
            self.emit(out, self.snd_nxt, TcpFlags::ACK, None, b"");
        }
    }

    /// Emit a segment. `seq` is the sequence number to stamp; the ACK number is always the
    /// current `RCV.NXT` (we only ever emit ACK-bearing or control segments).
    fn emit(&self, out: &mut Egress, seq: SeqNumber, flag_bits: u8, mss: Option<u16>, payload: &[u8]) {
        let flags = TcpFlags(flag_bits);
        let repr = TcpRepr {
            src_port: self.local.port,
            dst_port: self.remote.port,
            seq,
            ack: if flags.ack() { self.rcv_nxt } else { SeqNumber::new(0) },
            flags,
            window: self.rcv_wnd,
            mss,
        };
        out.push(build_segment(self.local, self.remote, &repr, payload));
    }

    /// Send a bare RST with the given sequence number (no ACK) — used for a bad ACK while
    /// half-open.
    fn send_rst_seq(&self, out: &mut Egress, seq: SeqNumber) {
        let repr = TcpRepr {
            src_port: self.local.port,
            dst_port: self.remote.port,
            seq,
            ack: SeqNumber::new(0),
            flags: TcpFlags(TcpFlags::RST),
            window: 0,
            mss: None,
        };
        out.push(build_segment(self.local, self.remote, &repr, b""));
    }
}
