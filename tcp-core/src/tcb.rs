//! The Transmission Control Block: one connection's full state machine and reliable transport.
//!
//! Driven sans-IO by three entry points the backend calls in a loop:
//! - [`Tcb::on_segment`] — feed a received segment; updates state, frees acked data, samples
//!   RTT, buffers in-order data, and arms timers. It never emits directly.
//! - [`Tcb::poll_transmit`] — produce the next datagram to send (SYN-ACK, (re)transmitted
//!   data, FIN, zero-window probe, or a pure/duplicate ACK), in a fixed priority order.
//! - [`Tcb::poll_at`] / [`Tcb::on_timer`] — the earliest armed deadline, and firing of the
//!   retransmission, persist, and TIME-WAIT timers.
//!
//! Application I/O is [`Tcb::send`] / [`Tcb::recv`] / [`Tcb::close`].
//!
//! Reliability is go-back-N over a send ring: unacked bytes stay in `tx`; an RTO rewinds
//! `snd_nxt` to `snd_una` and `poll_transmit` resends. Congestion control (Tahoe) layers onto
//! the send window in M3.

use crate::buffers::RingBuffer;
use crate::congestion::Tahoe;
use crate::iface::{build_segment, Endpoint};
use crate::rtt::RttEstimator;
use crate::seq::SeqNumber;
use crate::state::State;
use crate::time::Instant;
use crate::wire::{TcpFlags, TcpPacket, TcpRepr};

const MSS_ADVERTISE: u16 = 1460; // our MTU(1500) - IPv4(20) - TCP(20)
const MSS_DEFAULT: u16 = 536; // RFC 9293 default when the peer sends no MSS option
const TX_BUFFER: usize = 65_536;
const RX_BUFFER: usize = 65_536;
/// TIME-WAIT duration (2·MSL). A demo-friendly value; RFC 793 suggests up to ~4 min.
const TIME_WAIT_MILLIS: u64 = 10_000;
const PERSIST_MIN_MILLIS: u64 = 1_000;
const PERSIST_MAX_MILLIS: u64 = 60_000;
const CHALLENGE_ACK_LIMIT: u32 = 100; // RFC 5961 per-connection budget per second

pub struct Tcb {
    pub state: State,
    local: Endpoint,
    remote: Endpoint,

    // Send sequence space (RFC 793 §3.3).
    iss: SeqNumber,
    snd_una: SeqNumber,
    snd_nxt: SeqNumber,
    snd_wnd: u16,
    snd_wl1: SeqNumber, // seq of the segment that last updated the send window
    snd_wl2: SeqNumber, // ack of that segment
    snd_mss: u16,

    // Receive sequence space.
    irs: SeqNumber,
    rcv_nxt: SeqNumber,
    rcv_wnd: u16,    // the window we most recently advertised
    rcv_adv: SeqNumber, // the right edge we most recently advertised (never moves left)

    tx: RingBuffer, // unacked + unsent application data; tx[0] is the byte at snd_una
    rx: RingBuffer, // in-order received data awaiting the application

    rtt: RttEstimator,
    cc: Tahoe,
    /// (sent_at, seq_end) of the segment currently being timed for RTT, if any.
    rtt_sample: Option<(Instant, SeqNumber)>,
    /// The outstanding window has been retransmitted; suppress RTT sampling (Karn).
    retransmitted: bool,

    // Timers.
    rtx_deadline: Option<Instant>,
    persist_deadline: Option<Instant>,
    persist_backoff: u64,
    time_wait_deadline: Option<Instant>,

    // FIN bookkeeping.
    fin_queued: bool, // the application asked to close
    fin_seq: Option<SeqNumber>, // sequence number assigned to our FIN once sent
    fin_acked: bool,
    peer_fin_seen: bool,

    needs_ack: bool, // an ACK is owed (data received, or a dup/challenge ACK)
    send_probe: bool, // the persist timer fired; emit a 1-byte window probe
    pending_reset: Option<SeqNumber>, // a RST is owed (bad ACK while half-open); seq to stamp

    // RFC 5961 challenge-ACK rate limiter (per connection — not global; CVE-2016-5696).
    challenge_window_start: Instant,
    challenge_count: u32,
}

impl Tcb {
    /// Passive open: a SYN arrived for our listening endpoint. The SYN-ACK is emitted by the
    /// next `poll_transmit`.
    pub fn new_syn_received(
        local: Endpoint,
        remote: Endpoint,
        syn: &TcpPacket<'_>,
        iss: SeqNumber,
        now: Instant,
    ) -> Self {
        let snd_mss = syn.mss_option().unwrap_or(MSS_DEFAULT).min(MSS_ADVERTISE);
        let irs = syn.seq();
        let rcv_nxt = irs + 1; // the peer's SYN consumes one sequence number
        let rcv_wnd = RX_BUFFER.min(0xFFFF) as u16;
        Tcb {
            state: State::SynReceived,
            local,
            remote,
            iss,
            snd_una: iss,
            snd_nxt: iss, // the SYN-ACK has not been sent yet
            snd_wnd: syn.window(),
            snd_wl1: irs,
            snd_wl2: iss,
            snd_mss,
            irs,
            rcv_nxt,
            rcv_wnd,
            rcv_adv: rcv_nxt + rcv_wnd as u32,
            tx: RingBuffer::with_capacity(TX_BUFFER),
            rx: RingBuffer::with_capacity(RX_BUFFER),
            rtt: RttEstimator::new(),
            cc: Tahoe::new(snd_mss),
            rtt_sample: None,
            retransmitted: false,
            rtx_deadline: None,
            persist_deadline: None,
            persist_backoff: PERSIST_MIN_MILLIS,
            time_wait_deadline: None,
            fin_queued: false,
            fin_seq: None,
            fin_acked: false,
            peer_fin_seen: false,
            needs_ack: false,
            send_probe: false,
            pending_reset: None,
            challenge_window_start: now,
            challenge_count: 0,
        }
    }

    // ── application interface ─────────────────────────────────────────────────────────────

    /// Queue application bytes to send. Returns how many were accepted (bounded by tx space).
    pub fn send(&mut self, data: &[u8]) -> usize {
        match self.state {
            State::Established | State::CloseWait => self.tx.write(data),
            _ => 0,
        }
    }

    /// Read received bytes into `dst`. Returns how many were copied.
    pub fn recv(&mut self, dst: &mut [u8]) -> usize {
        self.rx.read(dst)
    }

    /// Begin an orderly close; the FIN is sent after all queued data.
    pub fn close(&mut self) {
        self.fin_queued = true;
    }

    pub fn rx_available(&self) -> usize {
        self.rx.len()
    }
    pub fn tx_free(&self) -> usize {
        self.tx.free()
    }
    /// The peer has closed and we have delivered everything: reads should return EOF.
    pub fn recv_eof(&self) -> bool {
        self.peer_fin_seen && self.rx.is_empty()
    }
    pub fn remote(&self) -> Endpoint {
        self.remote
    }

    // ── inbound ───────────────────────────────────────────────────────────────────────────

    pub fn on_segment(&mut self, now: Instant, tcp: &TcpPacket<'_>) {
        let seg_seq = tcp.seq();
        let seg_ack = tcp.ack();
        let flags = tcp.flags();
        let payload = tcp.payload();
        let seg_len = payload.len() as u32 + u32::from(flags.syn()) + u32::from(flags.fin());

        // (1) RST (RFC 5961 §3.2): in-window only; never ACK an out-of-window RST.
        if flags.rst() {
            if self.seq_in_window(seg_seq) {
                if seg_seq == self.rcv_nxt {
                    self.state = State::Closed;
                } else {
                    self.challenge_ack(now);
                }
            }
            return;
        }

        // (2) SYN on an existing connection.
        if flags.syn() {
            if self.state == State::SynReceived && seg_seq == self.irs {
                self.snd_nxt = self.iss; // force the SYN-ACK to be (re)sent by poll_transmit
            } else if self.seq_in_window(seg_seq) {
                self.challenge_ack(now); // in-window SYN on a synchronized conn (RFC 5961)
            }
            return;
        }

        // (3) Four-case acceptability (RFC 793 §3.9). An unacceptable segment still gets a
        // current ACK (so the peer learns RCV.NXT) — including a zero-length out-of-order one.
        if !self.segment_acceptable(seg_seq, seg_len) {
            self.needs_ack = true;
            return;
        }

        // (4) After the handshake every segment must carry ACK.
        if !flags.ack() {
            return;
        }

        // (5) ACK processing.
        if self.state == State::SynReceived {
            if seg_ack.gt(self.snd_una) && seg_ack.le(self.snd_nxt) {
                self.snd_una = seg_ack; // our SYN is acknowledged
                self.update_window(seg_seq, seg_ack, tcp.window());
                self.state = State::Established;
                self.rtx_deadline = None; // SYN-ACK acknowledged
            } else {
                // Bad ACK while half-open: owe a RST (emitted by poll_transmit, then Closed).
                self.pending_reset = Some(seg_ack);
                return;
            }
        } else {
            // A pure, non-advancing ACK with outstanding data is a duplicate ACK.
            let is_dup = payload.is_empty()
                && !flags.fin()
                && !flags.syn()
                && seg_ack == self.snd_una
                && self.snd_una != self.snd_nxt;
            if !self.process_ack(seg_seq, seg_ack, tcp.window(), now) {
                return; // SEG.ACK > SND.NXT: ACK already owed, drop the segment
            }
            if is_dup {
                let flight = self.snd_nxt.offset_from(self.snd_una);
                if self.cc.on_dup_ack(flight) {
                    // Fast retransmit (Tahoe): resend from SND.UNA; suppress RTT sampling.
                    self.snd_nxt = self.snd_una;
                    self.retransmitted = true;
                    self.rtt_sample = None;
                    self.restart_rtx(now);
                }
            }
        }

        // (6) In-order data.
        if !payload.is_empty() {
            if seg_seq == self.rcv_nxt {
                let n = self.rx.write(payload);
                self.rcv_nxt += n as u32;
            }
            // In-order or not (gap / no room), the peer is owed an ACK of our RCV.NXT.
            self.needs_ack = true;
        }

        // (7) Peer FIN. In order -> consume it; out of order or a duplicate -> still dup-ACK so
        // the peer learns our RCV.NXT and can fill the gap.
        if flags.fin() {
            if seg_seq + payload.len() as u32 == self.rcv_nxt && !self.peer_fin_seen {
                self.rcv_nxt += 1; // FIN consumes one sequence number
                self.peer_fin_seen = true;
            }
            self.needs_ack = true;
        }

        // (8) Recompute the closing state from the (fin_acked, peer_fin_seen) flags — this is
        // order-independent and handles segments that both ack our FIN and carry the peer's.
        self.recompute_closing_state(now);

        // In TIME-WAIT, any segment (e.g. a retransmitted FIN) re-arms the 2·MSL timer and is
        // re-ACKed.
        if self.state == State::TimeWait {
            self.needs_ack = true;
            self.arm_time_wait(now);
        }
    }

    /// Advance over acked data/FIN, sample RTT (Karn), manage the rtx timer and send window.
    /// Returns `false` if the ACK is for unsent data (caller drops the segment).
    fn process_ack(&mut self, seg_seq: SeqNumber, seg_ack: SeqNumber, seg_wnd: u16, now: Instant) -> bool {
        if seg_ack.gt(self.snd_nxt) {
            self.needs_ack = true; // acks data we never sent: ACK and drop (RFC 793)
            return false;
        }
        if seg_ack.gt(self.snd_una) {
            let acked = seg_ack.offset_from(self.snd_una) as usize;
            let data_acked = acked.min(self.tx.len());
            self.tx.consume(data_acked);
            self.cc.on_ack(data_acked as u32); // grow cwnd by the data bytes acknowledged
            if let Some(fin_seq) = self.fin_seq {
                if seg_ack.gt(fin_seq) {
                    self.fin_acked = true;
                }
            }
            self.snd_una = seg_ack;

            // RTT (Karn): only sample / clear backoff when the acked data was never resent.
            if !self.retransmitted {
                if let Some((sent_at, seq_end)) = self.rtt_sample {
                    if seg_ack.ge(seq_end) {
                        let ms = (now.saturating_micros_since(sent_at) / 1000).max(1) as u32;
                        self.rtt.on_sample(ms);
                        self.rtt_sample = None;
                    }
                }
                self.rtt.on_clean_ack();
            }

            if self.snd_una == self.snd_nxt {
                // Everything outstanding is acked: stop the timer, clear Karn state.
                self.rtx_deadline = None;
                self.retransmitted = false;
                self.rtt_sample = None;
            } else {
                self.restart_rtx(now); // RFC 6298 (5.3): restart for the remaining data
            }
        }
        self.update_window(seg_seq, seg_ack, seg_wnd);
        true
    }

    fn recompute_closing_state(&mut self, now: Instant) {
        let entered_time_wait;
        self.state = match self.state {
            State::FinWait1 => match (self.fin_acked, self.peer_fin_seen) {
                (true, true) => State::TimeWait,
                (true, false) => State::FinWait2,
                (false, true) => State::Closing,
                (false, false) => State::FinWait1,
            },
            State::FinWait2 => {
                if self.peer_fin_seen {
                    State::TimeWait
                } else {
                    State::FinWait2
                }
            }
            State::Closing => {
                if self.fin_acked {
                    State::TimeWait
                } else {
                    State::Closing
                }
            }
            State::LastAck => {
                if self.fin_acked {
                    State::Closed
                } else {
                    State::LastAck
                }
            }
            State::Established => {
                if self.peer_fin_seen {
                    State::CloseWait
                } else {
                    State::Established
                }
            }
            other => other,
        };
        entered_time_wait = self.state == State::TimeWait && self.time_wait_deadline.is_none();
        if entered_time_wait {
            self.arm_time_wait(now);
        }
    }

    // ── outbound ──────────────────────────────────────────────────────────────────────────

    /// Produce the next datagram to send, or `None` if nothing is pending.
    pub fn poll_transmit(&mut self, now: Instant) -> Option<Vec<u8>> {
        // An owed RST takes priority and terminates the connection.
        if let Some(seq) = self.pending_reset.take() {
            self.state = State::Closed;
            return Some(self.build_rst(seq));
        }
        match self.state {
            State::Closed | State::Listen | State::SynSent => None,
            State::SynReceived => {
                if self.snd_nxt == self.iss {
                    let seg = self.build(self.iss, TcpFlags::SYN, b"");
                    self.snd_nxt = self.iss + 1;
                    self.start_rtx(now);
                    Some(seg)
                } else if self.take_needs_ack() {
                    Some(self.build(self.snd_nxt, 0, b""))
                } else {
                    None
                }
            }
            State::TimeWait => {
                if self.take_needs_ack() {
                    Some(self.build(self.snd_nxt, 0, b""))
                } else {
                    None
                }
            }
            _ => {
                if let Some(seg) = self.transmit_data_or_fin(now) {
                    return Some(seg);
                }
                if self.take_needs_ack() {
                    return Some(self.build(self.snd_nxt, 0, b""));
                }
                None
            }
        }
    }

    fn transmit_data_or_fin(&mut self, now: Instant) -> Option<Vec<u8>> {
        let inflight = self.snd_nxt.offset_from(self.snd_una);
        let usable = self.cc.cwnd().min(self.snd_wnd as u32); // min(cwnd, advertised window)
        let sent_data = (inflight as usize).min(self.tx.len());
        let unsent_data = self.tx.len() - sent_data;

        if usable == 0 {
            // Zero window: probe with a single byte at SND.UNA (without advancing SND.NXT).
            if unsent_data > 0 && inflight == 0 {
                self.arm_persist(now);
                if self.send_probe {
                    self.send_probe = false;
                    let mut byte = [0u8; 1];
                    self.tx.peek(0, &mut byte);
                    return Some(self.build(self.snd_una, 0, &byte));
                }
            }
            return None;
        }

        let allowed = usable.saturating_sub(inflight);
        let n = (allowed as usize).min(unsent_data).min(self.snd_mss as usize);
        if n > 0 {
            let mut payload = vec![0u8; n];
            self.tx.peek(sent_data, &mut payload);
            let seq = self.snd_nxt;
            let last_buffered = sent_data + n == self.tx.len();
            let flags = if last_buffered { TcpFlags::PSH } else { 0 };
            let seg = self.build(seq, flags, &payload);
            self.snd_nxt = self.snd_nxt + n as u32;
            if self.rtt_sample.is_none() && !self.retransmitted {
                self.rtt_sample = Some((now, self.snd_nxt));
            }
            self.start_rtx(now);
            return Some(seg);
        }

        // All buffered data is in flight: send (or resend) our FIN if one is queued.
        let data_end = self.snd_una + self.tx.len() as u32;
        if self.fin_queued && !self.fin_acked && self.snd_nxt == data_end && allowed >= 1 {
            let seq = data_end;
            let seg = self.build(seq, TcpFlags::FIN, b"");
            self.fin_seq = Some(seq);
            self.snd_nxt = data_end + 1;
            self.start_rtx(now);
            self.state = match self.state {
                State::Established => State::FinWait1,
                State::CloseWait => State::LastAck,
                other => other,
            };
            return Some(seg);
        }
        None
    }

    // ── timers ────────────────────────────────────────────────────────────────────────────

    /// The earliest armed deadline (the backend sleeps until then).
    pub fn poll_at(&self) -> Option<Instant> {
        [self.rtx_deadline, self.persist_deadline, self.time_wait_deadline]
            .into_iter()
            .flatten()
            .min()
    }

    /// Fire every timer whose deadline has passed (a late wake may pass several at once).
    pub fn on_timer(&mut self, now: Instant) {
        if let Some(d) = self.rtx_deadline {
            if now >= d {
                let flight = self.snd_nxt.offset_from(self.snd_una);
                self.cc.on_rto(flight); // ssthresh = max(flight/2, 2*MSS); cwnd = 1*MSS
                self.rtt.on_timeout();
                self.snd_nxt = self.snd_una; // go-back-N
                self.retransmitted = true;
                self.rtt_sample = None;
                self.restart_rtx(now);
            }
        }
        if let Some(d) = self.persist_deadline {
            if now >= d {
                self.send_probe = true;
                self.persist_backoff = (self.persist_backoff * 2).min(PERSIST_MAX_MILLIS);
                self.persist_deadline = Some(now.plus_millis(self.persist_backoff));
            }
        }
        if let Some(d) = self.time_wait_deadline {
            if now >= d {
                self.state = State::Closed;
            }
        }
    }

    // ── helpers ───────────────────────────────────────────────────────────────────────────

    fn seq_in_window(&self, seq: SeqNumber) -> bool {
        let wnd = self.rcv_wnd as u32;
        if wnd == 0 {
            seq == self.rcv_nxt
        } else {
            seq.ge(self.rcv_nxt) && seq.lt(self.rcv_nxt + wnd)
        }
    }

    fn segment_acceptable(&self, seq: SeqNumber, seg_len: u32) -> bool {
        let wnd = self.rcv_wnd as u32;
        let right = self.rcv_nxt + wnd;
        match (seg_len == 0, wnd == 0) {
            (true, true) => seq == self.rcv_nxt,
            (true, false) => seq.ge(self.rcv_nxt) && seq.lt(right),
            (false, true) => false,
            (false, false) => {
                let last = seq + (seg_len - 1);
                (seq.ge(self.rcv_nxt) && seq.lt(right)) || (last.ge(self.rcv_nxt) && last.lt(right))
            }
        }
    }

    fn update_window(&mut self, seg_seq: SeqNumber, seg_ack: SeqNumber, seg_wnd: u16) {
        if self.snd_wl1.lt(seg_seq) || (self.snd_wl1 == seg_seq && self.snd_wl2.le(seg_ack)) {
            self.snd_wnd = seg_wnd;
            self.snd_wl1 = seg_seq;
            self.snd_wl2 = seg_ack;
            if seg_wnd > 0 {
                self.persist_deadline = None;
                self.persist_backoff = PERSIST_MIN_MILLIS;
                self.send_probe = false;
            }
        }
    }

    fn challenge_ack(&mut self, now: Instant) {
        if now.saturating_micros_since(self.challenge_window_start) >= 1_000_000 {
            self.challenge_window_start = now;
            self.challenge_count = 0;
        }
        if self.challenge_count < CHALLENGE_ACK_LIMIT {
            self.challenge_count += 1;
            self.needs_ack = true;
        }
    }

    fn take_needs_ack(&mut self) -> bool {
        core::mem::take(&mut self.needs_ack)
    }

    fn start_rtx(&mut self, now: Instant) {
        if self.rtx_deadline.is_none() {
            self.rtx_deadline = Some(now.plus_millis(self.rtt.rto_millis() as u64));
        }
    }

    fn restart_rtx(&mut self, now: Instant) {
        self.rtx_deadline = Some(now.plus_millis(self.rtt.rto_millis() as u64));
    }

    fn arm_persist(&mut self, now: Instant) {
        if self.persist_deadline.is_none() {
            self.persist_backoff = PERSIST_MIN_MILLIS;
            self.persist_deadline = Some(now.plus_millis(self.persist_backoff));
        }
    }

    fn arm_time_wait(&mut self, now: Instant) {
        self.time_wait_deadline = Some(now.plus_millis(TIME_WAIT_MILLIS));
        self.rtx_deadline = None;
        self.persist_deadline = None;
    }

    /// Build a segment carrying ACK (+ any `extra_flags`) and the current advertised window.
    /// Stamps `needs_ack = false` implicitly handled by callers via [`Tcb::take_needs_ack`].
    fn build(&mut self, seq: SeqNumber, extra_flags: u8, payload: &[u8]) -> Vec<u8> {
        let flags = TcpFlags(extra_flags | TcpFlags::ACK);
        let window = self.advertised_window();
        let mss = if flags.syn() { Some(MSS_ADVERTISE) } else { None };
        let repr = TcpRepr {
            src_port: self.local.port,
            dst_port: self.remote.port,
            seq,
            ack: self.rcv_nxt,
            flags,
            window,
            mss,
        };
        build_segment(self.local, self.remote, &repr, payload)
    }

    /// Compute the window to advertise: free receive space, clamped so the right edge never
    /// moves left (RFC 9293 — a receiver must not shrink the window).
    fn advertised_window(&mut self) -> u16 {
        let free = self.rx.free().min(0xFFFF) as u32;
        let candidate_right = self.rcv_nxt + free;
        let right = if candidate_right.lt(self.rcv_adv) {
            self.rcv_adv
        } else {
            candidate_right
        };
        self.rcv_adv = right;
        let w = right.offset_from(self.rcv_nxt).min(0xFFFF) as u16;
        self.rcv_wnd = w;
        w
    }

    /// Build a bare RST (no ACK flag) carrying `seq` — used to reject a bad half-open ACK.
    fn build_rst(&self, seq: SeqNumber) -> Vec<u8> {
        let repr = TcpRepr {
            src_port: self.local.port,
            dst_port: self.remote.port,
            seq,
            ack: SeqNumber::new(0),
            flags: TcpFlags(TcpFlags::RST),
            window: 0,
            mss: None,
        };
        build_segment(self.local, self.remote, &repr, b"")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iface::Endpoint;
    use crate::wire::{checksum, Ipv4Packet};
    use std::net::Ipv4Addr;

    const HOST: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const US: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const CPORT: u16 = 50000;
    const OUR_ISS: u32 = 0x5000;

    fn ep_us() -> Endpoint {
        Endpoint::new(US, 8080)
    }
    fn ep_host() -> Endpoint {
        Endpoint::new(HOST, CPORT)
    }

    #[derive(Debug)]
    struct Out {
        flags: TcpFlags,
        seq: SeqNumber,
        ack: SeqNumber,
        payload: Vec<u8>,
    }

    fn parse(frame: &[u8]) -> Out {
        let ip = Ipv4Packet::new_checked(frame).unwrap();
        assert!(ip.checksum_valid(), "emitted IP checksum invalid");
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        assert!(
            checksum::tcp_checksum_valid(ip.src(), ip.dst(), tcp.as_bytes()),
            "emitted TCP checksum invalid"
        );
        Out {
            flags: tcp.flags(),
            seq: tcp.seq(),
            ack: tcp.ack(),
            payload: tcp.payload().to_vec(),
        }
    }

    fn inbound(seq: SeqNumber, ack: SeqNumber, flags: u8, window: u16, mss: Option<u16>, payload: &[u8]) -> Vec<u8> {
        let repr = TcpRepr {
            src_port: CPORT,
            dst_port: 8080,
            seq,
            ack,
            flags: TcpFlags(flags),
            window,
            mss,
        };
        build_segment(ep_host(), ep_us(), &repr, payload)
    }

    fn deliver(tcb: &mut Tcb, now: Instant, frame: &[u8]) {
        let ip = Ipv4Packet::new_checked(frame).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        tcb.on_segment(now, &tcp);
    }

    fn drain(tcb: &mut Tcb, now: Instant) -> Vec<Out> {
        let mut v = Vec::new();
        while let Some(seg) = tcb.poll_transmit(now) {
            v.push(parse(&seg));
        }
        v
    }

    /// Build an Established server connection. Returns (tcb, our_iss, client_nxt).
    fn established(now: Instant, client_isn: u32, window: u16) -> (Tcb, SeqNumber, SeqNumber) {
        let syn = inbound(SeqNumber::new(client_isn), SeqNumber::new(0), TcpFlags::SYN, window, Some(1460), b"");
        let ip = Ipv4Packet::new_checked(&syn).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        let mut tcb = Tcb::new_syn_received(ep_us(), ep_host(), &tcp, SeqNumber::new(OUR_ISS), now);
        let out = drain(&mut tcb, now);
        assert_eq!(out.len(), 1);
        assert!(out[0].flags.syn() && out[0].flags.ack());
        let our_iss = out[0].seq;
        let client_nxt = SeqNumber::new(client_isn) + 1;
        deliver(&mut tcb, now, &inbound(client_nxt, our_iss + 1, TcpFlags::ACK, window, None, b""));
        assert!(drain(&mut tcb, now).is_empty());
        assert_eq!(tcb.state, State::Established);
        (tcb, our_iss, client_nxt)
    }

    #[test]
    fn send_data_and_ack_frees_tx() {
        let now = Instant::from_millis(0);
        let (mut tcb, iss, cnxt) = established(now, 1000, 64000);
        let full = tcb.tx_free();
        assert_eq!(tcb.send(b"hello world"), 11);
        let out = drain(&mut tcb, now);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].seq, iss + 1);
        assert_eq!(out[0].payload, b"hello world");
        assert!(out[0].flags.psh());
        assert!(tcb.tx_free() < full);
        deliver(&mut tcb, now, &inbound(cnxt, iss + 1 + 11, TcpFlags::ACK, 64000, None, b""));
        assert_eq!(tcb.tx_free(), full); // tx fully drained by the ACK
        assert!(drain(&mut tcb, now).is_empty());
    }

    #[test]
    fn send_respects_peer_window() {
        let now = Instant::from_millis(0);
        let (mut tcb, iss, cnxt) = established(now, 2000, 4); // tiny 4-byte window
        assert_eq!(tcb.send(b"0123456789"), 10);
        let out = drain(&mut tcb, now);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].payload, b"0123"); // window-limited
        deliver(&mut tcb, now, &inbound(cnxt, iss + 1 + 4, TcpFlags::ACK, 4, None, b""));
        let out = drain(&mut tcb, now);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].payload, b"4567");
    }

    #[test]
    fn send_segments_at_mss() {
        let now = Instant::from_millis(0);
        let (mut tcb, _iss, _cnxt) = established(now, 3000, 65535);
        let data = vec![0xab; 1500];
        assert_eq!(tcb.send(&data), 1500);
        let out = drain(&mut tcb, now);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].payload.len(), 1460); // one MSS
        assert_eq!(out[1].payload.len(), 40);
    }

    #[test]
    fn retransmits_after_rto() {
        let now = Instant::from_millis(0);
        let (mut tcb, iss, _cnxt) = established(now, 4000, 64000);
        tcb.send(b"data");
        let out = drain(&mut tcb, now);
        assert_eq!(out[0].payload, b"data");
        let deadline = tcb.poll_at().expect("rtx armed while data is outstanding");
        let later = deadline.plus_millis(1);
        tcb.on_timer(later);
        let out = drain(&mut tcb, later);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].seq, iss + 1); // resent from SND.UNA (go-back-N)
        assert_eq!(out[0].payload, b"data");
    }

    #[test]
    fn active_close_goes_through_time_wait() {
        let now = Instant::from_millis(0);
        let (mut tcb, iss, cnxt) = established(now, 5000, 64000);
        tcb.close();
        let out = drain(&mut tcb, now);
        assert_eq!(out.len(), 1);
        assert!(out[0].flags.fin());
        assert_eq!(out[0].seq, iss + 1);
        assert_eq!(tcb.state, State::FinWait1);
        deliver(&mut tcb, now, &inbound(cnxt, iss + 2, TcpFlags::ACK, 64000, None, b"")); // ack our FIN
        assert_eq!(tcb.state, State::FinWait2);
        deliver(&mut tcb, now, &inbound(cnxt, iss + 2, TcpFlags::FIN | TcpFlags::ACK, 64000, None, b"")); // peer FIN
        assert_eq!(tcb.state, State::TimeWait);
        let out = drain(&mut tcb, now);
        assert_eq!(out.len(), 1);
        assert!(out[0].flags.ack());
        let deadline = tcb.poll_at().expect("time-wait armed");
        tcb.on_timer(deadline.plus_millis(1));
        assert_eq!(tcb.state, State::Closed);
    }

    #[test]
    fn passive_close() {
        let now = Instant::from_millis(0);
        let (mut tcb, iss, cnxt) = established(now, 6000, 64000);
        deliver(&mut tcb, now, &inbound(cnxt, iss + 1, TcpFlags::FIN | TcpFlags::ACK, 64000, None, b"")); // client FIN
        assert_eq!(tcb.state, State::CloseWait);
        assert!(drain(&mut tcb, now)[0].flags.ack());
        tcb.close();
        let out = drain(&mut tcb, now);
        assert!(out[0].flags.fin());
        assert_eq!(tcb.state, State::LastAck);
        deliver(&mut tcb, now, &inbound(cnxt + 1, iss + 2, TcpFlags::ACK, 64000, None, b"")); // ack our FIN
        assert_eq!(tcb.state, State::Closed);
    }

    #[test]
    fn simultaneous_close_via_closing() {
        let now = Instant::from_millis(0);
        let (mut tcb, iss, cnxt) = established(now, 7000, 64000);
        tcb.close();
        assert!(drain(&mut tcb, now)[0].flags.fin());
        assert_eq!(tcb.state, State::FinWait1);
        deliver(&mut tcb, now, &inbound(cnxt, iss + 1, TcpFlags::FIN | TcpFlags::ACK, 64000, None, b"")); // peer FIN, our FIN not yet acked
        assert_eq!(tcb.state, State::Closing);
        drain(&mut tcb, now);
        deliver(&mut tcb, now, &inbound(cnxt + 1, iss + 2, TcpFlags::ACK, 64000, None, b"")); // now acks our FIN
        assert_eq!(tcb.state, State::TimeWait);
    }

    #[test]
    fn zero_window_persist_probe() {
        let now = Instant::from_millis(0);
        let (mut tcb, iss, cnxt) = established(now, 8000, 0); // peer advertises a zero window
        tcb.send(b"X");
        assert!(drain(&mut tcb, now).is_empty()); // can't send into a zero window
        let deadline = tcb.poll_at().expect("persist armed");
        tcb.on_timer(deadline.plus_millis(1));
        let out = drain(&mut tcb, deadline.plus_millis(1));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].payload, b"X"); // 1-byte window probe
        assert_eq!(out[0].seq, iss + 1);
        deliver(&mut tcb, now, &inbound(cnxt, iss + 1, TcpFlags::ACK, 64000, None, b"")); // window opens
        let out = drain(&mut tcb, now);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].payload, b"X");
    }

    #[test]
    fn ack_beyond_snd_nxt_is_dropped() {
        let now = Instant::from_millis(0);
        let (mut tcb, iss, cnxt) = established(now, 9000, 64000);
        // Acks data we never sent, and carries data — must ACK and drop, not accept.
        deliver(&mut tcb, now, &inbound(cnxt, iss + 9999, TcpFlags::ACK | TcpFlags::PSH, 64000, None, b"evil"));
        assert_eq!(tcb.rx_available(), 0);
        let out = drain(&mut tcb, now);
        assert_eq!(out.len(), 1);
        assert!(out[0].flags.ack());
        assert_eq!(out[0].ack, cnxt); // RCV.NXT unchanged
        assert_eq!(tcb.state, State::Established);
    }

    #[test]
    fn out_of_order_fin_triggers_dup_ack() {
        let now = Instant::from_millis(0);
        let (mut tcb, iss, cnxt) = established(now, 10000, 64000);
        deliver(&mut tcb, now, &inbound(cnxt + 100, iss + 1, TcpFlags::FIN | TcpFlags::ACK, 64000, None, b"")); // FIN with a gap
        assert_eq!(tcb.state, State::Established); // not accepted out of order
        let out = drain(&mut tcb, now);
        assert_eq!(out.len(), 1);
        assert!(out[0].flags.ack() && !out[0].flags.fin());
        assert_eq!(out[0].ack, cnxt); // dup ACK of our RCV.NXT
    }

    #[test]
    fn slow_start_caps_first_burst_at_initial_window() {
        let now = Instant::from_millis(0);
        // Large advertised window so the *congestion* window is the only limit.
        let (mut tcb, iss, _cnxt) = established(now, 12000, 64000);
        let data = vec![0u8; 30000];
        assert_eq!(tcb.send(&data), 30000);
        let out = drain(&mut tcb, now);
        // RFC 6928 IW for MSS 1460 = 14600 bytes = ten 1460-byte segments.
        let sent: usize = out.iter().map(|o| o.payload.len()).sum();
        assert_eq!(sent, 14600);
        assert_eq!(out.len(), 10);
        assert_eq!(out[0].seq, iss + 1);
    }

    #[test]
    fn three_dup_acks_fast_retransmit_and_collapse_cwnd() {
        let now = Instant::from_millis(0);
        let (mut tcb, iss, cnxt) = established(now, 13000, 64000);
        let data: Vec<u8> = (0..5000).map(|i| i as u8).collect();
        tcb.send(&data);
        let out = drain(&mut tcb, now); // initial burst (within IW)
        assert!(out.len() >= 4);

        // Three duplicate ACKs for iss+1 (no new data acknowledged).
        let dup = |t: &mut Tcb| {
            deliver(t, now, &inbound(cnxt, iss + 1, TcpFlags::ACK, 64000, None, b""));
            drain(t, now)
        };
        assert!(dup(&mut tcb).is_empty()); // 1st
        assert!(dup(&mut tcb).is_empty()); // 2nd
        let out = dup(&mut tcb); // 3rd -> fast retransmit
        assert_eq!(out.len(), 1, "fast retransmit emits one segment");
        assert_eq!(out[0].seq, iss + 1); // resent from SND.UNA
        assert_eq!(out[0].payload, &data[..1460]); // exactly one (collapsed) cwnd of 1 MSS
    }

    #[test]
    fn full_rx_window_then_rst_at_rcv_nxt_closes() {
        let now = Instant::from_millis(0);
        let (mut tcb, iss, cnxt) = established(now, 11000, 64000);
        // Fill the 64 KiB receive buffer so the advertised window collapses to zero.
        deliver(&mut tcb, now, &inbound(cnxt, iss + 1, TcpFlags::ACK, 64000, None, &vec![7u8; 60000]));
        let after = cnxt + 60000;
        deliver(&mut tcb, now, &inbound(after, iss + 1, TcpFlags::ACK, 64000, None, &vec![7u8; 5536]));
        let out = drain(&mut tcb, now);
        assert_eq!(out.last().unwrap().payload.len(), 0); // an ACK advertising window 0
        // A RST at exactly RCV.NXT must be accepted despite the zero window (review fix #1).
        let rcv_nxt = after + 5536;
        deliver(&mut tcb, now, &inbound(rcv_nxt, SeqNumber::new(0), TcpFlags::RST, 0, None, b""));
        assert_eq!(tcb.state, State::Closed);
    }
}
