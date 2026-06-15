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
//! Reliability is built over a send ring: unacked bytes stay in `tx`. Retransmission resends the
//! oldest unacked segment from `snd_una` **without** rewinding `snd_nxt` (the receiver buffers
//! out-of-order data, so the cumulative ACK jumps forward once a hole is filled; rewinding
//! `snd_nxt` would make in-flight ACKs look like they acknowledge unsent data). On RTO this is
//! go-back-N; with SACK negotiated (RFC 2018), `on_segment` buffers out-of-order data for
//! reassembly and the sender runs RFC 6675 selective repair (scoreboard + pipe + NextSeg),
//! falling back to go-back-N on a true RTO. Congestion control is Reno.

use crate::buffers::RingBuffer;
use crate::congestion::Reno;
use crate::iface::{build_segment, Endpoint};
use crate::reasm::Reasm;
use crate::rtt::RttEstimator;
use crate::sack::Scoreboard;
use crate::seq::SeqNumber;
use crate::state::State;
use crate::time::Instant;
use crate::wire::{SackBlocks, TcpFlags, TcpPacket, TcpRepr, MAX_SACK_BLOCKS};

const MSS_DEFAULT: u16 = 536; // RFC 9293 default when the peer sends no MSS option
/// Largest MSS a single IPv4 datagram can carry: 65535 (IP total-length max) − 20 (IPv4) − 20 (TCP).
const MSS_MAX: u16 = 65_495;

/// The MSS to advertise for a device MTU: `MTU − IPv4(20) − TCP(20)`, clamped to a sane range.
/// For the default 1500-byte MTU this is 1460; a jumbo/loopback-sized MTU yields a larger MSS and
/// hence far fewer packets (and `write` syscalls) for the same data.
pub fn mss_for_mtu(mtu: usize) -> u16 {
    (mtu.saturating_sub(40)).clamp(MSS_DEFAULT as usize, MSS_MAX as usize) as u16
}
// Send/receive ring sizes. Beyond the 64 KiB an unscaled window can address: with window
// scaling negotiated (RFC 7323) we advertise the full buffer, so a high-bandwidth or large-MTU
// path can keep many segments in flight instead of ~one per RTT. Non-scaling peers still see a
// window capped at 65535.
const TX_BUFFER: usize = 262_144; // 256 KiB
const RX_BUFFER: usize = 262_144; // 256 KiB

/// The smallest window-scale shift that lets `buf` be advertised in the 16-bit window field.
const fn wscale_for(buf: usize) -> u8 {
    let mut s = 0u8;
    while (buf >> s) > 0xFFFF {
        s += 1;
    }
    s
}
/// The window scale we advertise (and apply to our own advertised window) once negotiated.
const RCV_WSCALE: u8 = wscale_for(RX_BUFFER);

/// TIME-WAIT duration (2·MSL). A demo-friendly value; RFC 793 suggests up to ~4 min.
const TIME_WAIT_MILLIS: u64 = 10_000;
/// FIN-WAIT-2 bound: a peer that ACKs our FIN but never closes can't leak the connection.
const FIN_WAIT2_MILLIS: u64 = 60_000;
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
    snd_wnd: u32, // peer's advertised window, already left-shifted by snd_wscale
    snd_wl1: SeqNumber, // seq of the segment that last updated the send window
    snd_wl2: SeqNumber, // ack of that segment
    snd_mss: u16,
    /// Window scaling (RFC 7323), negotiated iff the SYN carried the WScale option. `snd_wscale`
    /// is applied to the peer's advertised windows; `rcv_wscale` (= `RCV_WSCALE` when negotiated)
    /// is what we advertise and apply to our own window. All inert when `window_scaling` is false.
    window_scaling: bool,
    snd_wscale: u8,
    rcv_wscale: u8,

    // Receive sequence space.
    irs: SeqNumber,
    rcv_nxt: SeqNumber,
    rcv_adv: SeqNumber, // the right edge we most recently advertised (never moves left)

    tx: RingBuffer, // unacked + unsent application data; tx[0] is the byte at snd_una
    rx: RingBuffer, // in-order received data awaiting the application

    rtt: RttEstimator,
    cc: Reno,
    /// (sent_at, seq_end) of the segment currently being timed for RTT, if any.
    rtt_sample: Option<(Instant, SeqNumber)>,
    /// The outstanding window has been retransmitted; suppress RTT sampling (Karn).
    retransmitted: bool,
    /// A retransmission of the oldest unacked segment is pending (set by RTO / fast retransmit).
    retransmit: bool,

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
    /// An in-window RST closed us (distinguishes an abortive reset from an orderly FIN).
    reset: bool,

    needs_ack: bool, // an ACK is owed (data received, or a dup/challenge ACK)
    send_probe: bool, // the persist timer fired; emit a 1-byte window probe
    pending_reset: Option<SeqNumber>, // a RST is owed (bad ACK while half-open); seq to stamp

    // RFC 5961 challenge-ACK rate limiter (per connection — not global; CVE-2016-5696).
    challenge_window_start: Instant,
    challenge_count: u32,

    // SACK (RFC 2018 + RFC 6675), negotiated on the handshake. When `sack_enabled` is false the
    // connection behaves exactly as before: no OOO buffering, no SACK options, legacy go-back-N.
    sack_enabled: bool,
    reasm: Reasm,           // receiver: out-of-order data buffered above rcv_nxt
    scoreboard: Scoreboard, // sender: SACK scoreboard + RFC 6675 recovery state
    /// A peer FIN whose sequence slot is above rcv_nxt (arrived out of order); consumed the
    /// instant a gap-fill makes rcv_nxt reach it.
    pending_fin: Option<SeqNumber>,
    /// The MSS we advertise (derived from the device MTU); also the cap on our segment size.
    mss_advertise: u16,
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
        mss_advertise: u16,
    ) -> Self {
        let snd_mss = syn.mss_option().unwrap_or(MSS_DEFAULT).min(mss_advertise);
        let irs = syn.seq();
        let rcv_nxt = irs + 1; // the peer's SYN consumes one sequence number
        let rcv_wnd = RX_BUFFER.min(0xFFFF) as u16;
        let sack_enabled = syn.sack_permitted(); // negotiated: echo it on the SYN-ACK
        // Window scaling (RFC 7323) is negotiated only if the SYN carried the option. Then we
        // apply the peer's scale to its windows and advertise our own; otherwise both scales are
        // 0 and windows stay capped at 65535 (byte-identical to a non-scaling peer).
        let (window_scaling, snd_wscale, rcv_wscale) = match syn.window_scale() {
            Some(peer) => (true, peer, RCV_WSCALE),
            None => (false, 0, 0),
        };
        Tcb {
            state: State::SynReceived,
            local,
            remote,
            iss,
            snd_una: iss,
            snd_nxt: iss, // the SYN-ACK has not been sent yet
            snd_wnd: syn.window() as u32, // the SYN's window itself is never scaled (RFC 7323)
            snd_wl1: irs,
            snd_wl2: iss,
            snd_mss,
            window_scaling,
            snd_wscale,
            rcv_wscale,
            irs,
            rcv_nxt,
            rcv_adv: rcv_nxt + rcv_wnd as u32,
            tx: RingBuffer::with_capacity(TX_BUFFER),
            rx: RingBuffer::with_capacity(RX_BUFFER),
            rtt: RttEstimator::new(),
            cc: Reno::new(snd_mss),
            rtt_sample: None,
            retransmitted: false,
            retransmit: false,
            rtx_deadline: None,
            persist_deadline: None,
            persist_backoff: PERSIST_MIN_MILLIS,
            time_wait_deadline: None,
            fin_queued: false,
            fin_seq: None,
            fin_acked: false,
            peer_fin_seen: false,
            reset: false,
            needs_ack: false,
            send_probe: false,
            pending_reset: None,
            challenge_window_start: now,
            challenge_count: 0,
            sack_enabled,
            reasm: Reasm::new(),
            scoreboard: Scoreboard::new(),
            pending_fin: None,
            mss_advertise,
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
    /// An abortive reset closed this connection (reads should error, not return EOF).
    pub fn is_reset(&self) -> bool {
        self.reset
    }
    /// Past the handshake (any synchronized state) — eligible to be `accept`ed.
    pub fn is_synchronized(&self) -> bool {
        matches!(
            self.state,
            State::Established
                | State::CloseWait
                | State::FinWait1
                | State::FinWait2
                | State::Closing
                | State::LastAck
        )
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
                    self.reset = true;
                } else {
                    self.challenge_ack(now);
                }
            }
            return;
        }

        // In TIME-WAIT we are done processing: just re-ACK (e.g. a retransmitted FIN, whose
        // sequence number is RCV.NXT-1 and would otherwise fail the acceptability test) and
        // extend the 2*MSL timer.
        if self.state == State::TimeWait {
            self.needs_ack = true;
            self.arm_time_wait(now);
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
            // A duplicate ACK: no data, ack == SND.UNA, and data is still outstanding. We
            // deliberately do NOT require the advertised window to be unchanged (RFC 5681
            // §2(e)): under real loss the receiver buffers out-of-order data, so its window
            // shrinks with every dup-ACK — requiring an unchanged window would suppress fast
            // retransmit exactly when it is needed and force slow RTO-based recovery.
            let is_dup = payload.is_empty()
                && !flags.fin()
                && !flags.syn()
                && seg_ack == self.snd_una
                && self.snd_una != self.snd_nxt;
            if !self.process_ack(seg_seq, seg_ack, tcp.window(), now) {
                return; // SEG.ACK > SND.NXT: ACK already owed, drop the segment
            }
            if self.sack_enabled {
                // Ingest SACK blocks AFTER process_ack advanced SND.UNA (and trimmed the
                // scoreboard), on EVERY ACK — a partial ACK that advances SND.UNA may also carry
                // fresh blocks and is not a duplicate ACK.
                let mut blocks = [(SeqNumber::new(0), SeqNumber::new(0)); MAX_SACK_BLOCKS];
                let count = tcp.sack_blocks(&mut blocks);
                self.scoreboard.update(self.snd_una, self.snd_nxt, &blocks[..count]);

                // Loss-recovery entry. Guard the whole trigger on "not already in recovery" so a
                // later 3rd dup-ACK can neither re-enter nor double-halve cwnd after an early
                // IsLost entry. The selective retransmit itself is driven by poll_transmit
                // (step 0.5); we only arm recovery + the RTO timer here.
                if !self.scoreboard.in_recovery() {
                    let flight = self.snd_nxt.offset_from(self.snd_una);
                    let three_dups = is_dup && self.cc.on_dup_ack(flight);
                    let lost = self.is_lost(self.snd_una);
                    if three_dups || lost {
                        if !three_dups {
                            // Entered via SACK IsLost before 3 dup-ACKs: force Reno's halving.
                            self.cc.enter_recovery(flight);
                        }
                        self.scoreboard.begin_recovery(self.snd_nxt); // RecoveryPoint = SND.NXT
                        self.retransmitted = true;
                        self.rtt_sample = None;
                        self.restart_rtx(now);
                    }
                }
            } else if is_dup {
                let flight = self.snd_nxt.offset_from(self.snd_una);
                if self.cc.on_dup_ack(flight) {
                    // Legacy fast retransmit: resend the oldest unacked segment; suppress RTT
                    // sampling (Karn). Do NOT rewind SND.NXT (see transmit_data_or_fin step 0).
                    self.retransmit = true;
                    self.retransmitted = true;
                    self.rtt_sample = None;
                    self.restart_rtx(now);
                }
            }
        }

        // (6) Data. In-order data goes straight to the receive ring (and may make earlier
        // out-of-order runs contiguous, which are then drained in). Out-of-order data — a gap
        // below it — is buffered for reassembly when SACK is enabled, instead of being dropped.
        if !payload.is_empty() {
            // Left-trim a segment overlapping the left window edge (seg_seq < RCV.NXT) so its
            // fresh in-order tail is delivered rather than dropped; an already-delivered prefix
            // (or a wholly-duplicate segment) trims to empty.
            let (data_seq, data): (SeqNumber, &[u8]) = if seg_seq.lt(self.rcv_nxt) {
                let off = (self.rcv_nxt.offset_from(seg_seq) as usize).min(payload.len());
                (self.rcv_nxt, &payload[off..])
            } else {
                (seg_seq, payload)
            };
            if !data.is_empty() {
                if data_seq == self.rcv_nxt {
                    let n = self.rx.write(data);
                    self.rcv_nxt += n as u32;
                    if self.sack_enabled {
                        // The in-order write may have overtaken buffered runs: purge/clip those
                        // now below RCV.NXT, then drain any run it made contiguous.
                        self.reasm.discard_below(self.rcv_nxt);
                        loop {
                            let run = self.reasm.pop_contiguous(self.rcv_nxt);
                            if run.is_empty() {
                                break;
                            }
                            let w = self.rx.write(&run);
                            self.rcv_nxt += w as u32;
                            if w < run.len() {
                                // Unreachable under the window-budget invariant, but never lose
                                // the tail: re-buffer it and stop draining.
                                self.reasm.reinsert_front(self.rcv_nxt, run[w..].to_vec());
                                break;
                            }
                        }
                    }
                } else if self.sack_enabled {
                    // data_seq > RCV.NXT: a gap remains below it — buffer for reassembly.
                    let edge = self.reasm_right_edge();
                    self.reasm.insert(self.rcv_nxt, edge, data_seq, data);
                }
            }
            // In-order or not (gap / no room), the peer is owed an ACK of our RCV.NXT.
            self.needs_ack = true;
        }

        // (7) Peer FIN. Its sequence slot is `seg_seq + payload.len()`. In order -> consume it;
        // out of order (a gap below it) -> remember the slot so it takes effect the instant
        // reassembly fills the gap.
        if flags.fin() {
            let fin_at = seg_seq + payload.len() as u32;
            if fin_at == self.rcv_nxt && !self.peer_fin_seen {
                self.rcv_nxt += 1; // FIN consumes one sequence number
                self.peer_fin_seen = true;
            } else if !self.peer_fin_seen {
                self.pending_fin = Some(fin_at);
            }
            self.needs_ack = true;
        }

        // (7b) A FIN recorded out of order (whose data gap step 6 may have just filled) is
        // consumed here, before the closing-state recompute, so CloseWait is entered this call.
        if let Some(fin_at) = self.pending_fin {
            if fin_at == self.rcv_nxt && !self.peer_fin_seen {
                self.rcv_nxt += 1;
                self.peer_fin_seen = true;
                self.pending_fin = None;
                self.needs_ack = true;
            }
        }

        // (8) Recompute the closing state from the (fin_acked, peer_fin_seen) flags — this is
        // order-independent and handles segments that both ack our FIN and carry the peer's.
        self.recompute_closing_state(now);
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
            // During SACK recovery cwnd is held at ssthresh (RFC 6675 gates transmission by the
            // pipe estimate, not by Reno's per-ACK growth); outside recovery, grow normally.
            let in_recovery = self.sack_enabled && self.scoreboard.in_recovery();
            if !in_recovery {
                self.cc.on_ack(data_acked as u32); // grow cwnd by the data bytes acknowledged
            }
            if let Some(fin_seq) = self.fin_seq {
                if seg_ack.gt(fin_seq) {
                    self.fin_acked = true;
                }
            }
            self.snd_una = seg_ack;
            if self.sack_enabled {
                self.scoreboard.trim(self.snd_una);
                if self.scoreboard.recovery_reached(self.snd_una) {
                    // Cumulative ACK reached RecoveryPoint: leave recovery; cwnd stays at the
                    // (deflated) ssthresh. Reset Reno's dup-ACK counter without growing cwnd.
                    self.scoreboard.exit_recovery();
                    self.cc.on_ack(0);
                    // Data sent fresh during recovery (above RecoveryPoint) was never
                    // retransmitted, so RTT sampling may resume. Clearing this here (not only on
                    // full drain) avoids suppressing samples for the rest of a healthy flow.
                    self.retransmitted = false;
                }
            }

            // Karn: suppress the RTT *sample* on retransmitted data (an ACK is ambiguous).
            if !self.retransmitted {
                if let Some((sent_at, seq_end)) = self.rtt_sample {
                    if seg_ack.ge(seq_end) {
                        let rtt_us =
                            now.saturating_micros_since(sent_at).min(u32::MAX as u64).max(1) as u32;
                        self.rtt.on_sample(rtt_us);
                        self.rtt_sample = None;
                    }
                }
            }
            // ...but forward progress ALWAYS clears the RTO backoff. Otherwise, while we are
            // retransmitting, a doubled RTO never comes back down and recovery ratchets toward
            // the 60 s cap — which made bulk transfers effectively wedge under loss.
            self.rtt.on_clean_ack();

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
        let prev = self.state;
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
        // Arm the relevant timer on *entry* to a state (a fresh 2*MSL on TIME-WAIT must
        // overwrite any FIN-WAIT-2 timer we set earlier).
        if self.state != prev {
            match self.state {
                State::TimeWait => self.arm_time_wait(now),
                // Bound FIN-WAIT-2 so a peer that ACKs our FIN but never closes can't leak us.
                State::FinWait2 => {
                    self.time_wait_deadline = Some(now.plus_millis(FIN_WAIT2_MILLIS))
                }
                _ => {}
            }
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
        let sent_data = (inflight as usize).min(self.tx.len());
        let unsent_data = self.tx.len() - sent_data;
        let data_end = self.snd_una + self.tx.len() as u32;

        // 0. A pending retransmission of the oldest unacked segment takes priority. Critically,
        //    we resend from SND.UNA WITHOUT rewinding SND.NXT: the receiver buffers out-of-order
        //    data, so filling the hole lets its cumulative ACK jump forward — whereas rewinding
        //    SND.NXT would make the in-flight ACKs (which acknowledge data past the rewound
        //    SND.NXT) look like they acknowledge unsent data, and they'd be dropped. This is the
        //    go-back-N path used on RTO and (without SACK) on fast retransmit.
        if self.retransmit && inflight > 0 {
            self.retransmit = false;
            let n = (inflight as usize).min(self.tx.len()).min(self.snd_mss as usize);
            if n > 0 {
                let mut payload = vec![0u8; n];
                self.tx.peek(0, &mut payload);
                let psh = n == self.tx.len();
                let flags = if psh { TcpFlags::PSH } else { 0 };
                let seg = self.build(self.snd_una, flags, &payload);
                self.start_rtx(now);
                return Some(seg);
            }
            // No data to resend (tx drained) but data is still in flight: the outstanding octet
            // is our FIN. Retransmit it at its own sequence slot — peeking tx would yield nothing
            // and emit an empty segment, leaving a lost FIN to never be resent.
            if let Some(fin_seq) = self.fin_seq {
                if !self.fin_acked && self.snd_una == fin_seq {
                    let seg = self.build(fin_seq, TcpFlags::FIN, b"");
                    self.start_rtx(now);
                    return Some(seg);
                }
            }
        }

        // 0.5. SACK selective retransmit (RFC 6675): during recovery, repair lost holes before
        //      sending new data, paced by the pipe estimate (send while cwnd > pipe). Like step
        //      0, the segment is resent from inside [SND.UNA, SND.NXT) and SND.NXT is NEVER
        //      assigned — so the no-rewind invariant holds for selective repair too.
        if self.sack_enabled && self.scoreboard.in_recovery() {
            let smss = self.snd_mss as u32;
            let pipe = self.scoreboard.pipe(self.snd_una, self.snd_nxt, smss);
            if self.cc.cwnd() > pipe {
                if let Some((seq, is_rescue)) =
                    self.scoreboard.next_seg(self.snd_una, self.snd_nxt, smss)
                {
                    let off = seq.offset_from(self.snd_una) as usize;
                    let hole = self.scoreboard.unsacked_run_len(seq, self.snd_nxt) as usize;
                    let avail = self.tx.len().saturating_sub(off);
                    let n = hole.min(self.snd_mss as usize).min(avail);
                    if n > 0 {
                        let mut payload = vec![0u8; n];
                        self.tx.peek(off, &mut payload);
                        let psh = off + n == self.tx.len();
                        let flags = if psh { TcpFlags::PSH } else { 0 };
                        let seg = self.build(seq, flags, &payload);
                        self.scoreboard.mark_rexmit(seq, seq + n as u32);
                        if is_rescue {
                            self.scoreboard.set_rescue_done();
                        }
                        self.retransmitted = true; // Karn: a retransmit makes an RTT sample ambiguous
                        self.rtt_sample = None;
                        self.start_rtx(now);
                        return Some(seg);
                    }
                }
            }
        }

        // 1. Send new data the window allows. The gate is min(cwnd − pipe, rwnd − inflight):
        //    pipe is the RFC 6675 in-flight estimate (== inflight outside SACK recovery, so this
        //    reduces to the classic min(cwnd, rwnd) − inflight there). During recovery, SACKed
        //    bytes do not count against cwnd, so new data flows once holes are repaired.
        let pipe = if self.sack_enabled {
            self.scoreboard.pipe(self.snd_una, self.snd_nxt, self.snd_mss as u32)
        } else {
            inflight
        };
        let cwnd_room = self.cc.cwnd().saturating_sub(pipe);
        let rwnd_room = self.snd_wnd.saturating_sub(inflight);
        let allowed = cwnd_room.min(rwnd_room);
        if allowed > 0 {
            let n = (allowed as usize).min(unsent_data).min(self.snd_mss as usize);
            if n > 0 {
                let mut payload = vec![0u8; n];
                self.tx.peek(sent_data, &mut payload);
                let seq = self.snd_nxt;
                let last_buffered = sent_data + n == self.tx.len();
                let flags = if last_buffered { TcpFlags::PSH } else { 0 };
                let seg = self.build(seq, flags, &payload);
                self.snd_nxt += n as u32;
                if self.rtt_sample.is_none() && !self.retransmitted {
                    self.rtt_sample = Some((now, self.snd_nxt));
                }
                self.start_rtx(now);
                return Some(seg);
            }
        } else if unsent_data > 0 && inflight == 0 {
            // ...or, with a zero window and data to send, probe one byte at SND.UNA (without
            // advancing SND.NXT — the same byte is sent normally once the window reopens).
            self.arm_persist(now);
            if self.send_probe {
                self.send_probe = false;
                let mut byte = [0u8; 1];
                self.tx.peek(0, &mut byte);
                return Some(self.build(self.snd_una, 0, &byte));
            }
        }

        // 2. Send (or retransmit) our FIN once all data is sent. A FIN carries no data, so it
        //    is sent even into a zero window — otherwise an orderly close could wedge.
        if self.fin_queued && !self.fin_acked && self.snd_nxt == data_end {
            let seg = self.build(data_end, TcpFlags::FIN, b"");
            self.fin_seq = Some(data_end);
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
                // An RTO is the stronger loss signal: abandon SACK recovery and fall back to the
                // go-back-N path (step 0). The SACKed set is kept (RFC 6675 §5.1) so a
                // non-reneging peer's cumulative ACK still jumps past data it already holds.
                if self.sack_enabled {
                    self.scoreboard.on_rto();
                }
                self.retransmit = true; // resend the oldest unacked segment (no SND.NXT rewind)
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

    // Both window predicates use `rcv_adv` — the right edge we actually advertised, which
    // never moves left — rather than `rcv_nxt + rcv_wnd`, which can drift right of the
    // advertised edge between accepting data and the next ACK.
    fn seq_in_window(&self, seq: SeqNumber) -> bool {
        if self.rcv_adv == self.rcv_nxt {
            seq == self.rcv_nxt // zero window
        } else {
            seq.ge(self.rcv_nxt) && seq.lt(self.rcv_adv)
        }
    }

    fn segment_acceptable(&self, seq: SeqNumber, seg_len: u32) -> bool {
        let zero_window = self.rcv_adv == self.rcv_nxt;
        let right = self.rcv_adv;
        match (seg_len == 0, zero_window) {
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
            // Post-handshake windows are scaled (RFC 7323); snd_wscale is 0 unless negotiated.
            self.snd_wnd = (seg_wnd as u32) << self.snd_wscale;
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
            self.rtx_deadline = Some(now.plus_micros(self.rtt.rto_micros() as u64));
        }
    }

    fn restart_rtx(&mut self, now: Instant) {
        self.rtx_deadline = Some(now.plus_micros(self.rtt.rto_micros() as u64));
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
        // Encode the advertised window into the 16-bit field. The SYN-ACK's window is never
        // scaled (RFC 7323); every later segment is right-shifted by rcv_wscale.
        let window_true = self.advertised_window();
        let window = if flags.syn() {
            window_true.min(0xFFFF) as u16
        } else {
            (window_true >> self.rcv_wscale).min(0xFFFF) as u16
        };
        let mss = if flags.syn() { Some(self.mss_advertise) } else { None };
        // Advertise our window scale on the SYN-ACK iff scaling was negotiated.
        let window_scale = if flags.syn() && self.window_scaling {
            Some(self.rcv_wscale)
        } else {
            None
        };
        // Echo SACK-Permitted on the SYN-ACK; report out-of-order runs as SACK blocks on every
        // other ACK while reassembly holds data (never on the SYN-ACK, which carries the MSS
        // option and no data).
        let sack_permitted = flags.syn() && self.sack_enabled;
        let mut sack = SackBlocks::default();
        if self.sack_enabled && !flags.syn() && !self.reasm.is_empty() {
            let mut blocks = [(SeqNumber::new(0), SeqNumber::new(0)); MAX_SACK_BLOCKS];
            let count = self.reasm.report(&mut blocks);
            for &(l, r) in &blocks[..count] {
                sack.push(l, r);
            }
        }
        let repr = TcpRepr {
            src_port: self.local.port,
            dst_port: self.remote.port,
            seq,
            ack: self.rcv_nxt,
            flags,
            window,
            mss,
            sack_permitted,
            window_scale,
            sack,
        };
        build_segment(self.local, self.remote, &repr, payload)
    }

    /// Compute the window to advertise: free receive space, clamped so the right edge never
    /// moves left (RFC 9293 — a receiver must not shrink the window). The receive pool is shared
    /// between the in-order ring and the out-of-order reassembly buffer, so free space is
    /// `RX_BUFFER − rx.len() − reasm.buffered()` (== `rx.free()` when nothing is buffered OOO,
    /// so non-SACK connections are unaffected). Advertising `rx.free()` alone would promise space
    /// the reassembly buffer has already taken.
    /// The true (unscaled) advertised window in bytes, capped to what the scaled 16-bit window
    /// field can encode so `rcv_adv` stays representable. The caller ([`Tcb::build`]) encodes it
    /// into the wire field, applying `rcv_wscale` on every segment except the SYN-ACK (whose
    /// window field is never scaled, RFC 7323).
    fn advertised_window(&mut self) -> u32 {
        let occupied = self.rx.len() + self.reasm.buffered();
        let max_window = 0xFFFFusize << self.rcv_wscale;
        let free = RX_BUFFER.saturating_sub(occupied).min(max_window) as u32;
        let candidate_right = self.rcv_nxt + free;
        let right = if candidate_right.lt(self.rcv_adv) {
            self.rcv_adv
        } else {
            candidate_right
        };
        self.rcv_adv = right;
        right.offset_from(self.rcv_nxt)
    }

    /// The effective right edge for buffering out-of-order data: the lesser of the advertised
    /// edge (`rcv_adv`, which never moves left) and the byte budget the receive pool can still
    /// hold. Both lie within one window above `rcv_nxt`, so this clip keeps total occupancy
    /// (`rx.len() + reasm.buffered()`) bounded by `RX_BUFFER` — the same budget
    /// [`Tcb::advertised_window`] hands out, so the receiver never over-advertises.
    fn reasm_right_edge(&self) -> SeqNumber {
        let budget = RX_BUFFER.saturating_sub(self.rx.len() + self.reasm.buffered());
        let budget_edge = self.rcv_nxt + budget.min(0xFFFF) as u32;
        budget_edge.min(self.rcv_adv)
    }

    /// RFC 6675 `IsLost` for the sender's current SMSS — the predicate gating recovery entry.
    fn is_lost(&self, seq: SeqNumber) -> bool {
        self.scoreboard.is_lost(seq, self.snd_mss as u32)
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
            sack_permitted: false,
            window_scale: None,
            sack: SackBlocks::default(),
        };
        build_segment(self.local, self.remote, &repr, b"")
    }

    // Test-only inspectors for private reliability state.
    #[cfg(test)]
    fn snd_nxt_dbg(&self) -> SeqNumber {
        self.snd_nxt
    }
    #[cfg(test)]
    fn in_sack_recovery_dbg(&self) -> bool {
        self.scoreboard.in_recovery()
    }
    #[cfg(test)]
    fn cwnd_dbg(&self) -> u32 {
        self.cc.cwnd()
    }
    #[cfg(test)]
    fn reasm_buffered_dbg(&self) -> usize {
        self.reasm.buffered()
    }
    #[cfg(test)]
    fn retransmitted_dbg(&self) -> bool {
        self.retransmitted
    }
    #[cfg(test)]
    fn snd_wnd_dbg(&self) -> u32 {
        self.snd_wnd
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
            sack_permitted: false,
            window_scale: None,
            sack: SackBlocks::default(),
        };
        build_segment(ep_host(), ep_us(), &repr, payload)
    }

    /// A SYN that offers the SACK-Permitted option (and MSS), to negotiate SACK on the handshake.
    fn inbound_syn_sack(seq: SeqNumber, window: u16) -> Vec<u8> {
        let repr = TcpRepr {
            src_port: CPORT,
            dst_port: 8080,
            seq,
            ack: SeqNumber::new(0),
            flags: TcpFlags(TcpFlags::SYN),
            window,
            mss: Some(1460),
            sack_permitted: true,
            window_scale: None,
            sack: SackBlocks::default(),
        };
        build_segment(ep_host(), ep_us(), &repr, b"")
    }

    /// An ACK carrying SACK blocks (kind 5), reporting `blocks` the peer holds out of order.
    fn inbound_with_sack(seq: SeqNumber, ack: SeqNumber, window: u16, blocks: &[(SeqNumber, SeqNumber)]) -> Vec<u8> {
        let mut sack = SackBlocks::default();
        for &(l, r) in blocks {
            sack.push(l, r);
        }
        let repr = TcpRepr {
            src_port: CPORT,
            dst_port: 8080,
            seq,
            ack,
            flags: TcpFlags(TcpFlags::ACK),
            window,
            mss: None,
            sack_permitted: false,
            window_scale: None,
            sack,
        };
        build_segment(ep_host(), ep_us(), &repr, b"")
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
        let mut tcb = Tcb::new_syn_received(ep_us(), ep_host(), &tcp, SeqNumber::new(OUR_ISS), now, 1460);
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
    fn three_dup_acks_trigger_fast_retransmit() {
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
        let out = dup(&mut tcb); // 3rd -> fast retransmit of the oldest unacked segment
        // We retransmit exactly the hole at SND.UNA (one segment) without rewinding SND.NXT;
        // the receiver's cumulative ACK then jumps past the data it already buffered.
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].seq, iss + 1);
        assert_eq!(out[0].payload, &data[..1460]);
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

    #[test]
    fn reset_at_rcv_nxt_sets_reset_flag() {
        let now = Instant::from_millis(0);
        let (mut tcb, iss, cnxt) = established(now, 14000, 64000);
        deliver(&mut tcb, now, &inbound(cnxt, iss + 1, TcpFlags::RST, 64000, None, b""));
        assert_eq!(tcb.state, State::Closed);
        assert!(tcb.is_reset()); // distinguishes an abortive reset from an orderly FIN
    }

    #[test]
    fn fin_is_sent_into_a_zero_window() {
        let now = Instant::from_millis(0);
        let (mut tcb, iss, _cnxt) = established(now, 15000, 0); // peer advertises window 0
        tcb.close();
        let out = drain(&mut tcb, now);
        assert_eq!(out.len(), 1, "a FIN carries no data, so it is sent despite a zero window");
        assert!(out[0].flags.fin());
        assert_eq!(out[0].seq, iss + 1);
        assert_eq!(tcb.state, State::FinWait1);
        assert!(tcb.poll_at().is_some(), "rtx armed -> the close cannot wedge");
    }

    #[test]
    fn fin_wait2_is_bounded_by_a_timer() {
        let now = Instant::from_millis(0);
        let (mut tcb, iss, cnxt) = established(now, 16000, 64000);
        tcb.close();
        drain(&mut tcb, now); // FIN -> FinWait1
        deliver(&mut tcb, now, &inbound(cnxt, iss + 2, TcpFlags::ACK, 64000, None, b"")); // ack our FIN
        assert_eq!(tcb.state, State::FinWait2);
        let deadline = tcb.poll_at().expect("FIN-WAIT-2 must be timer-bounded, not leaked");
        tcb.on_timer(deadline.plus_millis(1));
        assert_eq!(tcb.state, State::Closed);
    }

    #[test]
    fn retransmitted_fin_in_time_wait_rearms_the_timer() {
        let now = Instant::from_millis(0);
        let (mut tcb, iss, cnxt) = established(now, 17000, 64000);
        tcb.close();
        drain(&mut tcb, now);
        deliver(&mut tcb, now, &inbound(cnxt, iss + 2, TcpFlags::ACK, 64000, None, b"")); // -> FinWait2
        deliver(&mut tcb, now, &inbound(cnxt, iss + 2, TcpFlags::FIN | TcpFlags::ACK, 64000, None, b"")); // -> TimeWait
        assert_eq!(tcb.state, State::TimeWait);
        drain(&mut tcb, now);
        let first = tcb.poll_at().unwrap();
        // A retransmitted FIN arrives later; its seq is RCV.NXT-1 and would fail the strict
        // acceptability test, but TIME-WAIT must still re-ACK it and extend 2*MSL.
        let later = now.plus_millis(1000);
        deliver(&mut tcb, later, &inbound(cnxt, iss + 2, TcpFlags::FIN | TcpFlags::ACK, 64000, None, b""));
        assert_eq!(tcb.state, State::TimeWait);
        assert!(drain(&mut tcb, later).iter().any(|o| o.flags.ack()));
        assert!(tcb.poll_at().unwrap().millis() > first.millis(), "2*MSL re-armed");
    }

    #[test]
    fn dup_acks_fast_retransmit_even_when_window_changes() {
        let now = Instant::from_millis(0);
        let (mut tcb, iss, cnxt) = established(now, 18000, 64000);
        tcb.send(b"payload");
        drain(&mut tcb, now);
        // Three ACKs at SND.UNA whose advertised window shrinks each time — exactly what a
        // receiver buffering out-of-order data does under loss. They must still count as
        // duplicate ACKs and fast-retransmit on the third (not be dismissed as window updates).
        deliver(&mut tcb, now, &inbound(cnxt, iss + 1, TcpFlags::ACK, 50000, None, b""));
        assert!(drain(&mut tcb, now).is_empty());
        deliver(&mut tcb, now, &inbound(cnxt, iss + 1, TcpFlags::ACK, 40000, None, b""));
        assert!(drain(&mut tcb, now).is_empty());
        deliver(&mut tcb, now, &inbound(cnxt, iss + 1, TcpFlags::ACK, 30000, None, b""));
        let out = drain(&mut tcb, now); // 3rd dup-ACK -> fast retransmit
        assert!(!out.is_empty(), "third dup-ACK must fast-retransmit despite the changing window");
        assert_eq!(out[0].seq, iss + 1);
        assert_eq!(out[0].payload, b"payload");
    }

    // ── SACK + reassembly + RFC 6675 (M8) ─────────────────────────────────────────────────────

    fn drain_raw(tcb: &mut Tcb, now: Instant) -> Vec<Vec<u8>> {
        let mut v = Vec::new();
        while let Some(seg) = tcb.poll_transmit(now) {
            v.push(seg);
        }
        v
    }

    /// Parse `(sack_permitted, sack_blocks)` from an emitted frame.
    fn parse_sack(frame: &[u8]) -> (bool, Vec<(u32, u32)>) {
        let ip = Ipv4Packet::new_checked(frame).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        let mut blocks = [(SeqNumber::new(0), SeqNumber::new(0)); MAX_SACK_BLOCKS];
        let n = tcp.sack_blocks(&mut blocks);
        let v = blocks[..n].iter().map(|&(l, r)| (l.raw(), r.raw())).collect();
        (tcp.sack_permitted(), v)
    }

    /// Bring up an Established server connection that negotiated SACK on the handshake.
    fn established_sack(now: Instant, client_isn: u32, window: u16) -> (Tcb, SeqNumber, SeqNumber) {
        let syn = inbound_syn_sack(SeqNumber::new(client_isn), window);
        let ip = Ipv4Packet::new_checked(&syn).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        let mut tcb = Tcb::new_syn_received(ep_us(), ep_host(), &tcp, SeqNumber::new(OUR_ISS), now, 1460);
        let synack = tcb.poll_transmit(now).expect("SYN-ACK");
        assert!(parse_sack(&synack).0, "SYN-ACK must echo SACK-Permitted");
        let our_iss = parse(&synack).seq;
        assert!(tcb.poll_transmit(now).is_none());
        let client_nxt = SeqNumber::new(client_isn) + 1;
        deliver(&mut tcb, now, &inbound(client_nxt, our_iss + 1, TcpFlags::ACK, window, None, b""));
        assert!(drain(&mut tcb, now).is_empty());
        assert_eq!(tcb.state, State::Established);
        (tcb, our_iss, client_nxt)
    }

    #[test]
    fn sack_permitted_echoed_only_when_offered() {
        let now = Instant::from_millis(0);
        // A plain SYN must NOT get SACK-Permitted on the SYN-ACK.
        let syn = inbound(SeqNumber::new(1), SeqNumber::new(0), TcpFlags::SYN, 64000, Some(1460), b"");
        let ip = Ipv4Packet::new_checked(&syn).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        let mut tcb = Tcb::new_syn_received(ep_us(), ep_host(), &tcp, SeqNumber::new(OUR_ISS), now, 1460);
        let synack = tcb.poll_transmit(now).unwrap();
        assert!(!parse_sack(&synack).0);
        // A SACK-permitting SYN does (asserted inside established_sack).
        let _ = established_sack(now, 2, 64000);
    }

    #[test]
    fn ooo_data_buffered_and_sack_reported_then_delivered() {
        let now = Instant::from_millis(0);
        let (mut tcb, iss, cnxt) = established_sack(now, 200, 64000);
        // Out-of-order data [cnxt+100, cnxt+200): a 100-byte gap sits below it.
        deliver(&mut tcb, now, &inbound(cnxt + 100, iss + 1, TcpFlags::ACK | TcpFlags::PSH, 64000, None, &[7u8; 100]));
        assert_eq!(tcb.rx_available(), 0, "out-of-order data is not yet deliverable");
        let frames = drain_raw(&mut tcb, now);
        assert_eq!(frames.len(), 1);
        assert_eq!(parse(&frames[0]).ack, cnxt, "cumulative ACK still at the gap");
        assert_eq!(parse_sack(&frames[0]).1, vec![((cnxt + 100).raw(), (cnxt + 200).raw())]);
        // Fill the gap [cnxt, cnxt+100): both runs deliver in order, no SACK block remains.
        deliver(&mut tcb, now, &inbound(cnxt, iss + 1, TcpFlags::ACK | TcpFlags::PSH, 64000, None, &[5u8; 100]));
        assert_eq!(tcb.rx_available(), 200);
        let frames = drain_raw(&mut tcb, now);
        assert_eq!(frames.len(), 1);
        assert_eq!(parse(&frames[0]).ack, cnxt + 200);
        assert!(parse_sack(&frames[0]).1.is_empty(), "no SACK block once data is in order");
    }

    #[test]
    fn ooo_buffer_is_window_bounded() {
        let now = Instant::from_millis(0);
        // A non-scaled handshake (no WScale): the advertised window is capped at ~64 KiB, so OOO
        // buffering is bounded by the window, not by the larger ring.
        let (mut tcb, iss, cnxt) = established_sack(now, 400, 64000);
        deliver(&mut tcb, now, &inbound(cnxt + 100, iss + 1, TcpFlags::ACK, 64000, None, &vec![9u8; 60000]));
        assert_eq!(tcb.reasm_buffered_dbg(), 60000);
        // A run past the advertised right edge (~rcv_nxt + 65535) is clipped.
        deliver(&mut tcb, now, &inbound(cnxt + 64000, iss + 1, TcpFlags::ACK, 64000, None, &vec![8u8; 10000]));
        let buffered = tcb.reasm_buffered_dbg();
        assert!(buffered <= 65535, "OOO buffer bounded by the unscaled advertised window");
        assert!(buffered + tcb.rx_available() <= RX_BUFFER);
    }

    #[test]
    fn ooo_fin_consumed_when_gap_fills() {
        let now = Instant::from_millis(0);
        let (mut tcb, iss, cnxt) = established_sack(now, 800, 64000);
        // Out-of-order data [cnxt+50, cnxt+100) carrying a FIN (slot cnxt+100), above a gap.
        deliver(&mut tcb, now, &inbound(cnxt + 50, iss + 1, TcpFlags::ACK | TcpFlags::FIN, 64000, None, &[3u8; 50]));
        assert_eq!(tcb.state, State::Established, "OOO data + FIN not yet consumed");
        drain_raw(&mut tcb, now);
        // Fill the gap [cnxt, cnxt+50): the buffered run delivers and the FIN is consumed.
        deliver(&mut tcb, now, &inbound(cnxt, iss + 1, TcpFlags::ACK, 64000, None, &[2u8; 50]));
        assert_eq!(tcb.state, State::CloseWait);
        let mut buf = [0u8; 200];
        assert_eq!(tcb.recv(&mut buf), 100);
        assert!(tcb.recv_eof());
    }

    #[test]
    fn sack_selective_retransmit_repairs_only_the_hole_then_exits() {
        let now = Instant::from_millis(0);
        let (mut tcb, iss, cnxt) = established_sack(now, 500, 64000);
        let data: Vec<u8> = (0..5000).map(|i| i as u8).collect();
        assert_eq!(tcb.send(&data), 5000);
        let burst = drain_raw(&mut tcb, now);
        assert!(burst.len() >= 4, "5000 bytes go out within the initial window");
        let snd_nxt_before = tcb.snd_nxt_dbg();

        // The receiver holds segments 2..4 ([iss+1461, iss+5001)) but lost segment 1. The SACKed
        // block (3540 bytes) is more than 2*MSS above SND.UNA, so IsLost flags segment 1 at once.
        deliver(&mut tcb, now, &inbound_with_sack(cnxt, iss + 1, 64000, &[(iss + 1461, iss + 5001)]));
        assert!(tcb.in_sack_recovery_dbg(), "SACK IsLost enters recovery");

        let out = drain_raw(&mut tcb, now);
        assert_eq!(out.len(), 1, "exactly one segment: the repaired hole");
        assert_eq!(parse(&out[0]).seq, iss + 1, "retransmit starts at the hole (SND.UNA)");
        assert_eq!(parse(&out[0]).payload, &data[..1460], "only segment 1 is resent");
        assert_eq!(tcb.snd_nxt_dbg(), snd_nxt_before, "SND.NXT must not rewind");

        // The repaired data arrives; the peer cumulative-ACKs everything -> recovery ends.
        deliver(&mut tcb, now, &inbound(cnxt, iss + 5001, TcpFlags::ACK, 64000, None, b""));
        assert!(!tcb.in_sack_recovery_dbg(), "recovery ends at RecoveryPoint");
    }

    #[test]
    fn rto_during_sack_falls_back_to_goback_n() {
        let now = Instant::from_millis(0);
        let (mut tcb, iss, cnxt) = established_sack(now, 600, 64000);
        let data: Vec<u8> = (0..5000).map(|i| i as u8).collect();
        tcb.send(&data);
        drain_raw(&mut tcb, now);
        deliver(&mut tcb, now, &inbound_with_sack(cnxt, iss + 1, 64000, &[(iss + 1461, iss + 5001)]));
        assert!(tcb.in_sack_recovery_dbg());
        drain_raw(&mut tcb, now); // emits the selective retransmit (also lost)

        let deadline = tcb.poll_at().expect("rtx armed");
        let later = deadline.plus_millis(1);
        tcb.on_timer(later);
        assert!(!tcb.in_sack_recovery_dbg(), "an RTO abandons SACK recovery");
        assert_eq!(tcb.cwnd_dbg(), 1460, "RTO collapses cwnd to one MSS");
        let out = drain_raw(&mut tcb, later);
        assert!(!out.is_empty());
        assert_eq!(parse(&out[0]).seq, iss + 1, "go-back-N resends from SND.UNA");
    }

    #[test]
    fn non_sack_peer_still_uses_legacy_fast_retransmit() {
        let now = Instant::from_millis(0);
        let (mut tcb, iss, cnxt) = established(now, 700, 64000); // plain SYN: no SACK
        let data: Vec<u8> = (0..5000).map(|i| i as u8).collect();
        tcb.send(&data);
        drain(&mut tcb, now);
        let dup = |t: &mut Tcb| {
            deliver(t, now, &inbound(cnxt, iss + 1, TcpFlags::ACK, 64000, None, b""));
            drain(t, now)
        };
        assert!(dup(&mut tcb).is_empty());
        assert!(dup(&mut tcb).is_empty());
        let out = dup(&mut tcb); // 3rd dup-ACK -> legacy fast retransmit
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].seq, iss + 1);
        assert!(!tcb.in_sack_recovery_dbg(), "a non-SACK connection never enters SACK recovery");
    }

    // ── review regression tests (M8 adversarial findings) ─────────────────────────────────────

    #[test]
    fn lost_fin_is_retransmitted_on_rto() {
        // Finding #1: a FIN that is the only outstanding octet must be retransmitted on RTO; the
        // go-back-N path peeks tx (empty) and would otherwise emit an empty segment, never the FIN.
        let now = Instant::from_millis(0);
        let (mut tcb, _iss, cnxt) = established(now, 900, 64000);
        tcb.send(b"hello");
        assert_eq!(drain(&mut tcb, now)[0].payload, b"hello");
        tcb.close();
        let out = drain(&mut tcb, now);
        assert!(out[0].flags.fin());
        let fin_seq = out[0].seq;
        // Peer ACKs the data but not the FIN (cumulative ack == fin_seq).
        deliver(&mut tcb, now, &inbound(cnxt, fin_seq, TcpFlags::ACK, 64000, None, b""));
        assert_eq!(tcb.state, State::FinWait1);
        assert!(drain(&mut tcb, now).is_empty(), "nothing to send until the RTO");
        let deadline = tcb.poll_at().expect("rtx armed for the unacked FIN");
        let later = deadline.plus_millis(1);
        tcb.on_timer(later);
        let out = drain(&mut tcb, later);
        assert_eq!(out.len(), 1);
        assert!(out[0].flags.fin(), "the lost FIN is retransmitted, not an empty segment");
        assert_eq!(out[0].seq, fin_seq);
    }

    #[test]
    fn overlapping_in_order_write_purges_stale_ooo_run() {
        // Finding #2: an in-order segment overlapping a buffered OOO run must purge the run so it
        // doesn't leak the receive budget or emit a SACK block below the cumulative ACK.
        let now = Instant::from_millis(0);
        let (mut tcb, iss, cnxt) = established_sack(now, 250, 64000);
        deliver(&mut tcb, now, &inbound(cnxt + 1000, iss + 1, TcpFlags::ACK, 64000, None, &vec![7u8; 1000]));
        assert_eq!(tcb.reasm_buffered_dbg(), 1000);
        drain_raw(&mut tcb, now);
        // A repacketized gap-fill [cnxt, cnxt+2000) overlaps the buffered run entirely.
        deliver(&mut tcb, now, &inbound(cnxt, iss + 1, TcpFlags::ACK, 64000, None, &vec![5u8; 2000]));
        assert_eq!(tcb.rx_available(), 2000, "all in-order data delivered");
        assert_eq!(tcb.reasm_buffered_dbg(), 0, "the stale OOO run is purged (no budget leak)");
        let frames = drain_raw(&mut tcb, now);
        assert_eq!(parse(&frames[0]).ack, cnxt + 2000);
        assert!(parse_sack(&frames[0]).1.is_empty(), "no SACK block below the cumulative ACK");
    }

    #[test]
    fn left_overlapping_segment_delivers_fresh_tail() {
        // Finding #3: a segment overlapping the left window edge must deliver its fresh in-order
        // tail rather than drop it (also exercises the legacy, non-SACK path).
        let now = Instant::from_millis(0);
        let (mut tcb, iss, cnxt) = established(now, 260, 64000);
        deliver(&mut tcb, now, &inbound(cnxt, iss + 1, TcpFlags::ACK, 64000, None, &[1u8; 50]));
        assert_eq!(tcb.rx_available(), 50);
        drain(&mut tcb, now);
        // A re-segmented retransmit [cnxt, cnxt+80): first 50 bytes old, 30 fresh in order.
        deliver(&mut tcb, now, &inbound(cnxt, iss + 1, TcpFlags::ACK, 64000, None, &[2u8; 80]));
        assert_eq!(tcb.rx_available(), 80, "the fresh in-order tail is delivered, not dropped");
        assert_eq!(drain(&mut tcb, now)[0].ack, cnxt + 80, "RCV.NXT advanced past the tail");
    }

    #[test]
    fn retransmitted_clears_on_sack_recovery_exit() {
        // Finding #4: the Karn `retransmitted` guard must clear when SACK recovery exits, not only
        // on full drain, so RTT sampling resumes for data sent fresh during recovery.
        let now = Instant::from_millis(0);
        let (mut tcb, iss, cnxt) = established_sack(now, 270, 64000);
        let data: Vec<u8> = (0..5000).map(|i| i as u8).collect();
        tcb.send(&data);
        drain_raw(&mut tcb, now);
        deliver(&mut tcb, now, &inbound_with_sack(cnxt, iss + 1, 64000, &[(iss + 1461, iss + 5001)]));
        assert!(tcb.in_sack_recovery_dbg());
        drain_raw(&mut tcb, now); // retransmit the hole
        assert!(tcb.retransmitted_dbg(), "Karn guard set during recovery");
        // New data sent during recovery pushes SND.NXT past RecoveryPoint.
        tcb.send(&[9u8; 2000]);
        drain_raw(&mut tcb, now);
        // Cumulative ACK reaches RecoveryPoint while the new data is still in flight.
        deliver(&mut tcb, now, &inbound(cnxt, iss + 5001, TcpFlags::ACK, 64000, None, b""));
        assert!(!tcb.in_sack_recovery_dbg());
        assert!(!tcb.retransmitted_dbg(), "RTT sampling resumes after recovery exit");
    }

    #[test]
    fn mss_adapts_to_mtu() {
        assert_eq!(mss_for_mtu(1500), 1460); // the default
        assert_eq!(mss_for_mtu(65535), 65495); // jumbo: one IP datagram's worth
        assert_eq!(mss_for_mtu(576), 536); // small MTU floors at the RFC 9293 default
        assert_eq!(mss_for_mtu(100), 536); // below the floor clamps up
        assert_eq!(mss_for_mtu(70000), 65495); // above the IP-datagram cap clamps down
    }

    // ── window scaling (RFC 7323) ─────────────────────────────────────────────────────────────

    /// A SYN offering MSS + SACK-Permitted + Window Scale (shift `wscale`).
    fn inbound_syn_wscale(seq: SeqNumber, window: u16, wscale: u8) -> Vec<u8> {
        let repr = TcpRepr {
            src_port: CPORT,
            dst_port: 8080,
            seq,
            ack: SeqNumber::new(0),
            flags: TcpFlags(TcpFlags::SYN),
            window,
            mss: Some(1460),
            sack_permitted: true,
            window_scale: Some(wscale),
            sack: SackBlocks::default(),
        };
        build_segment(ep_host(), ep_us(), &repr, b"")
    }

    fn frame_window_scale(frame: &[u8]) -> Option<u8> {
        let ip = Ipv4Packet::new_checked(frame).unwrap();
        TcpPacket::new_checked(ip.payload()).unwrap().window_scale()
    }

    /// Bring up an Established connection that negotiated window scaling; the final ACK carries
    /// `final_wnd_field` (scaled by `wscale` => effective send window).
    fn established_wscale(now: Instant, client_isn: u32, final_wnd_field: u16, wscale: u8) -> (Tcb, SeqNumber, SeqNumber) {
        let syn = inbound_syn_wscale(SeqNumber::new(client_isn), 64000, wscale);
        let ip = Ipv4Packet::new_checked(&syn).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        let mut tcb = Tcb::new_syn_received(ep_us(), ep_host(), &tcp, SeqNumber::new(OUR_ISS), now, 1460);
        let synack = tcb.poll_transmit(now).expect("SYN-ACK");
        assert_eq!(frame_window_scale(&synack), Some(RCV_WSCALE), "SYN-ACK must advertise our scale");
        let our_iss = parse(&synack).seq;
        assert!(tcb.poll_transmit(now).is_none());
        let client_nxt = SeqNumber::new(client_isn) + 1;
        deliver(&mut tcb, now, &inbound(client_nxt, our_iss + 1, TcpFlags::ACK, final_wnd_field, None, b""));
        assert_eq!(tcb.state, State::Established);
        (tcb, our_iss, client_nxt)
    }

    #[test]
    fn syn_ack_omits_wscale_when_not_offered() {
        let now = Instant::from_millis(0);
        let syn = inbound(SeqNumber::new(5), SeqNumber::new(0), TcpFlags::SYN, 64000, Some(1460), b"");
        let ip = Ipv4Packet::new_checked(&syn).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        let mut tcb = Tcb::new_syn_received(ep_us(), ep_host(), &tcp, SeqNumber::new(OUR_ISS), now, 1460);
        let synack = tcb.poll_transmit(now).unwrap();
        assert_eq!(frame_window_scale(&synack), None);
        // A non-scaling peer's window field is taken literally.
        let cnxt = SeqNumber::new(6);
        deliver(&mut tcb, now, &inbound(cnxt, parse(&synack).seq + 1, TcpFlags::ACK, 50000, None, b""));
        assert_eq!(tcb.snd_wnd_dbg(), 50000, "no scaling: window field is literal");
    }

    #[test]
    fn negotiated_scale_is_applied_to_the_send_window() {
        let now = Instant::from_millis(0);
        // SYN offers scale 7; the final ACK's window field 1000 means 1000 << 7 = 128000 bytes.
        let (tcb, _iss, _cnxt) = established_wscale(now, 1300, 1000, 7);
        assert_eq!(tcb.snd_wnd_dbg(), 1000u32 << 7);
        assert!(tcb.snd_wnd_dbg() > 65535, "scaled send window exceeds 64 KiB");
    }

    #[test]
    fn our_advertised_window_can_exceed_64k_when_scaling() {
        let now = Instant::from_millis(0);
        let (mut tcb, iss, cnxt) = established_wscale(now, 1400, 1000, 7);
        // A post-handshake ACK we emit encodes a scaled window; reconstruct it (field << RCV_WSCALE).
        deliver(&mut tcb, now, &inbound(cnxt, iss + 1, TcpFlags::ACK | TcpFlags::PSH, 1000, None, b"hi"));
        let frames = drain_raw(&mut tcb, now);
        let ip = Ipv4Packet::new_checked(&frames[0]).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        let effective = (tcp.window() as u32) << RCV_WSCALE;
        assert!(effective > 65535, "advertised window reconstructs to > 64 KiB, got {effective}");
        assert!(effective <= RX_BUFFER as u32);
    }

    #[test]
    #[cfg_attr(miri, ignore)] // pumps ~16 MB through the rings — far too slow under Miri's
                              // interpreter; the scaling code paths are covered by lighter tests.
    fn scaled_window_allows_large_inflight() {
        let now = Instant::from_millis(0);
        // Scaling negotiated; peer window field 1000 with scale 7 => 128000 (> 64 KiB).
        let (mut tcb, our_iss, cnxt) = established_wscale(now, 1100, 1000, 7);
        assert_eq!(tcb.snd_wnd_dbg(), 1000u32 << 7);
        let mut ack = our_iss + 1;
        let mut max_burst = 0usize;
        for _ in 0..80 {
            tcb.send(&vec![0u8; 200_000]); // keep the send buffer topped up as ACKs free space
            let frames = drain_raw(&mut tcb, now);
            if frames.is_empty() {
                break;
            }
            let mut total = 0usize;
            let mut high = ack;
            for f in &frames {
                let p = parse(f);
                total += p.payload.len();
                let end = p.seq + p.payload.len() as u32;
                if end.gt(high) {
                    high = end;
                }
            }
            max_burst = max_burst.max(total);
            // Cumulatively ACK everything sent so far (cwnd grows; window stays 128000).
            ack = high;
            deliver(&mut tcb, now, &inbound(cnxt, ack, TcpFlags::ACK, 1000, None, b""));
        }
        assert!(max_burst > 65536, "scaled window lifts the >64 KiB in-flight cap; got {max_burst}");
    }
}
