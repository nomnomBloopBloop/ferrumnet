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
//! falling back to go-back-N on a true RTO. Congestion control is pluggable: the TCB holds a
//! [`Cc`] controller (Reno today; CUBIC/BBR slot in as enum variants) and drives it through the
//! [`CongestionControl`] trait, threading `now` so a time-based controller can read the clock.

use crate::buffers::RingBuffer;
use crate::congestion::{Cc, CcKind, CongestionControl};
use crate::iface::{build_segment, Endpoint};
use crate::reasm::Reasm;
use crate::rtt::RttEstimator;
use crate::sack::Scoreboard;
use crate::seq::SeqNumber;
use crate::state::State;
use crate::time::Instant;
use crate::wire::{set_ecn, SackBlocks, TcpFlags, TcpPacket, TcpRepr, ECN_ECT1, MAX_SACK_BLOCKS};

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
/// How many times the SYN of an active open (SYN-SENT) is retransmitted before the connect
/// attempt is abandoned (the connection moves to Closed and the connector observes a timeout).
const MAX_SYN_RETRIES: u16 = 7;
/// Delayed-ACK timeout (RFC 1122 §4.2.3.2 requires ≤ 500 ms). A short value keeps the tail of a
/// burst from stalling while still coalescing ACKs; the every-other-segment rule does most of the
/// work, so this only bounds the wait for a lone or trailing in-order segment.
const DELAYED_ACK_MILLIS: u64 = 40;

/// AccECN (RFC 9768 §3.2.2.2) initial value of the CE-packet counter `r.cep`, and therefore of the
/// sender's reference `accecn_ace_seen`. Both ends seed it identically so the first wrapping delta is
/// zero; the RFC picks 5 (`0b101`) so a classic-ECN middlebox that strips the AE bit is still
/// distinguishable, which is moot here (we never negotiate ECN on the handshake) but kept for
/// faithfulness. The only thing that matters for delta correctness is that both ends agree on it.
const ACE_INIT: u8 = 5;

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
    /// TCP Timestamps (RFC 7323), negotiated iff both SYNs carried the option. When enabled every
    /// segment carries `(TSval, TSecr)`: `TSval` is our microsecond clock at send time, `TSecr`
    /// echoes `ts_recent` (the peer's most recent in-order TSval). Enables RTT measurement on every
    /// ACK (free of Karn's restriction) and PAWS. All inert when `ts_enabled` is false.
    ts_enabled: bool,
    ts_recent: u32,
    /// Our TSval to stamp on outgoing segments: the microsecond clock captured at the top of each
    /// `poll_transmit` (every `build` runs inside `poll_transmit`, so it is always fresh).
    cur_tsval: u32,
    /// AccECN (RFC 9768 §3.2.2) **receiver** state: a running count of CE-marked data packets this
    /// endpoint has *accepted* (`r.cep`). [`Tcb::on_segment`] increments it once per ECN-CE data segment
    /// that actually contributes accepted data (fresh in-order bytes or newly buffered out-of-order
    /// data — never a dropped or wholly-duplicate one, which would double-count on retransmission);
    /// [`Tcb::build`] reflects `accecn_cep mod 8` in the 3-bit **ACE** field (AE·CWR·ECE) of every
    /// post-handshake ACK. Because it is a *counter*, not a one-bit latch, a delayed ACK that coalesces
    /// a CE and a non-CE segment conveys **exactly one** mark — the run-boundary imprecision of the old
    /// single-bit ECE echo is gone. The exact count is recoverable by the sender only while fewer than 8
    /// CE marks fall between two ACKs it reads (the 3-bit field's inherent wrap); the reactor emits at
    /// most one ACK per turn, so on the in-process paths exercised here the bottleneck serialises data
    /// arrivals to ~one segment per turn and the field never wraps — a real-device burst of ≥8 CE
    /// segments in a single read under sustained heavy marking would lose a multiple of 8, for which RFC
    /// 9768's byte-accurate AccECN Option (§3.2.3) is the standard fix (see `docs/DESIGN.md`). Seeded to
    /// [`ACE_INIT`]; inert (never read, never encoded) unless this is an AccECN connection
    /// ([`Tcb::ecn_enabled`]), so the wire stays byte-identical for Reno/CUBIC/BBR.
    accecn_cep: u8,
    /// AccECN (RFC 9768 §3.2.2) **sender** state: the last ACE value we decoded from the peer's ACKs.
    /// [`Tcb::process_ack`] computes the wrapping delta `(ace − accecn_ace_seen) mod 8` on each
    /// advancing ACK — the exact number of our data packets the peer newly saw CE-marked — converts it
    /// to a marked-byte estimate (`delta · SMSS`, clamped to the bytes that ACK delivered), and feeds
    /// the controller via [`crate::congestion::CongestionControl::on_ecn`]. Seeded to [`ACE_INIT`] to
    /// match the peer's initial `r.cep` so the first delta is zero. There is no SYN ECN negotiation:
    /// both ends are configured the same (see `ecn_enabled`).
    accecn_ace_seen: u8,

    // Receive sequence space.
    irs: SeqNumber,
    rcv_nxt: SeqNumber,
    rcv_adv: SeqNumber, // the right edge we most recently advertised (never moves left)

    tx: RingBuffer, // unacked + unsent application data; tx[0] is the byte at snd_una
    rx: RingBuffer, // in-order received data awaiting the application

    rtt: RttEstimator,
    cc: Cc,
    /// Which controller `cc` is, so it can be rebuilt for the same kind when the MSS is learned.
    cc_kind: CcKind,
    /// (sent_at, seq_end) of the segment currently being timed for RTT, if any.
    rtt_sample: Option<(Instant, SeqNumber)>,
    /// The outstanding window has been retransmitted; suppress RTT sampling (Karn).
    retransmitted: bool,
    /// A retransmission of the oldest unacked segment is pending (set by RTO / fast retransmit).
    retransmit: bool,
    /// Post-RTO go-back-N drain target. `Some(high)` from an RTO until the cumulative ACK reaches
    /// `high` (= `SND.NXT` captured at the RTO). While set, every cumulative-ACK advance re-arms the
    /// go-back-N retransmit (step 0), so the oldest hole is resent once per **RTT** (ACK-clocked)
    /// instead of once per **RTO**. This is what drains a Swiss-cheese window — where >`DupThresh`
    /// holes have gone SACK-invisible and `NextSeg` returns `None` — in O(holes) round trips rather
    /// than O(holes) timeouts (the sticky one-segment-per-RTO collapse). Helps every controller.
    gbn_recover: Option<SeqNumber>,

    // Timers.
    rtx_deadline: Option<Instant>,
    persist_deadline: Option<Instant>,
    persist_backoff: u64,
    time_wait_deadline: Option<Instant>,
    /// Delayed ACK (RFC 1122): a lone in-order segment defers its ACK until this deadline (or
    /// until a second segment / outgoing data piggybacks it). `unacked_segs` counts in-order
    /// segments since our last emitted ACK, to honour the "ACK every other segment" rule.
    delayed_ack_deadline: Option<Instant>,
    unacked_segs: u8,
    /// Pacing (BBR): a token bucket that gates new-data sends to the controller's pacing rate. It
    /// is entirely inert for a window-only controller — `pacing_rate()` is then `None`, so the
    /// bucket is never consulted and `pace_deadline` never armed, leaving the send path and
    /// `poll_at` byte-identical to a non-paced build.
    pace_tokens: u64,
    pace_last: Instant,
    pace_deadline: Option<Instant>,

    // FIN bookkeeping.
    fin_queued: bool, // the application asked to close
    fin_seq: Option<SeqNumber>, // sequence number assigned to our FIN once sent
    fin_acked: bool,
    peer_fin_seen: bool,
    /// An in-window RST closed us (distinguishes an abortive reset from an orderly FIN).
    reset: bool,

    needs_ack: bool, // an ACK is owed (data received, or a dup/challenge ACK)
    send_probe: bool, // the persist timer fired; emit a 1-byte window probe
    /// A RST is owed (bad ACK while half-open): the sequence number to stamp on it. Any state
    /// transition is applied where the bad ACK is *detected* (in `on_segment`), never here, so a
    /// connect/read waker sees the resulting Closed in the same reactor turn — `dispatch_wakeups`
    /// runs before `poll_transmit`, and a connection that only reached Closed during transmit
    /// would be reaped with its waker stranded.
    pending_reset: Option<SeqNumber>,
    /// Count of SYN retransmits while in SYN-SENT (active open), bounding the connect timeout.
    syn_retries: u16,

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
        // Timestamps (RFC 7323): negotiated only if the SYN carried the option; seed TS.Recent
        // with the SYN's TSval so the SYN-ACK echoes it.
        let (ts_enabled, ts_recent) = match syn.timestamps() {
            Some((tsval, _)) => (true, tsval),
            None => (false, 0),
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
            ts_enabled,
            ts_recent,
            cur_tsval: 0,
            accecn_cep: ACE_INIT,
            accecn_ace_seen: ACE_INIT,
            irs,
            rcv_nxt,
            rcv_adv: rcv_nxt + rcv_wnd as u32,
            tx: RingBuffer::with_capacity(TX_BUFFER),
            rx: RingBuffer::with_capacity(RX_BUFFER),
            rtt: RttEstimator::new(),
            cc: Cc::new(CcKind::Reno, snd_mss),
            cc_kind: CcKind::Reno,
            rtt_sample: None,
            retransmitted: false,
            retransmit: false,
            gbn_recover: None,
            rtx_deadline: None,
            persist_deadline: None,
            persist_backoff: PERSIST_MIN_MILLIS,
            time_wait_deadline: None,
            delayed_ack_deadline: None,
            unacked_segs: 0,
            pace_tokens: 0,
            pace_last: now,
            pace_deadline: None,
            fin_queued: false,
            fin_seq: None,
            fin_acked: false,
            peer_fin_seen: false,
            reset: false,
            needs_ack: false,
            send_probe: false,
            pending_reset: None,
            syn_retries: 0,
            challenge_window_start: now,
            challenge_count: 0,
            sack_enabled,
            reasm: Reasm::new(),
            scoreboard: Scoreboard::new(),
            pending_fin: None,
            mss_advertise,
        }
    }

    /// Active open: we are initiating a connection. The TCB starts in SYN-SENT; the SYN (offering
    /// MSS + SACK-Permitted + Window Scale) is emitted by the next `poll_transmit`. The receive
    /// sequence space (`irs`/`rcv_nxt`) and the peer's options stay unknown until the SYN-ACK
    /// arrives, where [`Tcb::on_segment_syn_sent`] negotiates them exactly as a passive open does.
    pub fn new_syn_sent(
        local: Endpoint,
        remote: Endpoint,
        iss: SeqNumber,
        now: Instant,
        mss_advertise: u16,
    ) -> Self {
        Tcb {
            state: State::SynSent,
            local,
            remote,
            iss,
            snd_una: iss,
            snd_nxt: iss, // the SYN has not been sent yet
            snd_wnd: 0,   // the peer's window is unknown until the SYN-ACK
            snd_wl1: iss,
            snd_wl2: iss,
            snd_mss: MSS_DEFAULT, // replaced by the peer's MSS (clamped) on the SYN-ACK
            // We *offer* SACK and window scaling on our SYN (see `build_syn`); whether they are
            // negotiated is decided when the SYN-ACK arrives. Until then both are inert.
            window_scaling: false,
            snd_wscale: 0,
            rcv_wscale: 0,
            ts_enabled: false, // negotiated on the SYN-ACK
            ts_recent: 0,
            cur_tsval: 0,
            accecn_cep: ACE_INIT,
            accecn_ace_seen: ACE_INIT,
            irs: SeqNumber::new(0), // unknown until the SYN/SYN-ACK carries IRS
            rcv_nxt: SeqNumber::new(0),
            rcv_adv: SeqNumber::new(0),
            tx: RingBuffer::with_capacity(TX_BUFFER),
            rx: RingBuffer::with_capacity(RX_BUFFER),
            rtt: RttEstimator::new(),
            cc: Cc::new(CcKind::Reno, MSS_DEFAULT),
            cc_kind: CcKind::Reno,
            rtt_sample: None,
            retransmitted: false,
            retransmit: false,
            gbn_recover: None,
            rtx_deadline: None,
            persist_deadline: None,
            persist_backoff: PERSIST_MIN_MILLIS,
            time_wait_deadline: None,
            delayed_ack_deadline: None,
            unacked_segs: 0,
            pace_tokens: 0,
            pace_last: now,
            pace_deadline: None,
            fin_queued: false,
            fin_seq: None,
            fin_acked: false,
            peer_fin_seen: false,
            reset: false,
            needs_ack: false,
            send_probe: false,
            pending_reset: None,
            syn_retries: 0,
            challenge_window_start: now,
            challenge_count: 0,
            sack_enabled: false, // negotiated on the SYN-ACK
            reasm: Reasm::new(),
            scoreboard: Scoreboard::new(),
            pending_fin: None,
            mss_advertise,
        }
    }

    /// Select the congestion controller for this connection. The [`crate::iface::Stack`] calls this
    /// right after construction — before any data flows — so rebuilding `cc` at the current MSS is
    /// lossless (the window is still its initial value). A no-op when the kind is unchanged, so the
    /// default Reno path is byte-identical to never calling it.
    pub fn set_congestion_control(&mut self, kind: CcKind) {
        if kind != self.cc_kind {
            self.cc_kind = kind;
            self.cc = Cc::new(kind, self.snd_mss);
        }
    }

    /// Whether this connection runs ECN end-to-end (DCTCP/L4S with AccECN feedback). True iff the
    /// controller reacts to ECN — **DCTCP**, the evolved **`Learned`** controller (whose genome includes
    /// an ECN response), or **TCP Prague** (the L4S scalable controller): we then mark our data ECT(1) on
    /// egress, reflect CE back through the AccECN ACE counter (RFC 9768 §3.2.2), and the controller reacts
    /// to the exact marked fraction. There is **no** SYN ECN negotiation (RFC 3168 §6.1.1 / RFC 9768 §3.1)
    /// — both ends are configured the same, a deliberate simplification that keeps the handshake untouched
    /// while still exercising the full mark/feedback/response loop. For the loss-based controllers
    /// (Reno/CUBIC/BBR) this is false, so no ECT is ever set, no ACE bits are ever encoded, and the wire
    /// stays byte-identical.
    #[inline]
    fn ecn_enabled(&self) -> bool {
        matches!(self.cc_kind, CcKind::Dctcp | CcKind::Learned | CcKind::Prague | CcKind::Synth)
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
    /// This connection's local endpoint. For a passive open it is the listening endpoint; for an
    /// active open it is the local IP with the ephemeral port chosen by [`crate::iface::Stack`].
    /// The demux uses it to route a segment to the right connection on a client's ephemeral port.
    pub fn local(&self) -> Endpoint {
        self.local
    }

    // ── inbound ───────────────────────────────────────────────────────────────────────────

    pub fn on_segment(&mut self, now: Instant, tcp: &TcpPacket<'_>, ce: bool) {
        // SYN-SENT (active open) has its own RFC 793 §3.9 processing order: the receive window is
        // not yet established (IRS is unknown), so the four-case acceptability test below does not
        // apply. Handle it separately, then return.
        if self.state == State::SynSent {
            self.on_segment_syn_sent(tcp);
            return;
        }

        let seg_seq = tcp.seq();
        let seg_ack = tcp.ack();
        let flags = tcp.flags();
        let payload = tcp.payload();
        let seg_len = payload.len() as u32 + u32::from(flags.syn()) + u32::from(flags.fin());
        let seg_ts = if self.ts_enabled { tcp.timestamps() } else { None };

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

        // (2b) PAWS (RFC 7323 §5.3): drop a segment whose timestamp predates TS.Recent — it is an
        // old duplicate (from this or a prior incarnation). A genuine retransmit is never older
        // because we re-stamp every emitted segment with the current clock, and out-of-order
        // segments are sent *after* the in-order stream that set TS.Recent, so their TSval is newer.
        // (We omit the 24-day idle invalidation; our connections are far shorter than the wrap.)
        if let Some((seg_tsval, _)) = seg_ts {
            if (seg_tsval.wrapping_sub(self.ts_recent) as i32) < 0 {
                self.needs_ack = true;
                return;
            }
        }

        // (3) Four-case acceptability (RFC 793 §3.9). An unacceptable segment still gets a
        // current ACK (so the peer learns RCV.NXT) — including a zero-length out-of-order one.
        if !self.segment_acceptable(seg_seq, seg_len) {
            self.needs_ack = true;
            return;
        }

        // RFC 7323 §4.3: advance TS.Recent from an accepted segment that reaches the left window
        // edge (PAWS above guarantees its TSval is not older). This is the value we echo in TSecr.
        if let Some((seg_tsval, _)) = seg_ts {
            if seg_seq.le(self.rcv_nxt) {
                self.ts_recent = seg_tsval;
            }
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
                self.retransmit = false; // drop any pending SYN-ACK retransmit (now acked)
            } else {
                // Bad ACK while half-open: reject the peer with a RST and tear down. Close NOW
                // (not in poll_transmit) so a connector/reader waker observes Closed in this same
                // turn; poll_transmit only emits the queued RST.
                self.pending_reset = Some(seg_ack);
                self.state = State::Closed;
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
            // Decode the peer's 3-bit AccECN ACE counter (RFC 9768 §3.2.2): AE·CWR·ECE. On a non-ECN
            // connection the peer never sets these, so this is 0 and `process_ack` ignores it.
            let ace = (u8::from(tcp.ae()) << 2) | (u8::from(flags.cwr()) << 1) | u8::from(flags.ece());
            if !self.process_ack(seg_seq, seg_ack, tcp.window(), seg_ts.map(|(_, e)| e), ace, now) {
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
                //
                // Also suppressed while a post-RTO go-back-N drain is in progress (`gbn_recover`):
                // an RTO keeps the SACKed set (RFC 6675 §5.1), so the first hole-filling cumulative
                // ACK would still see ≥`DupThresh` blocks above the new SND.UNA and re-enter recovery
                // — which (a) re-`enter_recovery`s, bouncing cwnd from the RTO's 1·MSS back up to
                // FlightSize/2 and defeating the slow-start restart, and (b) lets step 0.5 re-send the
                // very hole step 0 just resent (it was not `mark_rexmit`ed), a redundant copy. The
                // ack-clocked drain owns the repair until SND.UNA reaches the high-water; SACK
                // recovery re-engages afterwards if loss persists.
                if !self.scoreboard.in_recovery() && self.gbn_recover.is_none() {
                    let flight = self.snd_nxt.offset_from(self.snd_una);
                    let three_dups = is_dup && self.cc.on_dup_ack(now, flight);
                    let lost = self.is_lost(self.snd_una);
                    if three_dups || lost {
                        if !three_dups {
                            // Entered via SACK IsLost before 3 dup-ACKs: force the window halving.
                            self.cc.enter_recovery(now, flight);
                        }
                        self.scoreboard.begin_recovery(self.snd_nxt); // RecoveryPoint = SND.NXT
                        self.retransmitted = true;
                        self.rtt_sample = None;
                        self.restart_rtx(now);
                    }
                }
            } else if is_dup {
                let flight = self.snd_nxt.offset_from(self.snd_una);
                if self.cc.on_dup_ack(now, flight) {
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
            let rcv_nxt_before = self.rcv_nxt;
            // Left-trim a segment overlapping the left window edge (seg_seq < RCV.NXT) so its
            // fresh in-order tail is delivered rather than dropped; an already-delivered prefix
            // (or a wholly-duplicate segment) trims to empty.
            let (data_seq, data): (SeqNumber, &[u8]) = if seg_seq.lt(self.rcv_nxt) {
                let off = (self.rcv_nxt.offset_from(seg_seq) as usize).min(payload.len());
                (self.rcv_nxt, &payload[off..])
            } else {
                (seg_seq, payload)
            };
            let mut in_order = false;
            let mut no_room = false;
            let reasm_before = self.reasm.buffered();
            if !data.is_empty() {
                if data_seq == self.rcv_nxt {
                    in_order = true;
                    let n = self.rx.write(data);
                    self.rcv_nxt += n as u32;
                    no_room = n < data.len(); // part of the segment dropped for lack of rx space
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
            // AccECN receiver (RFC 9768 §3.2.2): count this segment's CE mark into the CE-packet
            // counter (which our next ACK reflects in the ACE field, see `build`) — but only if the
            // segment actually contributed *accepted* data: fresh in-order bytes (RCV.NXT advanced) or
            // newly buffered out-of-order data. Counting before the accept decision would double-count
            // a CE-marked segment that is dropped — out-of-order with SACK disabled, or no rx room —
            // and then retransmitted CE-marked: the same congestion mark would land in the counter
            // twice, inflating the sender's marked fraction. A running counter, not a one-bit latch, so
            // a mark on a segment later coalesced under a delayed ACK is still conveyed exactly once.
            // Inert unless this is an AccECN connection.
            let accepted = self.rcv_nxt != rcv_nxt_before || self.reasm.buffered() > reasm_before;
            if self.ecn_enabled() && ce && accepted {
                self.accecn_cep = self.accecn_cep.wrapping_add(1);
            }
            // ACK scheduling (RFC 1122 §4.2.3.2). Only a *clean* in-order segment may defer its ACK
            // (coalesced with the next, or piggybacked on outgoing data): in order, fully accepted,
            // and with no out-of-order data buffered before it — i.e. no reassembly/recovery in
            // progress. Everything else ACKs immediately: out-of-order data and any in-order
            // segment that filled all or part of a gap (RFC 5681 §4.2 — keep the sender's SACK
            // scoreboard current), a no-room/duplicate segment (signal the shrunk window / drive
            // the dup-ACK), and every second clean segment.
            let clean_in_order = in_order && !no_room && reasm_before == 0;
            if clean_in_order {
                self.unacked_segs = self.unacked_segs.saturating_add(1);
                if self.unacked_segs >= 2 {
                    self.needs_ack = true;
                    self.unacked_segs = 0;
                } else {
                    self.arm_delayed_ack(now);
                }
            } else {
                self.needs_ack = true;
            }
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

    /// RFC 793 §3.9 SYN-SENT segment processing (active open). Steps in the RFC's fixed order:
    /// check the ACK, then the RST, then the SYN; security/precedence (the third step) is not
    /// implemented. A segment is never emitted here (sans-IO): an owed RST is queued in
    /// `pending_reset`, an owed ACK / SYN-ACK is left to `poll_transmit` via `needs_ack` / the
    /// re-armed SYN-RECEIVED path.
    fn on_segment_syn_sent(&mut self, tcp: &TcpPacket<'_>) {
        let flags = tcp.flags();
        let seg_seq = tcp.seq();
        let seg_ack = tcp.ack();

        // (1) Check the ACK. With our SYN sent, SND.NXT == ISS+1, so the only acceptable ACK is
        // ISS < SEG.ACK <= SND.NXT (i.e. it acknowledges exactly our SYN).
        let ack_present = flags.ack();
        let ack_acceptable = ack_present && seg_ack.gt(self.iss) && seg_ack.le(self.snd_nxt);
        if ack_present && !ack_acceptable {
            // SEG.ACK <= ISS or SEG.ACK > SND.NXT: reset the sender of this bad ACK — unless it
            // carries RST, in which case just drop it. Either way we stay in SYN-SENT and keep
            // retransmitting our SYN, per RFC 793 (poll_transmit emits the RST without closing).
            if !flags.rst() {
                self.pending_reset = Some(seg_ack);
            }
            return;
        }

        // (2) Check the RST. A RST is honoured only alongside an acceptable ACK (otherwise it is a
        // blind reset and is dropped). An acceptable ACK + RST means the peer refused the open.
        if flags.rst() {
            if ack_acceptable {
                self.state = State::Closed;
                self.reset = true; // connection refused
            }
            return;
        }

        // (4) Check the SYN. (Reached only with an acceptable ACK or no ACK, and no RST.)
        if flags.syn() {
            // Our SYN drew a response, so cancel any pending SYN retransmit from an earlier RTO.
            self.retransmit = false;
            self.irs = seg_seq;
            self.rcv_nxt = seg_seq + 1; // the peer's SYN consumes one sequence number
            // RCV.NXT is now known: seed the advertised right edge (it only ever moves right).
            let rcv_wnd = RX_BUFFER.min(0xFFFF) as u32;
            self.rcv_adv = self.rcv_nxt + rcv_wnd;

            // Negotiate options from the peer's SYN/SYN-ACK exactly as a passive open does. We
            // offered all three on our SYN, so each is enabled iff the peer also offers it.
            self.snd_mss = tcp.mss_option().unwrap_or(MSS_DEFAULT).min(self.mss_advertise);
            // No data has been sent yet, so re-sizing the congestion window to the negotiated MSS
            // (giving the correct RFC 6928 initial window) loses no state. Rebuild the same kind
            // the connection was assigned (Reno by default, or whatever the backend selected).
            self.cc = Cc::new(self.cc_kind, self.snd_mss);
            self.sack_enabled = tcp.sack_permitted();
            match tcp.window_scale() {
                Some(peer) => {
                    self.window_scaling = true;
                    self.snd_wscale = peer;
                    self.rcv_wscale = RCV_WSCALE;
                }
                None => {
                    self.window_scaling = false;
                    self.snd_wscale = 0;
                    self.rcv_wscale = 0;
                }
            }
            // Timestamps: enabled iff the SYN-ACK (or simultaneous-open SYN) also carried them.
            match tcp.timestamps() {
                Some((tsval, _)) => {
                    self.ts_enabled = true;
                    self.ts_recent = tsval;
                }
                None => self.ts_enabled = false,
            }
            // The SYN/SYN-ACK window field is never scaled (RFC 7323); take it literally.
            self.snd_wnd = tcp.window() as u32;
            self.snd_wl1 = seg_seq;

            if ack_acceptable {
                // Normal three-way handshake: our SYN is acknowledged → ESTABLISHED, then ACK.
                self.snd_una = seg_ack;
                self.snd_wl2 = seg_ack;
                self.state = State::Established;
                self.rtx_deadline = None; // our SYN is acknowledged
                self.needs_ack = true; // poll_transmit emits the third-leg ACK
            } else {
                // Simultaneous open: a SYN with no ACK. Move to SYN-RECEIVED and answer with a
                // SYN-ACK. We mark `retransmit` (which the SYN-RECEIVED arm honours) rather than
                // rewinding SND.NXT to ISS: SND.NXT stays ISS+1, so any segment ingested before
                // poll_transmit runs still sees a stable acceptability window. The SYN-ACK is our
                // SYN re-emitted with ACK (IRS is now known); it consumes no new sequence. SND.UNA
                // stays at ISS. (`self.retransmit` was cleared at the top of this SYN block.)
                self.snd_wl2 = self.iss;
                self.state = State::SynReceived;
                self.retransmit = true;
            }
        }
        // (5) Neither SYN nor RST: drop the segment (nothing to do).
    }

    /// Advance over acked data/FIN, sample RTT, manage the rtx timer and send window. `seg_tsecr`
    /// is the ACK's echoed timestamp (RFC 7323), used for RTT when timestamps are negotiated.
    /// Returns `false` if the ACK is for unsent data (caller drops the segment).
    fn process_ack(&mut self, seg_seq: SeqNumber, seg_ack: SeqNumber, seg_wnd: u16, seg_tsecr: Option<u32>, ace: u8, now: Instant) -> bool {
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
                self.cc.on_ack(now, data_acked as u32); // grow cwnd by the data bytes acknowledged
            }
            if let Some(fin_seq) = self.fin_seq {
                if seg_ack.gt(fin_seq) {
                    self.fin_acked = true;
                }
            }
            self.snd_una = seg_ack;
            // Feed a rate-based controller its delivery-rate sample now that SND.UNA has advanced
            // (a no-op for Reno/CUBIC). `pipe` is the RFC 6675 in-flight estimate so a model-based
            // controller can hold its window near it during recovery (a BBRv2-style loss response);
            // `in_recovery` gates that — it keeps modelling but stops overshooting into the loss.
            let cc_inflight = self.snd_nxt.offset_from(self.snd_una);
            let cc_pipe = if self.sack_enabled {
                self.scoreboard.pipe(self.snd_una, self.snd_nxt, self.snd_mss as u32)
            } else {
                cc_inflight
            };
            self.cc.on_ack_sample(now, self.snd_una, cc_inflight, data_acked as u32, cc_pipe, in_recovery);
            // AccECN (RFC 9768 §3.2.2): the peer reflects its CE-marked-packet counter in the 3-bit
            // ACE field of every ACK. The wrapping delta since we last read it is the *exact* number of
            // our data packets it newly saw CE-marked, so `marked ≈ delta · SMSS` (clamped to the bytes
            // this ACK delivered) — a per-packet count, not the all-or-nothing-per-ACK estimate the old
            // one-bit ECE echo gave. The DCTCP/Learned controller turns the marked *fraction* over a
            // window into a proportional `cwnd ×= 1 − α/2` cut; every other controller's `on_ecn` is the
            // no-op trait default and `ecn_enabled()` is false, so this is byte-identical for them.
            //
            // The reference advances on *every* advancing ACK, even inside SACK recovery, so the delta
            // never re-counts a mark and a post-recovery ACK cannot deliver a spurious spike. The cut
            // itself is gated out of recovery, exactly like `on_ack` above: there the window is managed
            // by the loss-recovery algorithm, which (RFC 6675) requires `cwnd > pipe` to keep the
            // selective retransmit flowing — an ECN cut mid-recovery could drop `cwnd` below `pipe` and
            // stall repair. The loss response already cut the window; ECN accounting resumes on exit.
            // (A path that both drops *and* CE-marks is the only case this gate affects; with the shallow
            // queue DCTCP holds the buffer never fills, so it cannot drop.)
            if self.ecn_enabled() {
                let delta = (ace.wrapping_sub(self.accecn_ace_seen) & 0x07) as u32;
                self.accecn_ace_seen = ace & 0x07;
                if !in_recovery {
                    let marked = delta.saturating_mul(self.snd_mss as u32).min(data_acked as u32);
                    self.cc.on_ecn(now, data_acked as u32, marked);
                }
            }
            if self.sack_enabled {
                self.scoreboard.trim(self.snd_una);
                if self.scoreboard.recovery_reached(self.snd_una) {
                    // Cumulative ACK reached RecoveryPoint: leave recovery; cwnd stays at the
                    // (deflated) ssthresh. Reset the controller's dup-ACK state without growing cwnd.
                    self.scoreboard.exit_recovery();
                    self.cc.on_ack(now, 0);
                    // Data sent fresh during recovery (above RecoveryPoint) was never
                    // retransmitted, so RTT sampling may resume. Clearing this here (not only on
                    // full drain) avoids suppressing samples for the rest of a healthy flow.
                    self.retransmitted = false;
                }
            }

            // Post-RTO go-back-N drain (see `gbn_recover`). While the cumulative ACK is still below
            // the drain's high-water, this advance means the previous hole was filled, so re-arm the
            // retransmit to resend the *new* oldest hole on the next pass — repairing one hole per RTT
            // (ACK-clocked) rather than one per RTO. Cleared once SND.UNA reaches the high-water, so
            // normal sending resumes. Only meaningful with data still outstanding below the mark.
            if let Some(high) = self.gbn_recover {
                if self.snd_una.lt(high) && self.snd_una != self.snd_nxt {
                    self.retransmit = true;
                } else {
                    self.gbn_recover = None;
                }
            }

            // RTT measurement. With timestamps (RFC 7323) the ACK's TSecr echoes our TSval from
            // when the now-acked data was sent, so RTT = now − TSecr on EVERY ack — free of Karn's
            // restriction, since a retransmit carries a fresh TSval and its ACK therefore times the
            // retransmit, not the original. Without timestamps, fall back to the single
            // Karn-guarded sample per window (suppressed while any data has been retransmitted).
            if self.ts_enabled {
                if let Some(tsecr) = seg_tsecr {
                    // A real echo is a TSval we sent, so it lies in the past: `now − TSecr` is a
                    // small, non-negative elapsed time. Reading it as signed catches a peer that
                    // echoes a value "in the future" (one we never sent) — ignore that rather than
                    // let a fabricated sample pin the RTO.
                    let elapsed = (now.micros() as u32).wrapping_sub(tsecr);
                    if elapsed as i32 >= 0 {
                        self.rtt.on_sample(elapsed.max(1));
                    }
                }
            } else if !self.retransmitted {
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
            // Hand the smoothed RTT to the controller (TCP Prague reads it for its RTT-independent
            // additive increase). A no-op for every other controller. Once a measurement exists.
            if let Some(srtt) = self.rtt.srtt_micros() {
                self.cc.on_rtt_sample(srtt);
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
        // Capture the timestamp clock once for every segment this call emits (RFC 7323 TSval).
        self.cur_tsval = now.micros() as u32;
        // An owed RST takes priority. The state transition (if any) was already applied where the
        // bad ACK was detected, so this only emits the segment — never a state change.
        if let Some(seq) = self.pending_reset.take() {
            return Some(self.build_rst(seq));
        }
        match self.state {
            State::Closed | State::Listen => None,
            State::SynSent => {
                // Active open: emit our SYN, then re-emit it on each RTO. Critically, the RTO does
                // NOT rewind SND.NXT (which stays ISS+1 once the SYN is sent) — it sets `retransmit`
                // instead, so the SYN-SENT ACK-acceptability test (ISS < SEG.ACK <= SND.NXT) keeps
                // a stable SND.NXT even if a SYN-ACK is ingested in the same turn the RTO fires.
                // `build_syn` offers MSS + SACK-Permitted + Window Scale.
                if self.snd_nxt == self.iss {
                    let seg = self.build_syn();
                    self.snd_nxt = self.iss + 1; // the SYN consumes one sequence number
                    self.start_rtx(now);
                    Some(seg)
                } else if core::mem::take(&mut self.retransmit) {
                    Some(self.build_syn()) // RTO retransmit; the timer was re-armed by on_timer
                } else {
                    None
                }
            }
            State::SynReceived => {
                if self.snd_nxt == self.iss {
                    let seg = self.build(self.iss, TcpFlags::SYN, b"");
                    self.snd_nxt = self.iss + 1;
                    self.start_rtx(now);
                    Some(seg)
                } else if core::mem::take(&mut self.retransmit) {
                    // RTO with our SYN-ACK unacknowledged: retransmit it (the timer was re-armed by
                    // on_timer). Without this a lost SYN-ACK relied on the peer re-sending its SYN.
                    Some(self.build(self.iss, TcpFlags::SYN, b""))
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
        // The MSS minus our per-segment TCP options, so the datagram never exceeds the path MTU.
        let max_payload = self.max_segment_payload();

        // 0. A pending retransmission of the oldest unacked segment takes priority. Critically,
        //    we resend from SND.UNA WITHOUT rewinding SND.NXT: the receiver buffers out-of-order
        //    data, so filling the hole lets its cumulative ACK jump forward — whereas rewinding
        //    SND.NXT would make the in-flight ACKs (which acknowledge data past the rewound
        //    SND.NXT) look like they acknowledge unsent data, and they'd be dropped. This is the
        //    go-back-N path used on RTO and (without SACK) on fast retransmit.
        if self.retransmit && inflight > 0 {
            self.retransmit = false;
            let n = (inflight as usize).min(self.tx.len()).min(max_payload);
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
                    let n = hole.min(max_payload).min(avail);
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
        let mut allowed = cwnd_room.min(rwnd_room);
        // Pacing (BBR): a rate-based controller limits how many bytes may leave *now*, spacing the
        // window out at its modelled rate instead of bursting it. A window controller returns
        // `None`, so this whole block is skipped and `allowed` (and `poll_at`) are unchanged.
        if let Some(rate) = self.cc.pacing_rate() {
            self.pace_deadline = None;
            let paced = self.pace_allowance(now, rate, max_payload as u32);
            if paced < allowed && unsent_data > 0 {
                // Pacing is the binding constraint: wake again once a segment's credit has accrued.
                self.arm_pace(now, rate, paced);
            }
            allowed = allowed.min(paced);
        }
        if allowed > 0 {
            let n = (allowed as usize).min(unsent_data).min(max_payload);
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
                // Pacing bookkeeping + delivery-rate accounting (both no-ops for window controllers,
                // whose `pacing_rate()` is `None` and whose `on_transmit` is the default no-op). The
                // send is app-limited if it drained the write queue while the window had more room.
                if self.cc.pacing_rate().is_some() {
                    self.pace_tokens = self.pace_tokens.saturating_sub(n as u64);
                }
                let app_limited = n == unsent_data && cwnd_room.min(rwnd_room) > n as u32;
                self.cc.on_transmit(now, self.snd_nxt, n as u32, inflight, app_limited);
                self.start_rtx(now);
                return Some(seg);
            }
        } else if unsent_data > 0 && inflight == 0 && rwnd_room == 0 {
            // A genuine zero *peer* window (not a pacing throttle, where rwnd_room > 0): probe it.
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
        [
            self.rtx_deadline,
            self.persist_deadline,
            self.time_wait_deadline,
            self.delayed_ack_deadline,
            self.pace_deadline,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Fire every timer whose deadline has passed (a late wake may pass several at once).
    pub fn on_timer(&mut self, now: Instant) {
        if let Some(d) = self.rtx_deadline {
            if now >= d && self.state == State::SynSent {
                // Active open lost its SYN (or its SYN-ACK): re-emit the SYN, bounded by a retry
                // budget so a peer that never answers fails the connect instead of probing forever.
                self.syn_retries += 1;
                if self.syn_retries >= MAX_SYN_RETRIES {
                    self.state = State::Closed; // connect timed out (no RST → not "refused")
                    self.rtx_deadline = None;
                } else {
                    // Re-emit the SYN via poll_transmit WITHOUT rewinding SND.NXT — it stays ISS+1,
                    // so a SYN-ACK ingested in this same turn still passes the acceptability test.
                    self.retransmit = true;
                    self.rtt.on_timeout(); // back the RTO off
                    self.restart_rtx(now);
                }
            } else if now >= d {
                let flight = self.snd_nxt.offset_from(self.snd_una);
                self.cc.on_rto(now, flight); // ssthresh = max(flight/2, 2*MSS); cwnd = 1*MSS
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
                // Open an ACK-clocked go-back-N drain up to the current SND.NXT: every cumulative-ACK
                // advance below this point re-arms the resend (see `process_ack`), so a window full of
                // SACK-invisible holes drains one hole per RTT instead of one per RTO.
                self.gbn_recover = Some(self.snd_nxt);
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
        if let Some(d) = self.delayed_ack_deadline {
            if now >= d {
                // The deferred ACK timed out: owe it now (poll_transmit emits it and clears state).
                self.needs_ack = true;
                self.delayed_ack_deadline = None;
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

    fn arm_delayed_ack(&mut self, now: Instant) {
        if self.delayed_ack_deadline.is_none() {
            self.delayed_ack_deadline = Some(now.plus_millis(DELAYED_ACK_MILLIS));
        }
    }

    /// Pacing token bucket (BBR). Replenish the credit earned since the last call at `rate`
    /// bytes/sec, capped at a small burst (~1 ms of rate, floored at two segments) so an idle gap
    /// can't release a flood, and return the bytes pacing currently permits. Called once per
    /// `transmit` attempt; within a single turn `now` does not advance, so it does not
    /// double-replenish.
    fn pace_allowance(&mut self, now: Instant, rate: u64, mss: u32) -> u32 {
        let elapsed = now.saturating_micros_since(self.pace_last);
        let earned = elapsed.saturating_mul(rate) / 1_000_000;
        let cap = (rate / 1000).max(2 * mss as u64);
        self.pace_tokens = self.pace_tokens.saturating_add(earned).min(cap);
        self.pace_last = now;
        self.pace_tokens.min(u32::MAX as u64) as u32
    }

    /// Arm the pacing timer for when at least one more segment's worth of credit will have accrued
    /// (given `have` bytes already in the bucket), so the reactor wakes to send the next paced chunk.
    fn arm_pace(&mut self, now: Instant, rate: u64, have: u32) {
        let need = (self.snd_mss as u64).saturating_sub(have as u64);
        let wait_us = need.saturating_mul(1_000_000).div_ceil(rate.max(1)).max(1);
        self.pace_deadline = Some(now.plus_micros(wait_us));
    }

    fn arm_time_wait(&mut self, now: Instant) {
        self.time_wait_deadline = Some(now.plus_millis(TIME_WAIT_MILLIS));
        self.rtx_deadline = None;
        self.persist_deadline = None;
    }

    /// Build a segment carrying ACK (+ any `extra_flags`) and the current advertised window.
    /// Stamps `needs_ack = false` implicitly handled by callers via [`Tcb::take_needs_ack`].
    fn build(&mut self, seq: SeqNumber, extra_flags: u8, payload: &[u8]) -> Vec<u8> {
        // Any segment we emit carries the cumulative ACK (RCV.NXT), so it satisfies a pending
        // delayed ACK — clear it so the delayed-ACK timer does not later fire a redundant one.
        self.delayed_ack_deadline = None;
        self.unacked_segs = 0;
        // AccECN (RFC 9768 §3.2.2): an ECN-enabled receiver reflects its CE-marked-packet counter
        // `accecn_cep mod 8` in the 3-bit ACE field — AE (byte-12 bit 0) · CWR · ECE — on every
        // post-handshake ACK, so the sender recovers the exact mark count from the wrapping delta. The
        // counter is *not* cleared here (unlike the old one-bit echo): it is a running value the sender
        // differences. Never on a SYN/SYN-ACK — ECN is not negotiated on the handshake, so it stays
        // byte-identical — and entirely inert (no AE/CWR/ECE) for a non-ECN controller.
        let mut flag_bits = extra_flags | TcpFlags::ACK;
        let mut ae = false;
        if self.ecn_enabled() && (flag_bits & TcpFlags::SYN) == 0 {
            let ace = self.accecn_cep & 0x07;
            if ace & 0x01 != 0 {
                flag_bits |= TcpFlags::ECE;
            }
            if ace & 0x02 != 0 {
                flag_bits |= TcpFlags::CWR;
            }
            ae = ace & 0x04 != 0;
        }
        let flags = TcpFlags(flag_bits);
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
        // Timestamps on every segment once negotiated: our current TSval, echoing TS.Recent.
        let timestamps = if self.ts_enabled {
            Some((self.cur_tsval, self.ts_recent))
        } else {
            None
        };
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
            timestamps,
            ae,
        };
        let mut frame = build_segment(self.local, self.remote, &repr, payload);
        // DCTCP/L4S: mark our own ECN-capable *data* ECT(1) so a bottleneck can signal congestion by
        // flipping it to CE instead of dropping. Only data segments (non-empty payload) on a DCTCP
        // connection are ECT; pure ACKs, the SYN-ACK, and every non-DCTCP segment stay Not-ECT.
        // `set_ecn` rewrites the IP ECN codepoint and fixes the IP checksum only — the TCP checksum
        // is unaffected (its pseudo-header excludes the ToS/ECN byte), so the segment still validates.
        if self.ecn_enabled() && !payload.is_empty() {
            set_ecn(&mut frame, ECN_ECT1);
        }
        frame
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

    /// The largest data payload a single segment may carry. SND.MSS is the peer's advertised MSS
    /// (its MTU − 40), but our segment *also* carries TCP options — Timestamps (12 bytes) once
    /// negotiated, and SACK blocks while we hold out-of-order data — which RFC 9293 requires the
    /// sender to subtract from the MSS. Otherwise `20 (IP) + 20 (TCP) + options + payload` exceeds
    /// the MTU the MSS was derived from, and any forwarding hop or smaller-MTU path drops the
    /// oversized segment (it merely *looks* fine under same-host local delivery, which ignores the
    /// egress MTU). The option byte count here mirrors exactly what [`Tcb::build`] emits.
    fn max_segment_payload(&self) -> usize {
        let mut opt = 0;
        if self.ts_enabled {
            opt += 12; // NOP,NOP,kind8,len10 + TSval(4) + TSecr(4)
        }
        if self.sack_enabled && !self.reasm.is_empty() {
            let mut blocks = [(SeqNumber::new(0), SeqNumber::new(0)); MAX_SACK_BLOCKS];
            let mut n = self.reasm.report(&mut blocks);
            if self.ts_enabled {
                n = n.min(3); // the same cap build() applies when timestamps share the option area
            }
            if n > 0 {
                opt += 4 + 8 * n;
            }
        }
        (self.snd_mss as usize).saturating_sub(opt)
    }

    /// Build our active-open SYN: a pure SYN (no ACK — we have acknowledged nothing yet) offering
    /// MSS + SACK-Permitted + Window Scale + Timestamps. Unlike [`Tcb::build`], which always sets
    /// ACK and gates the options on what the peer offered, the active SYN advertises all of them
    /// unconditionally — it is the *offer* that the peer's SYN-ACK then accepts or declines. TSecr
    /// is 0: we have not yet seen the peer's TSval.
    fn build_syn(&self) -> Vec<u8> {
        let repr = TcpRepr {
            src_port: self.local.port,
            dst_port: self.remote.port,
            seq: self.iss,
            ack: SeqNumber::new(0),
            flags: TcpFlags(TcpFlags::SYN),
            window: RX_BUFFER.min(0xFFFF) as u16, // the SYN window is never scaled (RFC 7323)
            mss: Some(self.mss_advertise),
            sack_permitted: true,
            window_scale: Some(RCV_WSCALE),
            sack: SackBlocks::default(),
            timestamps: Some((self.cur_tsval, 0)),
            ae: false, // a SYN carries no ACE field — ECN is not negotiated on the handshake
        };
        build_segment(self.local, self.remote, &repr, b"")
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
            timestamps: None,
            ae: false,
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
    fn gbn_draining_dbg(&self) -> bool {
        self.gbn_recover.is_some()
    }
    #[cfg(test)]
    fn cwnd_dbg(&self) -> u32 {
        self.cc.cwnd()
    }
    #[cfg(test)]
    fn cc_prague_srtt_dbg(&self) -> Option<u32> {
        self.cc.prague_srtt_dbg()
    }
    #[cfg(test)]
    pub(crate) fn cc_kind_dbg(&self) -> CcKind {
        self.cc_kind
    }
    #[cfg(test)]
    fn pacing_rate_dbg(&self) -> Option<u64> {
        self.cc.pacing_rate()
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
    #[cfg(test)]
    fn sack_enabled_dbg(&self) -> bool {
        self.sack_enabled
    }
    #[cfg(test)]
    fn window_scaling_dbg(&self) -> bool {
        self.window_scaling
    }
    #[cfg(test)]
    fn ts_enabled_dbg(&self) -> bool {
        self.ts_enabled
    }
    #[cfg(test)]
    fn ts_recent_dbg(&self) -> u32 {
        self.ts_recent
    }
    #[cfg(test)]
    fn rto_dbg(&self) -> u32 {
        self.rtt.rto_micros()
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
        /// The decoded 3-bit AccECN ACE counter on this emitted segment (AE·CWR·ECE), 0..=7.
        ace: u8,
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
            ace: (u8::from(tcp.ae()) << 2) | (u8::from(tcp.flags().cwr()) << 1) | u8::from(tcp.flags().ece()),
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
            timestamps: None,
            ae: false,
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
            timestamps: None,
            ae: false,
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
            timestamps: None,
            ae: false,
        };
        build_segment(ep_host(), ep_us(), &repr, b"")
    }

    fn deliver(tcb: &mut Tcb, now: Instant, frame: &[u8]) {
        let ip = Ipv4Packet::new_checked(frame).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        let ce = ip.ecn() == crate::wire::ECN_CE;
        tcb.on_segment(now, &tcp, ce);
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
    fn rto_goback_n_drain_is_ack_clocked_not_rto_clocked() {
        // The sticky-wedge fix. After an RTO falls back to go-back-N, each cumulative-ACK advance must
        // re-arm the retransmit so the NEXT hole is repaired this round trip — not only when the RTO
        // timer fires again. Without it, a window with >DupThresh SACK-invisible holes drains one
        // segment per RTO (the collapse to ~0.2 MB/s); with it, it drains one hole per RTT.
        let now = Instant::from_millis(0);
        let (mut tcb, iss, cnxt) = established_sack(now, 600, 64000);
        let data: Vec<u8> = (0..6000).map(|i| i as u8).collect();
        tcb.send(&data);
        drain_raw(&mut tcb, now); // segments [iss+1 .. iss+6001) go out
        // Peer holds segments 2..4 ([iss+1461, iss+5841)) but lost segment 1 and segment 5 — two
        // holes. IsLost flags segment 1 (3*MSS+ SACKed above it) → SACK recovery.
        deliver(&mut tcb, now, &inbound_with_sack(cnxt, iss + 1, 64000, &[(iss + 1461, iss + 5841)]));
        assert!(tcb.in_sack_recovery_dbg(), "SACK IsLost enters recovery");
        drain_raw(&mut tcb, now); // selective retransmit of segment 1 — assume it is lost too

        // RTO: abandon SACK recovery, open the go-back-N drain, resend segment 1 from SND.UNA.
        let later = tcb.poll_at().expect("rtx armed").plus_millis(1);
        tcb.on_timer(later);
        assert!(tcb.gbn_draining_dbg(), "the RTO opened a go-back-N drain");
        let out = drain_raw(&mut tcb, later);
        assert_eq!(parse(&out[0]).seq, iss + 1, "drain resends the oldest hole (SND.UNA)");
        assert!(drain_raw(&mut tcb, later).is_empty(), "only one resend until an ACK or a new RTO");

        // Segment 1 lands; the cumulative ACK jumps past the SACKed block 2..4 to the next hole at
        // iss+5841. This advance alone — NO new RTO, the clock has not moved — must re-arm the drain.
        deliver(&mut tcb, later, &inbound(cnxt, iss + 5841, TcpFlags::ACK, 64000, None, b""));
        let out = drain_raw(&mut tcb, later);
        assert_eq!(out.len(), 1, "the cumulative-ACK advance re-armed the drain with no RTO");
        assert_eq!(parse(&out[0]).seq, iss + 5841, "and it resends the NEW oldest hole, ack-clocked");

        // The last hole lands; SND.UNA reaches the drain high-water → the drain closes.
        deliver(&mut tcb, later, &inbound(cnxt, iss + 6001, TcpFlags::ACK, 64000, None, b""));
        assert!(!tcb.gbn_draining_dbg(), "drain closes once SND.UNA reaches the RTO high-water");
    }

    #[test]
    fn rto_drain_does_not_re_enter_sack_recovery_or_double_send() {
        // Regression for the recovery review. After an RTO opens the go-back-N drain, a hole-filling
        // cumulative ACK that STILL carries SACK blocks above the new SND.UNA must NOT re-enter SACK
        // recovery (the RTO retained the SACKed set, so IsLost would still fire). If it did: (a)
        // enter_recovery bounces cwnd off the RTO's 1·MSS back toward FlightSize/2 (defeating the
        // slow-start restart), and (b) step 0.5 resends the very hole step 0 just resent (a redundant
        // duplicate). The ack-clocked drain owns the post-RTO repair until SND.UNA reaches its mark.
        let now = Instant::from_millis(0);
        let (mut tcb, iss, cnxt) = established_sack(now, 700, 64000);
        let data: Vec<u8> = (0..13140).map(|i| i as u8).collect(); // 9 segments, [iss+1 .. iss+13141)
        tcb.send(&data);
        drain_raw(&mut tcb, now);
        // Two holes — seg 1 ([iss+1, iss+1461)) and seg 6 ([iss+7301, iss+8761)) — with SACK for segs
        // 2..5 and segs 7..9. IsLost flags seg 1 (far more than 2·MSS SACKed above it) → recovery.
        deliver(&mut tcb, now, &inbound_with_sack(cnxt, iss + 1, 64000,
            &[(iss + 1461, iss + 7301), (iss + 8761, iss + 13141)]));
        assert!(tcb.in_sack_recovery_dbg(), "IsLost enters SACK recovery");
        drain_raw(&mut tcb, now); // selective retransmits of the holes — assume lost

        // RTO: leave SACK recovery, open the go-back-N drain, resend seg 1.
        let later = tcb.poll_at().expect("rtx armed").plus_millis(1);
        tcb.on_timer(later);
        assert!(tcb.gbn_draining_dbg() && !tcb.in_sack_recovery_dbg());
        assert_eq!(parse(&drain_raw(&mut tcb, later)[0]).seq, iss + 1, "drain resends seg 1");

        // Seg 1 lands; the cumulative ACK jumps to iss+7301 (segs 1..5) but STILL SACKs segs 7..9,
        // which sit above the new SND.UNA (the seg-6 hole) and would re-trigger IsLost. The gate must
        // keep us OUT of SACK recovery so step 0.5 doesn't duplicate the go-back-N resend.
        deliver(&mut tcb, later, &inbound_with_sack(cnxt, iss + 7301, 64000, &[(iss + 8761, iss + 13141)]));
        assert!(!tcb.in_sack_recovery_dbg(), "the active drain suppresses SACK-recovery re-entry");
        let out = drain_raw(&mut tcb, later);
        assert_eq!(out.len(), 1, "the new oldest hole is resent ONCE (no step-0 + step-0.5 double-send)");
        assert_eq!(parse(&out[0]).seq, iss + 7301, "and it is seg 6, the new SND.UNA");
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
            timestamps: None,
            ae: false,
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
        // The lone in-order segment defers its ACK; fire the delayed-ACK timer to emit it.
        let later = now.plus_millis(50);
        tcb.on_timer(later);
        let frames = drain_raw(&mut tcb, later);
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

    // ── active open / SYN-SENT (RFC 793 §3.9) ─────────────────────────────────────────────────

    const SPORT: u16 = 80; // the server we dial in the active-open tests
    const CLIENT_PORT: u16 = 50000; // our ephemeral local port

    fn client_local() -> Endpoint {
        Endpoint::new(US, CLIENT_PORT)
    }
    fn server_remote() -> Endpoint {
        Endpoint::new(HOST, SPORT)
    }

    /// A segment from the dialled server (HOST:SPORT) to our client (US:CLIENT_PORT).
    #[allow(clippy::too_many_arguments)]
    fn peer_seg(seq: SeqNumber, ack: SeqNumber, flags: u8, window: u16, mss: Option<u16>, sack_permitted: bool, wscale: Option<u8>, payload: &[u8]) -> Vec<u8> {
        let repr = TcpRepr {
            src_port: SPORT,
            dst_port: CLIENT_PORT,
            seq,
            ack,
            flags: TcpFlags(flags),
            window,
            mss,
            sack_permitted,
            window_scale: wscale,
            sack: SackBlocks::default(),
            timestamps: None,
            ae: false,
        };
        build_segment(server_remote(), client_local(), &repr, payload)
    }

    fn new_client(now: Instant) -> Tcb {
        Tcb::new_syn_sent(client_local(), server_remote(), SeqNumber::new(OUR_ISS), now, 1460)
    }

    #[test]
    fn active_open_emits_pure_syn_with_options() {
        let now = Instant::from_millis(0);
        let mut tcb = new_client(now);
        assert_eq!(tcb.state, State::SynSent);
        let out = drain_raw(&mut tcb, now);
        assert_eq!(out.len(), 1, "exactly one SYN");
        let ip = Ipv4Packet::new_checked(&out[0]).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        assert!(tcp.flags().syn() && !tcp.flags().ack(), "a pure SYN, no ACK");
        assert_eq!(tcp.seq(), SeqNumber::new(OUR_ISS));
        assert_eq!(tcp.mss_option(), Some(1460), "offers MSS");
        assert!(tcp.sack_permitted(), "offers SACK-Permitted");
        assert_eq!(tcp.window_scale(), Some(RCV_WSCALE), "offers window scaling");
        // The SYN is sent once; nothing more until the SYN-ACK.
        assert!(drain_raw(&mut tcb, now).is_empty());
    }

    #[test]
    fn active_open_completes_on_syn_ack_and_negotiates_options() {
        let now = Instant::from_millis(0);
        let mut tcb = new_client(now);
        drain_raw(&mut tcb, now); // our SYN
        let our_iss = SeqNumber::new(OUR_ISS);
        let peer_isn = SeqNumber::new(7000);
        // SYN-ACK acks our SYN and offers SACK + window scale 7.
        deliver(&mut tcb, now, &peer_seg(peer_isn, our_iss + 1, TcpFlags::SYN | TcpFlags::ACK, 64000, Some(1460), true, Some(7), b""));
        assert_eq!(tcb.state, State::Established);
        // The third-leg ACK is emitted.
        let out = drain(&mut tcb, now);
        assert_eq!(out.len(), 1);
        assert!(out[0].flags.ack() && !out[0].flags.syn());
        assert_eq!(out[0].seq, our_iss + 1);
        assert_eq!(out[0].ack, peer_isn + 1, "ACKs the peer's SYN");
        // Negotiated state.
        assert!(tcb.sack_enabled_dbg(), "SACK negotiated");
        assert!(tcb.window_scaling_dbg(), "window scaling negotiated");
        assert_eq!(tcb.snd_wnd_dbg(), 64000, "the SYN-ACK window field is taken literally (not scaled)");
        // A subsequent in-order ACK's window IS scaled by the negotiated shift (7).
        deliver(&mut tcb, now, &peer_seg(peer_isn + 1, our_iss + 1, TcpFlags::ACK, 1000, None, false, None, b""));
        assert_eq!(tcb.snd_wnd_dbg(), 1000u32 << 7, "post-handshake window is scaled");
    }

    #[test]
    fn active_open_without_peer_options_is_plain() {
        let now = Instant::from_millis(0);
        let mut tcb = new_client(now);
        drain_raw(&mut tcb, now);
        let our_iss = SeqNumber::new(OUR_ISS);
        let peer_isn = SeqNumber::new(8000);
        // A SYN-ACK that offers neither SACK nor window scaling.
        deliver(&mut tcb, now, &peer_seg(peer_isn, our_iss + 1, TcpFlags::SYN | TcpFlags::ACK, 50000, Some(1460), false, None, b""));
        assert_eq!(tcb.state, State::Established);
        assert!(!tcb.sack_enabled_dbg(), "no SACK when the peer does not offer it");
        assert!(!tcb.window_scaling_dbg(), "no scaling when the peer does not offer it");
        assert_eq!(tcb.snd_wnd_dbg(), 50000, "window taken literally");
    }

    #[test]
    fn simultaneous_open_enters_syn_received_then_established() {
        let now = Instant::from_millis(0);
        let mut tcb = new_client(now);
        drain_raw(&mut tcb, now); // our SYN
        let our_iss = SeqNumber::new(OUR_ISS);
        let peer_isn = SeqNumber::new(9000);
        // A SYN with NO ACK crossed ours on the wire: simultaneous open.
        deliver(&mut tcb, now, &peer_seg(peer_isn, SeqNumber::new(0), TcpFlags::SYN, 64000, Some(1460), true, Some(7), b""));
        assert_eq!(tcb.state, State::SynReceived);
        let out = drain(&mut tcb, now);
        assert_eq!(out.len(), 1);
        assert!(out[0].flags.syn() && out[0].flags.ack(), "answers with a SYN-ACK");
        assert_eq!(out[0].seq, our_iss, "re-emitted at our ISS");
        assert_eq!(out[0].ack, peer_isn + 1);
        // The peer now ACKs our SYN -> ESTABLISHED.
        deliver(&mut tcb, now, &peer_seg(peer_isn + 1, our_iss + 1, TcpFlags::ACK, 64000, None, false, None, b""));
        assert_eq!(tcb.state, State::Established);
    }

    #[test]
    fn active_open_unacceptable_ack_resets_sender_and_stays_syn_sent() {
        let now = Instant::from_millis(0);
        let mut tcb = new_client(now);
        drain_raw(&mut tcb, now);
        let our_iss = SeqNumber::new(OUR_ISS);
        // An ACK for data we never sent (SEG.ACK > SND.NXT): RFC 793 says reset that sender.
        deliver(&mut tcb, now, &peer_seg(SeqNumber::new(123), our_iss + 5, TcpFlags::ACK, 64000, None, false, None, b""));
        assert_eq!(tcb.state, State::SynSent, "we stay in SYN-SENT and keep retrying our SYN");
        let out = drain(&mut tcb, now);
        assert_eq!(out.len(), 1);
        assert!(out[0].flags.rst() && !out[0].flags.ack(), "a bare RST");
        assert_eq!(out[0].seq, our_iss + 5, "SEQ = SEG.ACK");
    }

    #[test]
    fn active_open_refused_by_rst_with_acceptable_ack() {
        let now = Instant::from_millis(0);
        let mut tcb = new_client(now);
        drain_raw(&mut tcb, now);
        let our_iss = SeqNumber::new(OUR_ISS);
        deliver(&mut tcb, now, &peer_seg(SeqNumber::new(1), our_iss + 1, TcpFlags::RST | TcpFlags::ACK, 0, None, false, None, b""));
        assert_eq!(tcb.state, State::Closed);
        assert!(tcb.is_reset(), "a refused connect is observable as a reset");
    }

    #[test]
    fn active_open_ignores_blind_rst() {
        let now = Instant::from_millis(0);
        let mut tcb = new_client(now);
        drain_raw(&mut tcb, now);
        // A RST with no acceptable ACK is a blind reset — dropped, we stay SYN-SENT.
        deliver(&mut tcb, now, &peer_seg(SeqNumber::new(1), SeqNumber::new(0), TcpFlags::RST, 0, None, false, None, b""));
        assert_eq!(tcb.state, State::SynSent);
    }

    #[test]
    fn active_open_retransmits_syn_on_rto() {
        let now = Instant::from_millis(0);
        let mut tcb = new_client(now);
        let out = drain(&mut tcb, now);
        assert!(out[0].flags.syn());
        let deadline = tcb.poll_at().expect("rtx armed for the SYN");
        let later = deadline.plus_millis(1);
        tcb.on_timer(later);
        let out = drain(&mut tcb, later);
        assert_eq!(out.len(), 1);
        assert!(out[0].flags.syn() && !out[0].flags.ack(), "the SYN is retransmitted");
        assert_eq!(out[0].seq, SeqNumber::new(OUR_ISS));
        assert_eq!(tcb.state, State::SynSent);
    }

    #[test]
    fn active_open_times_out_after_max_syn_retries() {
        let now = Instant::from_millis(0);
        let mut tcb = new_client(now);
        drain_raw(&mut tcb, now); // initial SYN
        while tcb.state == State::SynSent {
            let d = tcb.poll_at().expect("rtx armed while SYN-SENT");
            let later = d.plus_millis(1);
            tcb.on_timer(later);
            drain_raw(&mut tcb, later);
        }
        assert_eq!(tcb.state, State::Closed);
        assert!(!tcb.is_reset(), "a connect timeout is not a reset (distinct from refused)");
    }

    #[test]
    fn active_open_synack_in_same_turn_as_rto_still_establishes() {
        // Regression (review finding): a SYN-SENT RTO must not rewind SND.NXT, or a SYN-ACK
        // ingested in the same reactor turn (after on_timer, before poll_transmit) would fail the
        // acceptability test (ISS < SEG.ACK <= SND.NXT) and be rejected with a spurious RST.
        let now = Instant::from_millis(0);
        let mut tcb = new_client(now);
        drain_raw(&mut tcb, now); // our SYN; SND.NXT = ISS+1, rtx armed
        let our_iss = SeqNumber::new(OUR_ISS);
        let peer_isn = SeqNumber::new(4242);

        // The RTO fires, THEN the SYN-ACK arrives — with no intervening poll_transmit.
        let deadline = tcb.poll_at().expect("rtx armed for the SYN");
        let later = deadline.plus_millis(1);
        tcb.on_timer(later);
        deliver(&mut tcb, later, &peer_seg(peer_isn, our_iss + 1, TcpFlags::SYN | TcpFlags::ACK, 64000, Some(1460), true, Some(7), b""));

        assert_eq!(tcb.state, State::Established, "the valid SYN-ACK must establish, not be rejected");
        let out = drain(&mut tcb, later);
        assert!(out.iter().all(|o| !o.flags.rst()), "no spurious RST to a cooperating peer");
        assert_eq!(out.len(), 1, "just the third-leg ACK");
        assert!(out[0].flags.ack() && !out[0].flags.syn());
        assert_eq!(out[0].seq, our_iss + 1, "the ACK uses SND.NXT = ISS+1, not a rewound ISS");
        assert_eq!(out[0].ack, peer_isn + 1);
    }

    #[test]
    fn half_open_bad_ack_closes_immediately_then_emits_rst() {
        // Regression (review finding): a half-open SYN-RECEIVED rejected by a bad ACK must reach
        // Closed in on_segment (so a waker observes it the same turn), with poll_transmit only
        // emitting the queued RST — not driving the close itself.
        let now = Instant::from_millis(0);
        let syn = inbound(SeqNumber::new(1000), SeqNumber::new(0), TcpFlags::SYN, 64000, Some(1460), b"");
        let ip = Ipv4Packet::new_checked(&syn).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        let mut tcb = Tcb::new_syn_received(ep_us(), ep_host(), &tcp, SeqNumber::new(OUR_ISS), now, 1460);
        let iss = drain(&mut tcb, now)[0].seq; // SYN-ACK
        // An in-window segment whose ACK does not acknowledge our SYN.
        deliver(&mut tcb, now, &inbound(SeqNumber::new(1001), iss + 9, TcpFlags::ACK, 64000, None, b""));
        assert_eq!(tcb.state, State::Closed, "the close is applied in on_segment, before poll_transmit");
        let out = drain(&mut tcb, now);
        assert_eq!(out.len(), 1);
        assert!(out[0].flags.rst() && !out[0].flags.ack(), "a bare RST is emitted");
        assert_eq!(out[0].seq, iss + 9, "SEQ = SEG.ACK");
    }

    #[test]
    fn syn_received_retransmits_syn_ack_on_rto() {
        // Regression (review finding): a passive (or simultaneous) open whose SYN-ACK is lost must
        // retransmit it on its own RTO, rather than relying on the peer re-sending its SYN.
        let now = Instant::from_millis(0);
        let syn = inbound(SeqNumber::new(2000), SeqNumber::new(0), TcpFlags::SYN, 64000, Some(1460), b"");
        let ip = Ipv4Packet::new_checked(&syn).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        let mut tcb = Tcb::new_syn_received(ep_us(), ep_host(), &tcp, SeqNumber::new(OUR_ISS), now, 1460);
        let out = drain(&mut tcb, now);
        assert!(out[0].flags.syn() && out[0].flags.ack());
        let iss = out[0].seq;

        let deadline = tcb.poll_at().expect("rtx armed for the SYN-ACK");
        let later = deadline.plus_millis(1);
        tcb.on_timer(later);
        let out = drain(&mut tcb, later);
        assert_eq!(out.len(), 1, "the SYN-ACK is retransmitted on RTO");
        assert!(out[0].flags.syn() && out[0].flags.ack());
        assert_eq!(out[0].seq, iss, "retransmitted at ISS");
        assert_eq!(tcb.state, State::SynReceived);
    }

    // ── TCP timestamps (RFC 7323) ─────────────────────────────────────────────────────────────

    /// A SYN offering MSS + SACK-Permitted + Timestamps (TSval `tsval`).
    fn inbound_syn_ts(seq: SeqNumber, window: u16, tsval: u32) -> Vec<u8> {
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
            timestamps: Some((tsval, 0)),
            ae: false,
        };
        build_segment(ep_host(), ep_us(), &repr, b"")
    }

    /// A segment carrying a Timestamps option `(tsval, tsecr)`.
    #[allow(clippy::too_many_arguments)]
    fn inbound_ts(seq: SeqNumber, ack: SeqNumber, flags: u8, window: u16, tsval: u32, tsecr: u32, payload: &[u8]) -> Vec<u8> {
        let repr = TcpRepr {
            src_port: CPORT,
            dst_port: 8080,
            seq,
            ack,
            flags: TcpFlags(flags),
            window,
            mss: None,
            sack_permitted: false,
            window_scale: None,
            sack: SackBlocks::default(),
            timestamps: Some((tsval, tsecr)),
            ae: false,
        };
        build_segment(ep_host(), ep_us(), &repr, payload)
    }

    fn frame_timestamps(frame: &[u8]) -> Option<(u32, u32)> {
        let ip = Ipv4Packet::new_checked(frame).unwrap();
        TcpPacket::new_checked(ip.payload()).unwrap().timestamps()
    }

    /// Establish a server connection that negotiated timestamps (client SYN TSval `cli_ts`).
    fn established_ts(now: Instant, client_isn: u32, window: u16, cli_ts: u32) -> (Tcb, SeqNumber, SeqNumber) {
        let syn = inbound_syn_ts(SeqNumber::new(client_isn), window, cli_ts);
        let ip = Ipv4Packet::new_checked(&syn).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        let mut tcb = Tcb::new_syn_received(ep_us(), ep_host(), &tcp, SeqNumber::new(OUR_ISS), now, 1460);
        let synack = tcb.poll_transmit(now).expect("SYN-ACK");
        let (synack_tsval, synack_tsecr) = frame_timestamps(&synack).expect("SYN-ACK carries timestamps");
        assert_eq!(synack_tsecr, cli_ts, "SYN-ACK echoes the client's SYN TSval");
        let our_iss = parse(&synack).seq;
        assert!(tcb.poll_transmit(now).is_none());
        let client_nxt = SeqNumber::new(client_isn) + 1;
        deliver(&mut tcb, now, &inbound_ts(client_nxt, our_iss + 1, TcpFlags::ACK, window, cli_ts + 1, synack_tsval, b""));
        assert!(drain(&mut tcb, now).is_empty());
        assert_eq!(tcb.state, State::Established);
        assert!(tcb.ts_enabled_dbg());
        (tcb, our_iss, client_nxt)
    }

    #[test]
    fn ts_negotiated_and_synack_echoes_tsval() {
        let now = Instant::from_millis(0);
        let syn = inbound_syn_ts(SeqNumber::new(1), 64000, 777);
        let ip = Ipv4Packet::new_checked(&syn).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        let mut tcb = Tcb::new_syn_received(ep_us(), ep_host(), &tcp, SeqNumber::new(OUR_ISS), now, 1460);
        assert!(tcb.ts_enabled_dbg(), "timestamps negotiated from the SYN");
        let synack = tcb.poll_transmit(now).unwrap();
        let (_, tsecr) = frame_timestamps(&synack).expect("SYN-ACK carries timestamps");
        assert_eq!(tsecr, 777, "TSecr echoes the SYN's TSval");
    }

    #[test]
    fn ts_not_enabled_when_not_offered() {
        let now = Instant::from_millis(0);
        let syn = inbound(SeqNumber::new(1), SeqNumber::new(0), TcpFlags::SYN, 64000, Some(1460), b"");
        let ip = Ipv4Packet::new_checked(&syn).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        let mut tcb = Tcb::new_syn_received(ep_us(), ep_host(), &tcp, SeqNumber::new(OUR_ISS), now, 1460);
        assert!(!tcb.ts_enabled_dbg());
        let synack = tcb.poll_transmit(now).unwrap();
        assert_eq!(frame_timestamps(&synack), None, "no timestamps emitted when not offered");
    }

    #[test]
    fn ts_emitted_on_every_segment_and_echoes_recent() {
        let now = Instant::from_micros(2_000_000);
        let (mut tcb, _iss, _cnxt) = established_ts(now, 1000, 64000, 5000);
        assert_eq!(tcb.ts_recent_dbg(), 5001, "TS.Recent advanced from the client's final ACK");
        tcb.send(b"hi");
        let frames = drain_raw(&mut tcb, now);
        let (tsval, tsecr) = frame_timestamps(&frames[0]).expect("data carries timestamps");
        assert_eq!(tsval, 2_000_000, "TSval is our microsecond clock (now)");
        assert_eq!(tsecr, 5001, "TSecr echoes TS.Recent");
    }

    #[test]
    fn ts_rtt_responds_to_tsecr() {
        let now0 = Instant::from_micros(1_000_000);
        let (mut tcb, iss, cnxt) = established_ts(now0, 1000, 64000, 5000);
        tcb.send(b"data");
        let frames = drain_raw(&mut tcb, now0);
        let (data_tsval, _) = frame_timestamps(&frames[0]).unwrap();
        assert_eq!(data_tsval, 1_000_000);
        // The peer ACKs 300 ms later, echoing our data TSval — the first RTT sample (the
        // SYN-RECEIVED→ESTABLISHED handshake path does not sample). First sample (RFC 6298):
        // RTO = R + 4·(R/2) = 3R = 900 ms.
        let now1 = Instant::from_micros(1_300_000);
        deliver(&mut tcb, now1, &inbound_ts(cnxt, iss + 1 + 4, TcpFlags::ACK, 64000, 6000, data_tsval, b""));
        assert_eq!(tcb.rto_dbg(), 900_000, "the 300 ms ts-RTT became the RTO estimate");
    }

    #[test]
    fn ts_rtt_is_karn_free_on_a_retransmit() {
        // The headline: timestamps let the retransmit's ACK measure RTT, which Karn forbids
        // without them. A 3 s retransmit RTT pushes the RTO well past 2 s; the Karn path would
        // take no sample and the RTO would fall back to the ~200 ms base.
        let now0 = Instant::from_micros(1_000_000);
        let (mut tcb, iss, cnxt) = established_ts(now0, 1000, 64000, 5000);
        tcb.send(b"data");
        drain_raw(&mut tcb, now0);
        let deadline = tcb.poll_at().expect("rtx armed");
        let now1 = deadline.plus_millis(1);
        tcb.on_timer(now1); // RTO: retransmit pending, backoff applied
        let rfrm = drain_raw(&mut tcb, now1);
        let (retx_tsval, _) = frame_timestamps(&rfrm[0]).unwrap();
        assert_eq!(retx_tsval, now1.micros() as u32, "the retransmit carries a fresh TSval");
        // The peer ACKs the RETRANSMIT 3 s later, echoing its fresh TSval.
        let now2 = Instant::from_micros(now1.micros() + 3_000_000);
        deliver(&mut tcb, now2, &inbound_ts(cnxt, iss + 1 + 4, TcpFlags::ACK, 64000, 7000, retx_tsval, b""));
        assert!(tcb.rto_dbg() > 2_000_000, "the retransmit's 3 s RTT was measured despite Karn");
    }

    #[test]
    fn segment_payload_leaves_room_for_the_timestamp_option() {
        // Regression: with timestamps negotiated, a full segment carries MSS − 12 bytes of payload
        // so the datagram (20 IP + 20 TCP + 12 TS + payload) fits the MTU the MSS was derived from
        // — otherwise a forwarding hop / smaller-MTU path drops the oversized 1512-byte segment.
        let now = Instant::from_micros(1_000_000);
        let (mut tcb, _iss, _cnxt) = established_ts(now, 30000, 64000, 5000);
        assert_eq!(tcb.send(&vec![0xab; 5000]), 5000);
        let frames = drain_raw(&mut tcb, now);
        assert_eq!(parse(&frames[0]).payload.len(), 1460 - 12, "payload leaves room for the TS option");
        assert_eq!(frames[0].len(), 1500, "the full datagram is exactly the MTU (20 + 32 + 1448)");
    }

    #[test]
    fn paws_drops_stale_then_accepts_fresh() {
        let now = Instant::from_micros(1_000_000);
        let (mut tcb, iss, cnxt) = established_ts(now, 1000, 64000, 5000);
        assert_eq!(tcb.ts_recent_dbg(), 5001);
        // A segment whose TSval (4000) predates TS.Recent (5001) is an old duplicate: PAWS drops it.
        deliver(&mut tcb, now, &inbound_ts(cnxt, iss + 1, TcpFlags::ACK | TcpFlags::PSH, 64000, 4000, 5001, b"old"));
        assert_eq!(tcb.rx_available(), 0, "PAWS drops the stale segment");
        let out = drain(&mut tcb, now);
        assert!(out.iter().any(|o| o.flags.ack()), "PAWS still ACKs RCV.NXT");
        assert_eq!(tcb.ts_recent_dbg(), 5001, "TS.Recent unchanged by the dropped segment");
        // A fresh-timestamp segment is accepted and advances TS.Recent.
        deliver(&mut tcb, now, &inbound_ts(cnxt, iss + 1, TcpFlags::ACK | TcpFlags::PSH, 64000, 5002, 5001, b"new"));
        assert_eq!(tcb.rx_available(), 3, "a fresh-timestamp segment is accepted");
        assert_eq!(tcb.ts_recent_dbg(), 5002, "TS.Recent advanced");
    }

    // ── delayed ACKs (RFC 1122 §4.2.3.2) ──────────────────────────────────────────────────────

    #[test]
    fn delayed_ack_defers_a_lone_segment_until_the_timer() {
        let now = Instant::from_millis(0);
        let (mut tcb, iss, cnxt) = established(now, 21000, 64000);
        deliver(&mut tcb, now, &inbound(cnxt, iss + 1, TcpFlags::ACK | TcpFlags::PSH, 64000, None, b"a"));
        assert!(drain(&mut tcb, now).is_empty(), "a lone in-order segment's ACK is delayed");
        let deadline = tcb.poll_at().expect("the delayed-ACK timer is armed");
        let later = deadline.plus_millis(1);
        tcb.on_timer(later);
        let out = drain(&mut tcb, later);
        assert_eq!(out.len(), 1);
        assert!(out[0].flags.ack() && out[0].payload.is_empty());
        assert_eq!(out[0].ack, cnxt + 1, "the timed-out ACK covers the received byte");
    }

    #[test]
    fn delayed_ack_fires_immediately_on_the_second_segment() {
        let now = Instant::from_millis(0);
        let (mut tcb, iss, cnxt) = established(now, 22000, 64000);
        deliver(&mut tcb, now, &inbound(cnxt, iss + 1, TcpFlags::ACK | TcpFlags::PSH, 64000, None, b"a"));
        assert!(drain(&mut tcb, now).is_empty(), "first segment delayed");
        deliver(&mut tcb, now, &inbound(cnxt + 1, iss + 1, TcpFlags::ACK | TcpFlags::PSH, 64000, None, b"b"));
        let out = drain(&mut tcb, now);
        assert_eq!(out.len(), 1, "the second in-order segment forces an immediate ACK");
        assert_eq!(out[0].ack, cnxt + 2);
    }

    #[test]
    fn delayed_ack_piggybacks_on_outgoing_data() {
        let now = Instant::from_millis(0);
        let (mut tcb, iss, cnxt) = established(now, 23000, 64000);
        deliver(&mut tcb, now, &inbound(cnxt, iss + 1, TcpFlags::ACK | TcpFlags::PSH, 64000, None, b"a"));
        tcb.send(b"reply"); // a response is queued: its segment carries the ACK
        let out = drain(&mut tcb, now);
        assert_eq!(out.len(), 1, "just the data segment — no separate ACK");
        assert_eq!(out[0].payload, b"reply");
        assert_eq!(out[0].ack, cnxt + 1, "the data piggybacks the deferred ACK");
    }

    #[test]
    fn out_of_order_segment_acks_immediately() {
        let now = Instant::from_millis(0);
        let (mut tcb, iss, cnxt) = established_sack(now, 24000, 64000);
        // A gap below it: out-of-order data must ACK at once so the dup-ACK drives fast retransmit.
        deliver(&mut tcb, now, &inbound(cnxt + 100, iss + 1, TcpFlags::ACK | TcpFlags::PSH, 64000, None, &[7u8; 50]));
        let out = drain(&mut tcb, now);
        assert_eq!(out.len(), 1, "out-of-order data is ACKed immediately, not delayed");
        assert_eq!(out[0].ack, cnxt, "a dup-ACK at the gap");
    }

    #[test]
    fn partial_gap_fill_acks_immediately() {
        // Regression (review finding): an in-order segment that advances RCV.NXT but leaves a SACK
        // hole still open must ACK at once (RFC 5681 §4.2), not defer — the sender needs the fresh
        // cumulative ACK + remaining SACK block to keep recovering, not a 40 ms-delayed one.
        let now = Instant::from_millis(0);
        let (mut tcb, iss, cnxt) = established_sack(now, 25000, 64000);
        // Out-of-order run [cnxt+100, cnxt+200): a gap [cnxt, cnxt+100) sits below it.
        deliver(&mut tcb, now, &inbound(cnxt + 100, iss + 1, TcpFlags::ACK | TcpFlags::PSH, 64000, None, &[7u8; 100]));
        drain(&mut tcb, now); // the immediate dup-ACK for the out-of-order data
        // Fill only PART of the gap: [cnxt, cnxt+50). The hole [cnxt+50, cnxt+100) and the buffered
        // run both remain, so reassembly is still in progress — the ACK must not be delayed.
        deliver(&mut tcb, now, &inbound(cnxt, iss + 1, TcpFlags::ACK | TcpFlags::PSH, 64000, None, &[5u8; 50]));
        let frames = drain_raw(&mut tcb, now);
        assert_eq!(frames.len(), 1, "a partial gap fill ACKs immediately, not delayed");
        assert_eq!(parse(&frames[0]).ack, cnxt + 50, "cumulative ACK advanced over the filled part");
        assert_eq!(parse_sack(&frames[0]).1, vec![((cnxt + 100).raw(), (cnxt + 200).raw())], "still reports the open hole");
    }

    // ── pluggable congestion control (CUBIC selected at birth) ──────────────────────────────────

    #[test]
    fn cubic_connection_handshakes_and_sends() {
        let now = Instant::from_millis(0);
        // Passive open, with CUBIC selected before the handshake completes — exactly how the Stack
        // stamps a connection at birth.
        let syn = inbound(SeqNumber::new(40000), SeqNumber::new(0), TcpFlags::SYN, 64000, Some(1460), b"");
        let ip = Ipv4Packet::new_checked(&syn).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        let mut tcb = Tcb::new_syn_received(ep_us(), ep_host(), &tcp, SeqNumber::new(OUR_ISS), now, 1460);
        tcb.set_congestion_control(CcKind::Cubic);
        assert_eq!(tcb.cc_kind_dbg(), CcKind::Cubic);

        let out = drain(&mut tcb, now);
        let our_iss = out[0].seq;
        let client_nxt = SeqNumber::new(40000) + 1;
        deliver(&mut tcb, now, &inbound(client_nxt, our_iss + 1, TcpFlags::ACK, 64000, None, b""));
        assert_eq!(tcb.state, State::Established);

        // Before any loss CUBIC is in slow start at the RFC 6928 initial window (== Reno), so the
        // first burst is exactly 10 * 1460 = 14600 bytes — the send path drives the enum correctly.
        let data = vec![0u8; 30000];
        assert_eq!(tcb.send(&data), 30000);
        let out = drain(&mut tcb, now);
        let sent: usize = out.iter().map(|o| o.payload.len()).sum();
        assert_eq!(sent, 14600, "CUBIC initial window matches RFC 6928");
        assert_eq!(tcb.cwnd_dbg(), 14600);
    }

    #[test]
    fn bbr_connection_paces_and_delivers() {
        let t0 = Instant::from_millis(0);
        // Passive open with BBR selected at birth (as the Stack stamps it).
        let syn = inbound(SeqNumber::new(50000), SeqNumber::new(0), TcpFlags::SYN, 64000, Some(1460), b"");
        let ip = Ipv4Packet::new_checked(&syn).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        let mut tcb = Tcb::new_syn_received(ep_us(), ep_host(), &tcp, SeqNumber::new(OUR_ISS), t0, 1460);
        tcb.set_congestion_control(CcKind::Bbr);
        assert_eq!(tcb.cc_kind_dbg(), CcKind::Bbr);
        let our_iss = drain(&mut tcb, t0)[0].seq;
        let cnxt = SeqNumber::new(50000) + 1;
        deliver(&mut tcb, t0, &inbound(cnxt, our_iss + 1, TcpFlags::ACK, 64000, None, b""));
        assert_eq!(tcb.state, State::Established);
        assert!(tcb.pacing_rate_dbg().is_none(), "no pacing until the first delivery-rate sample");

        let full = tcb.tx_free();
        assert_eq!(tcb.send(&vec![7u8; 30000]), 30000);

        // First burst: BBR has no model yet, so it sends cwnd-limited at the RFC 6928 initial
        // window (14600), exactly like Reno/CUBIC — no pacing throttle.
        let out = drain(&mut tcb, t0);
        let burst1: usize = out.iter().map(|o| o.payload.len()).sum();
        assert_eq!(burst1, 14600, "unpaced initial-window burst before the first sample");
        let mut high = out.last().unwrap().seq + out.last().unwrap().payload.len() as u32;

        // ACK the burst one RTT (20 ms) later: BBR now has a bandwidth and a min-RTT, so it paces.
        let t1 = t0.plus_millis(20);
        deliver(&mut tcb, t1, &inbound(cnxt, high, TcpFlags::ACK, 64000, None, b""));
        assert!(tcb.pacing_rate_dbg().is_some(), "BBR paces once it has a model");
        let out = drain(&mut tcb, t1);
        let burst2: usize = out.iter().map(|o| o.payload.len()).sum();
        assert!(
            burst2 > 0 && burst2 < burst1,
            "the next burst is paced — throttled below what the window alone would send: {burst2}"
        );
        assert!(tcb.poll_at().is_some(), "a pacing timer is armed so the rest follows");
        if let Some(o) = out.last() {
            high = high.max(o.seq + o.payload.len() as u32);
        }

        // Advance to each pacing deadline, acking what goes out, until the whole buffer is gone.
        // If pacing ever wedged (no timer / zero allowance forever) this would not converge.
        for _ in 0..2000 {
            if tcb.tx_free() == full {
                break;
            }
            let d = tcb.poll_at().expect("a timer is armed while data remains to send");
            let t = d.plus_micros(1);
            tcb.on_timer(t);
            let out = drain(&mut tcb, t);
            for o in &out {
                high = high.max(o.seq + o.payload.len() as u32);
            }
            deliver(&mut tcb, t, &inbound(cnxt, high, TcpFlags::ACK, 64000, None, b""));
        }
        assert_eq!(tcb.tx_free(), full, "pacing delivered the whole buffer without wedging");
    }

    /// An inbound pure ACK carrying a given 3-bit AccECN ACE counter (AE·CWR·ECE), to drive the
    /// sender-side delta decode. `seq` is the peer's (client's) sequence; `ack` is what it
    /// cumulatively acknowledges of our data.
    fn inbound_ace(seq: SeqNumber, ack: SeqNumber, window: u16, ace: u8) -> Vec<u8> {
        let mut flag_bits = TcpFlags::ACK;
        if ace & 0x02 != 0 {
            flag_bits |= TcpFlags::CWR;
        }
        if ace & 0x01 != 0 {
            flag_bits |= TcpFlags::ECE;
        }
        let repr = TcpRepr {
            src_port: CPORT,
            dst_port: 8080,
            seq,
            ack,
            flags: TcpFlags(flag_bits),
            window,
            mss: None,
            sack_permitted: false,
            window_scale: None,
            sack: SackBlocks::default(),
            timestamps: None,
            ae: ace & 0x04 != 0,
        };
        build_segment(ep_host(), ep_us(), &repr, b"")
    }

    /// AccECN receiver (RFC 9768 §3.2.2): the CE-marked-packet counter is reflected *exactly* in the
    /// 3-bit ACE field, no matter how delayed ACKs coalesce segments. A CE mark on a segment later
    /// coalesced under a delayed ACK bumps the counter by exactly one — the run-boundary imprecision
    /// of the old one-bit ECE echo (which attributed the whole coalesced span as marked) is gone. This
    /// is the exactness AccECN buys: the counter is monotonic and per-packet, never per-ACK.
    #[test]
    fn accecn_receiver_reflects_the_exact_ce_count() {
        let now = Instant::from_millis(0);
        let (mut tcb, iss, cnxt) = established(now, 1000, 64000);
        tcb.set_congestion_control(CcKind::Dctcp);

        // First in-order segment is CE-marked and deferred (a lone segment → delayed ACK); the second
        // is un-marked and triggers the coalesced ACK. The ACK's ACE must be baseline + 1 — exactly
        // one CE, not two: the un-marked partner in the coalesced pair is not counted.
        let mut s1 = inbound(cnxt, iss + 1, TcpFlags::ACK | TcpFlags::PSH, 64000, None, b"hello");
        crate::wire::set_ecn(&mut s1, crate::wire::ECN_CE);
        deliver(&mut tcb, now, &s1);
        assert!(drain(&mut tcb, now).is_empty(), "the first clean in-order segment defers its ACK");

        let s2 = inbound(cnxt + 5, iss + 1, TcpFlags::ACK | TcpFlags::PSH, 64000, None, b"world");
        deliver(&mut tcb, now, &s2); // not CE; triggers the coalesced ACK
        let out = drain(&mut tcb, now);
        assert_eq!(out.len(), 1, "the second segment triggers the coalesced ACK");
        assert_eq!(out[0].ack, cnxt + 10);
        assert_eq!(out[0].ace, (ACE_INIT + 1) & 0x07, "exactly one CE counted across the coalesced pair");

        // A second CE-marked segment, again coalesced, advances the counter by exactly one more — and
        // the counter is *not* reset between ACKs (the sender differences it), so a following ACK with
        // no new CE reflects the same value rather than dropping back to baseline.
        let mut s3 = inbound(cnxt + 10, iss + 1, TcpFlags::ACK | TcpFlags::PSH, 64000, None, b"12345");
        crate::wire::set_ecn(&mut s3, crate::wire::ECN_CE);
        deliver(&mut tcb, now, &s3);
        let s4 = inbound(cnxt + 15, iss + 1, TcpFlags::ACK | TcpFlags::PSH, 64000, None, b"67890");
        deliver(&mut tcb, now, &s4);
        let out = drain(&mut tcb, now);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ace, (ACE_INIT + 2) & 0x07, "the counter is monotonic — two CE marks total");

        // No new CE: the counter holds, so the next ACK reflects the same value (delta 0 at the sender).
        let s5 = inbound(cnxt + 20, iss + 1, TcpFlags::ACK | TcpFlags::PSH, 64000, None, b"abcde");
        deliver(&mut tcb, now, &s5);
        let s6 = inbound(cnxt + 25, iss + 1, TcpFlags::ACK | TcpFlags::PSH, 64000, None, b"fghij");
        deliver(&mut tcb, now, &s6);
        let out = drain(&mut tcb, now);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ace, (ACE_INIT + 2) & 0x07, "no new CE → the counter is unchanged");
    }

    /// AccECN sender (RFC 9768 §3.2.2): the wrapping ACE delta the peer reports is decoded into an
    /// *exact* marked-byte count (`delta · SMSS`), not a per-ACK "marked at all?" estimate, and fed to
    /// the controller — so the cut is proportional to the true mark count. We drive three identical bulk
    /// transfers that differ only in how many of each coalesced 2-segment ACK's segments were CE-marked:
    /// 0 (clean), 1 (delta = 1, half marked), 2 (delta = 2, fully marked). The fully-marked run must cut
    /// **strictly more** than the half-marked run. This pins the exactness the commit exists for: with a
    /// per-ACK latch (`delta.min(1)`) or the old all-or-nothing estimate (`marked = data_acked`) the
    /// delta = 1 and delta = 2 runs would be identical, and the assertion would fail.
    #[test]
    fn accecn_sender_cut_is_proportional_to_the_exact_ace_delta() {
        // Bulk transfer where every ACK cumulatively covers two emitted segments and advances the peer's
        // ACE counter by `marks_per_ack` (0..=2) — i.e. `marks_per_ack` of the two acked packets were
        // CE-marked. Returns the controller's window after the schedule. `marks_per_ack < 8`, so the
        // 3-bit field never wraps.
        fn drive(marks_per_ack: u8) -> u32 {
            let now = Instant::from_millis(0);
            let (mut tcb, _iss, cnxt) = established(now, 9000, 64000);
            tcb.set_congestion_control(CcKind::Dctcp);
            tcb.send(&vec![0x5a; 128 * 1024]);
            let mut ace = ACE_INIT;
            let mut pending: Vec<(SeqNumber, u32)> = Vec::new();
            for _ in 0..400 {
                for o in drain(&mut tcb, now) {
                    if !o.payload.is_empty() {
                        pending.push((o.seq, o.payload.len() as u32));
                    }
                }
                if pending.is_empty() {
                    break; // send buffer drained — schedule complete
                }
                // Coalesce up to two segments into one delayed ACK (cumulative ack covers both).
                let n = pending.len().min(2);
                let (seq, len) = pending[n - 1];
                pending.drain(0..n);
                ace = ace.wrapping_add(marks_per_ack);
                deliver(&mut tcb, now, &inbound_ace(cnxt, seq + len, 64000, ace & 0x07));
            }
            tcb.cwnd_dbg()
        }

        let clean = drive(0); // no marks: slow-start growth, no cut
        let half = drive(1); // ~50% marked: a gentle proportional cut
        let full = drive(2); // ~100% marked: a much deeper cut
        assert!(clean > crate::congestion::initial_window(1460), "the un-marked control grows its window: {clean}");
        assert!(half < clean, "a marked run cuts the window below the un-marked control: half {half} vs clean {clean}");
        assert!(
            full < half,
            "a fully-marked run (delta 2/ACK) must cut strictly more than a half-marked one (delta 1/ACK) — \
             the cut tracks the *exact* decoded mark count, not a per-ACK latch: full {full} vs half {half}"
        );
    }

    /// AccECN receiver, finding-1 regression (RFC 9768 §3.2.2): a CE mark is counted only for a segment
    /// whose data is actually *accepted*. On a SACK-off connection an out-of-order segment is dropped, so
    /// its CE must NOT bump the counter — otherwise the in-order retransmission of that same data would
    /// count the one congestion mark twice, inflating the sender's marked fraction.
    #[test]
    fn accecn_receiver_does_not_count_a_dropped_out_of_order_ce_mark() {
        let now = Instant::from_millis(0);
        // `established` offers no SACK-Permitted, so this connection has reassembly disabled: an
        // out-of-order segment is dropped rather than buffered.
        let (mut tcb, iss, cnxt) = established(now, 1000, 64000);
        tcb.set_congestion_control(CcKind::Dctcp);

        // An out-of-order CE-marked segment (a 5-byte gap below it is still missing): dropped, so the
        // CE-packet counter must stay at the baseline. The out-of-order arrival forces an immediate ACK.
        let mut ooo = inbound(cnxt + 5, iss + 1, TcpFlags::ACK | TcpFlags::PSH, 64000, None, b"world");
        crate::wire::set_ecn(&mut ooo, crate::wire::ECN_CE);
        deliver(&mut tcb, now, &ooo);
        let out = drain(&mut tcb, now);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ace, ACE_INIT & 0x07, "a dropped out-of-order CE segment must not be counted");

        // Two in-order CE-marked segments are now accepted (the first fills the missing gap, the second
        // is the data the dropped out-of-order segment carried). With SACK off the receiver can't tell a
        // gap was filled, so the first defers its ACK (every-other-segment rule) and the second triggers
        // the coalesced ACK. Its ACE must be baseline + 2 — only the two *accepted* segments are counted;
        // the dropped out-of-order arrival is not. (With the pre-fix double-count it would read +3.)
        let mut fill1 = inbound(cnxt, iss + 1, TcpFlags::ACK | TcpFlags::PSH, 64000, None, b"hello");
        crate::wire::set_ecn(&mut fill1, crate::wire::ECN_CE);
        deliver(&mut tcb, now, &fill1);
        assert!(drain(&mut tcb, now).is_empty(), "the lone in-order segment defers its ACK");
        let mut fill2 = inbound(cnxt + 5, iss + 1, TcpFlags::ACK | TcpFlags::PSH, 64000, None, b"world");
        crate::wire::set_ecn(&mut fill2, crate::wire::ECN_CE);
        deliver(&mut tcb, now, &fill2);
        let out = drain(&mut tcb, now);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ace, (ACE_INIT + 2) & 0x07, "only the two accepted in-order CE segments are counted");
    }

    /// The byte-identical guarantee at the wire level: a non-ECN (Reno) receiver never sets *any* ACE
    /// bit (AE / CWR / ECE), even when the data it receives is CE-marked — AccECN is entirely gated on
    /// the controller, so Reno/CUBIC/BBR emit a zero ACE field exactly as before.
    #[test]
    fn non_ecn_receiver_never_sets_ace_bits_even_for_ce_data() {
        let now = Instant::from_millis(0);
        let (mut tcb, iss, cnxt) = established(now, 1000, 64000); // default Reno
        let mut s1 = inbound(cnxt, iss + 1, TcpFlags::ACK | TcpFlags::PSH, 64000, None, b"hello");
        crate::wire::set_ecn(&mut s1, crate::wire::ECN_CE);
        deliver(&mut tcb, now, &s1);
        let s2 = inbound(cnxt + 5, iss + 1, TcpFlags::ACK | TcpFlags::PSH, 64000, None, b"world");
        deliver(&mut tcb, now, &s2);
        let out = drain(&mut tcb, now);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].ace, 0, "a non-ECN receiver emits a zero ACE field (byte-identical wire)");
        assert!(!out[0].flags.ece() && !out[0].flags.cwr(), "neither ECE nor CWR is ever set for Reno");
    }

    /// End-to-end plumbing for TCP Prague's defining feature: the TCB must feed the controller the
    /// smoothed RTT (`process_ack` → `on_rtt_sample`) so Prague's RTT-independent additive increase
    /// actually engages over the real stack — not just in the controller unit tests that call
    /// `on_rtt_sample` directly. Without this glue, Prague would silently stay at its `srtt == 0`
    /// one-MSS (Reno) step. We drive a clean RTT measurement and confirm the controller received it.
    #[test]
    fn prague_tcb_feeds_the_controller_the_smoothed_rtt() {
        let now = Instant::from_millis(0);
        let (mut tcb, iss, cnxt) = established(now, 1000, 64000);
        tcb.set_congestion_control(CcKind::Prague); // rebuilds the controller — srtt starts at 0
        assert_eq!(tcb.cc_prague_srtt_dbg(), Some(0), "a fresh Prague controller has no RTT yet");

        // Send a segment; its ACK arrives 80 ms later, a clean (un-retransmitted) RTT sample over the
        // Karn path. The TCB must forward the resulting smoothed RTT to the controller.
        assert_eq!(tcb.send(b"hello world"), 11);
        let out = drain(&mut tcb, now);
        assert_eq!(out.len(), 1, "the data segment is emitted");
        let later = now.plus_millis(80);
        deliver(&mut tcb, later, &inbound(cnxt, iss + 1 + 11, TcpFlags::ACK, 64000, None, b""));

        let srtt = tcb.cc_prague_srtt_dbg().expect("the connection runs Prague");
        // A real RTT reached the controller (the deleted-plumbing regression leaves this at 0, failing
        // here). The value is the smoothed RTT — blended with the ~0 µs same-instant handshake sample,
        // so it is a few ms rather than the raw 80 ms, but unambiguously non-zero and multi-millisecond.
        assert!(srtt > 1_000, "the controller received a real smoothed RTT over the stack, got {srtt} µs");
    }
}
