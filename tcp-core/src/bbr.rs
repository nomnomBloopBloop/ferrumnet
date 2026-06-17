//! BBR congestion control (the v1 model, Cardwell et al., draft-cardwell-iccrg-bbr-congestion-control).
//!
//! Where Reno and CUBIC react to *loss* and control sending with a *window*, BBR builds an explicit
//! model of the path — its **bottleneck bandwidth** (BtlBw) and **round-trip propagation delay**
//! (RTprop = min-RTT) — and **paces** packets out at a multiple of that bandwidth, keeping the
//! in-flight data near the bandwidth-delay product (BDP) instead of overfilling the bottleneck
//! queue. That makes it the natural third point of the comparison: loss-based (Reno/CUBIC) vs
//! model-based.
//!
//! It is built from three pieces, each independently testable in this sans-IO core:
//! - [`RateSampler`] — the delivery-rate estimator (Cheng/Cardwell): per transmitted segment it
//!   snapshots how much had been delivered and when, and on each ACK turns the newly-delivered
//!   bytes over the elapsed interval into a delivery-rate sample (plus an RTT sample).
//! - [`WindowedMax`] — Kathleen Nichols' O(1) windowed-max filter, tracking BtlBw as the maximum
//!   delivery rate over the last several round trips so a transient dip never lowers the estimate.
//! - [`Bbr`] — the state machine: STARTUP (find the bandwidth, doubling each round), DRAIN (empty
//!   the queue STARTUP built), PROBE_BW (cruise at the BDP, periodically probing up then down), and
//!   PROBE_RTT (every 10 s, briefly drain to re-measure RTprop). Each phase is a deterministic
//!   function of the model, so each is unit-testable under a simulated path.
//!
//! Two pragmatic bounds vs the full draft, both documented at their use site: loss is handled for
//! *reliability* by the TCB (BBR does not cut its model on loss, by design), and pacing on the tx
//! path is a token bucket rather than a per-packet timer. Everything is **std-only** — the rates
//! and gains use `f64` arithmetic with no transcendental intrinsics, so the controller stays
//! deterministic and clean under Miri.
//!
//! **Under-loss throughput (the BBRv2 inflight bounds).** Pure BBRv1 is loss-agnostic, so on a path
//! with steady random (non-congestive) loss it kept refilling its whole send buffer (≈ the BDP) and
//! piled up more simultaneous holes than the 4-block SACK option can report; the unreported holes
//! were invisible to the sender, so RFC 6675 `NextSeg` returned `None` and recovery degraded to
//! one-segment-per-RTO go-back-N — a death spiral. The first fix held the recovery window at a fixed
//! `pipe + 3·MSS`: robust (it always completes) but slow, because it throttles *new* data to three
//! segments however light the loss. This module now closes that gap with the BBRv2 **inflight
//! bounds** ([`Bbr::inflight_hi`] / [`Bbr::inflight_lo`]): an AIMD pair that caps total inflight and
//! adapts the recovery headroom to the path. A loss signal cuts them multiplicatively; clean rounds
//! probe them back up one segment at a time. So on a lightly-lossy path BBR re-opens the window and
//! reclaims throughput, while on a heavily-lossy one the bounds stay tight and it does not out-run
//! the SACK budget — without ever violating the hard invariant that `cwnd > pipe` during recovery
//! (the floor stays `pipe + 3·MSS`). An **ACK-aggregation** estimate ([`Bbr::extra_acked`]) adds
//! the window slack a stretch/aggregated ACK train needs to keep the pipe full.

use std::collections::VecDeque;

use crate::congestion::{initial_window, CongestionControl};
use crate::seq::SeqNumber;
use crate::time::Instant;

// ── tunables (BBRv1) ────────────────────────────────────────────────────────────────────────────

/// STARTUP gain `2/ln2`, applied to both pacing and cwnd: doubles the sending rate each round until
/// the pipe is full, mirroring slow start but clocked by the bandwidth estimate.
const HIGH_GAIN: f64 = 2.885;
/// DRAIN pacing gain `ln2/2` (≈ `1/HIGH_GAIN`): drains the queue STARTUP created in one round.
const DRAIN_GAIN: f64 = 0.346;
/// PROBE_BW cwnd gain: hold up to ~2·BDP in flight while cruising.
const CWND_GAIN: f64 = 2.0;
/// PROBE_BW pacing-gain cycle: probe 25 % up, give it back 25 % down, then cruise at 1× for six
/// phases. Each phase lasts one min-RTT.
const PROBE_BW_GAINS: [f64; 8] = [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];
/// STARTUP is "full" once BtlBw fails to grow by ≥ 25 % for this many rounds.
const FULL_BW_THRESH: f64 = 1.25;
const FULL_BW_COUNT: u32 = 3;
/// RTprop window: re-probe min-RTT if no lower sample is seen for this long.
const MIN_RTT_WINDOW_US: u64 = 10_000_000;
/// PROBE_RTT holds a minimal window for at least this long to drain the path and read RTprop.
const PROBE_RTT_DURATION_US: u64 = 200_000;
/// BtlBw max-filter window, in round trips.
const BTLBW_WINDOW_ROUNDS: u64 = 10;
/// Floor on cwnd and on the PROBE_RTT window, in segments.
const MIN_CWND_SEGS: u32 = 4;
/// Robust recovery headroom above the RFC 6675 `pipe`, in segments — the floor that keeps
/// `cwnd > pipe` so the selective retransmit always fires while a loss is repaired. (Measured
/// tuning: 3·MSS completes at every loss level; 8·/16·MSS re-accumulate holes and time out — see
/// the module docs on the inflight bounds.) Above this floor the headroom grows *adaptively* via
/// the BBRv2 [`Bbr::inflight_lo`]/[`Bbr::inflight_hi`] bounds.
const RECOVERY_HEADROOM_SEGS: u32 = 3;
/// Multiplicative-decrease factor applied to [`Bbr::inflight_lo`] on each subsequent loss episode:
/// the short-term inflight bound drops to `(1 − BETA)` of its prior value. A **gentle 0.3** (keep
/// 70 %, the BBRv2 default), so BBR holds a fuller window than a reno-style halving would and beats
/// loss-based control when the path can actually carry it. This is only safe because the shared
/// go-back-N recovery now drains an over-large window's occasional >4-hole burst in O(holes) *round
/// trips* (ack-clocked, see `Tcb::gbn_recover`) instead of collapsing into one-segment-per-RTO; with
/// that sticky wedge removed, BBR no longer has to stay reno-small to avoid it.
const INFLIGHT_LO_BETA: f64 = 0.3;
/// The survivor fraction of peak inflight used when a bound is first activated, and when an RTO
/// re-cuts it: a reno-like halving — the proven-robust operating point for the initial drop and the
/// severe RTO signal — from which the gentler per-episode trims take over.
const INFLIGHT_HARD_KEEP: f64 = 0.5;

// ── delivery-rate estimator ───────────────────────────────────────────────────────────────────

/// A delivery-rate sample produced when an ACK newly delivers data.
#[derive(Clone, Copy, Debug)]
pub struct RateSample {
    /// Estimated delivery rate over the sample interval, in **bytes/second**.
    pub delivery_rate: u64,
    /// RTT of the newest packet this ACK delivered, in microseconds (`now − sent_time`).
    pub rtt_us: u32,
    /// The interval the rate was measured over, in microseconds.
    pub interval_us: u64,
    /// The sample came from data sent while the connection was application-limited (so it is a
    /// lower bound on the path's capacity, not a measurement of it).
    pub is_app_limited: bool,
    /// `delivered` (cumulative bytes) as of when the newest delivered packet was *sent* — used by
    /// the caller to count round trips.
    pub prior_delivered: u64,
}

/// Per-segment bookkeeping captured at transmit time, popped when the segment is cumulatively ACKed.
#[derive(Clone, Copy)]
struct Sent {
    seq_end: SeqNumber,
    /// New-data bytes this segment carried (its span; segments never overlap, since only new data
    /// — not retransmits — is recorded, so summing popped sizes is the bytes delivered).
    size: u32,
    sent_time: Instant,
    /// `C.delivered` when this segment was sent.
    delivered: u64,
    /// `C.delivered_time` when this segment was sent.
    delivered_time: Instant,
    /// `C.first_sent_time` when this segment was sent (start of its send burst).
    first_sent_time: Instant,
    is_app_limited: bool,
}

/// Delivery-rate estimator (draft-cheng-iccrg-delivery-rate-estimation). Connection-level counters
/// plus a FIFO of in-flight send records; bounded by the number of outstanding segments.
pub struct RateSampler {
    /// Total bytes cumulatively delivered (ACKed) on the connection.
    delivered: u64,
    /// When `delivered` last advanced.
    delivered_time: Instant,
    /// Send time that begins the current rate-sample interval.
    first_sent_time: Instant,
    /// `delivered` value past which app-limited no longer applies (0 ⇒ not app-limited).
    app_limited_until: u64,
    sent: VecDeque<Sent>,
}

impl RateSampler {
    fn new() -> Self {
        RateSampler {
            delivered: 0,
            delivered_time: Instant::ZERO,
            first_sent_time: Instant::ZERO,
            app_limited_until: 0,
            sent: VecDeque::new(),
        }
    }

    /// Total bytes delivered so far (used by the caller to track round trips).
    fn delivered(&self) -> u64 {
        self.delivered
    }

    /// Record a transmitted segment. `inflight` is the bytes outstanding *before* this send: when
    /// it is zero the connection restarted from idle, so the sample interval restarts here.
    fn on_transmit(&mut self, now: Instant, seq_end: SeqNumber, bytes: u32, inflight: u32, app_limited: bool) {
        // Restart the sample interval here when nothing is outstanding from the sampler's view —
        // a true idle restart (`inflight == 0`), or after `reset_in_flight` dropped the records on
        // an RTO (FIFO empty though `inflight` may not be). Otherwise the next send would snapshot a
        // `first_sent_time` spanning the gap and overstate the interval of the resulting sample.
        if inflight == 0 || self.sent.is_empty() {
            self.first_sent_time = now;
            self.delivered_time = now;
        }
        if app_limited {
            // Mark everything currently in flight (plus this send) as app-limited.
            self.app_limited_until = (self.delivered + inflight as u64 + bytes as u64).max(1);
        }
        self.sent.push_back(Sent {
            seq_end,
            size: bytes,
            sent_time: now,
            delivered: self.delivered,
            delivered_time: self.delivered_time,
            first_sent_time: self.first_sent_time,
            is_app_limited: self.app_limited_until != 0,
        });
    }

    /// Process an ACK that advanced the cumulative acknowledgement to `snd_una`. Pops every
    /// fully-ACKed send record (advancing `delivered` by their non-overlapping sizes) and returns a
    /// rate sample built from the newest one delivered, or `None` if this ACK delivered nothing new.
    fn on_ack(&mut self, now: Instant, snd_una: SeqNumber) -> Option<RateSample> {
        let mut newest: Option<Sent> = None;
        while let Some(front) = self.sent.front() {
            if front.seq_end.le(snd_una) {
                let s = *front;
                self.sent.pop_front();
                self.delivered += s.size as u64;
                newest = Some(s); // monotonic seq_end ⇒ the last popped is the newest delivered
            } else {
                break;
            }
        }
        let p = newest?;
        self.delivered_time = now;
        // App-limited no longer applies once we have delivered past the marked point.
        if self.app_limited_until != 0 && self.delivered > self.app_limited_until {
            self.app_limited_until = 0;
        }
        // The sample interval is the longer of how long the data took to send (send_elapsed) and
        // how long it took to be ACKed (ack_elapsed); the max guards against ACK compression /
        // bursty sends understating the interval and overstating the rate.
        let send_elapsed = p.sent_time.saturating_micros_since(p.first_sent_time);
        let ack_elapsed = now.saturating_micros_since(p.delivered_time);
        let interval_us = send_elapsed.max(ack_elapsed);
        let delivered = self.delivered - p.delivered;
        self.first_sent_time = p.sent_time; // start the next interval at the newest delivered send
        let delivery_rate = if interval_us > 0 {
            delivered.saturating_mul(1_000_000) / interval_us
        } else {
            0
        };
        Some(RateSample {
            delivery_rate,
            rtt_us: now.saturating_micros_since(p.sent_time).min(u32::MAX as u64) as u32,
            interval_us,
            is_app_limited: p.is_app_limited,
            prior_delivered: p.delivered,
        })
    }

    /// Drop all in-flight send records (e.g. on RTO, where their timing is no longer trustworthy).
    fn reset_in_flight(&mut self) {
        self.sent.clear();
    }
}

// ── windowed-max filter (BtlBw) ───────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Default)]
struct MaxSample {
    t: u64,
    v: u64,
}

/// Kathleen Nichols' windowed-max filter (Linux's `win_minmax`): the maximum value over a sliding
/// window of `window` time units, maintained in O(1) from three candidate samples. `t` is a
/// monotonic counter — for BtlBw it is the round-trip count, so "window = 10" means 10 round trips.
/// Tracking the *max* means a brief delivery-rate dip (e.g. an app-limited round) never lowers the
/// bandwidth estimate; it only decays once genuinely old samples age out of the window.
struct WindowedMax {
    window: u64,
    s: [MaxSample; 3],
}

impl WindowedMax {
    fn new(window: u64) -> Self {
        WindowedMax { window, s: [MaxSample::default(); 3] }
    }

    fn reset(&mut self, t: u64, v: u64) -> u64 {
        self.s = [MaxSample { t, v }; 3];
        self.s[0].v
    }

    fn update(&mut self, t: u64, v: u64) -> u64 {
        // A new running maximum, or the whole window has aged out: restart from this sample.
        if v >= self.s[0].v || t.wrapping_sub(self.s[2].t) > self.window {
            return self.reset(t, v);
        }
        if v >= self.s[1].v {
            self.s[1] = MaxSample { t, v };
            self.s[2] = self.s[1];
        } else if v >= self.s[2].v {
            self.s[2] = MaxSample { t, v };
        }
        // Expire the oldest estimate(s) that have fallen outside the window.
        if t.wrapping_sub(self.s[0].t) > self.window {
            self.s[0] = self.s[1];
            self.s[1] = self.s[2];
            self.s[2] = MaxSample { t, v };
            if t.wrapping_sub(self.s[0].t) > self.window {
                self.s[0] = self.s[1];
                self.s[1] = self.s[2];
            }
        }
        self.s[0].v
    }
}

// ── BBR state machine ─────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    /// Probe for bandwidth by doubling the rate each round until the pipe stops filling.
    Startup,
    /// Drain the queue STARTUP overshot into, down to one BDP in flight.
    Drain,
    /// Steady state: cruise at the BDP, cycling the pacing gain to probe up then yield.
    ProbeBw,
    /// Briefly hold a minimal window to re-measure the round-trip propagation delay.
    ProbeRtt,
}

/// BBR (v1). Holds the path model (BtlBw + min-RTT), the phase, and the derived pacing rate and
/// congestion window. See the module docs for the overall shape.
pub struct Bbr {
    mss: u32,
    cwnd: u32,
    mode: Mode,
    sampler: RateSampler,
    btlbw_filter: WindowedMax,
    /// Cached `btlbw_filter.get()`, bytes/sec (0 until the first reliable sample).
    btlbw: u64,
    /// RTprop estimate, microseconds (`u32::MAX` until the first RTT sample).
    min_rtt_us: u32,
    min_rtt_stamp: Instant,
    pacing_gain: f64,
    cwnd_gain: f64,
    /// Derived pacing rate, bytes/sec (0 ⇒ not enough model yet ⇒ send cwnd-limited, unpaced).
    pacing_rate: u64,

    // Round-trip accounting (a round ends when the data outstanding at its start is fully ACKed).
    round_count: u64,
    next_round_delivered: u64,
    round_start: bool,

    // STARTUP "pipe full" detection.
    full_bw: u64,
    full_bw_count: u32,
    filled_pipe: bool,

    // PROBE_BW pacing-gain cycle.
    cycle_index: usize,
    cycle_stamp: Instant,

    // PROBE_RTT.
    probe_rtt_done_stamp: Option<Instant>,
    prior_cwnd: u32,

    // ── BBRv2 inflight bounds (under-loss throughput) ───────────────────────────────────────────
    /// Long-term inflight ceiling (bytes): the largest inflight the path has sustained without
    /// excessive loss. `u32::MAX` until the first loss bounds it. Cut (gently) on a loss round,
    /// raised one segment per clean round; caps cwnd in *all* phases, so after a loss BBR rebuilds
    /// toward — not straight past — the level the path was last shown to hold.
    inflight_hi: u32,
    /// Short-term inflight bound (bytes): the AIMD reaction to recent loss, and the knob that sets
    /// the adaptive recovery headroom. `u32::MAX` while cruising clean (inactive). Cut
    /// multiplicatively the instant a loss episode starts and on RTO, raised one segment per clean
    /// (non-recovery) round, released back to `MAX` once it overtakes `inflight_hi`.
    inflight_lo: u32,
    /// A loss has been signalled (recovery entry / 3rd dup-ACK / RTO) since the current round began.
    loss_in_round: bool,
    /// Whether the previous `on_ack_sample` observed recovery in progress — for detecting the rising
    /// edge of a loss episode (the immediate-cut trigger).
    was_in_recovery: bool,
    /// Maximum raw inflight (bytes) seen during the current round — the level the loss cut shrinks
    /// from when the bounds are first activated.
    inflight_latest: u32,

    // ── ACK aggregation (extra_acked) ───────────────────────────────────────────────────────────
    /// Windowed-max of the per-epoch ACK-aggregation excess, over the BtlBw round window.
    extra_acked_filter: WindowedMax,
    /// Cached `extra_acked_filter` value (bytes): how much more than the bottleneck rate predicts a
    /// burst of ACKs has delivered, added to the cwnd target so a stretch/aggregated ACK train does
    /// not starve the pipe.
    extra_acked: u32,
    /// Start of the current ACK-aggregation measurement epoch.
    ack_epoch_stamp: Instant,
    /// Bytes cumulatively acknowledged since `ack_epoch_stamp`.
    ack_epoch_acked: u64,

    /// Duplicate-ACK count, for triggering fast retransmit only — BBR never cuts its model on loss.
    dup_acks: u8,
}

impl Bbr {
    pub fn new(mss: u16) -> Self {
        let mss = mss as u32;
        Bbr {
            mss,
            cwnd: initial_window(mss),
            mode: Mode::Startup,
            sampler: RateSampler::new(),
            btlbw_filter: WindowedMax::new(BTLBW_WINDOW_ROUNDS),
            btlbw: 0,
            min_rtt_us: u32::MAX,
            min_rtt_stamp: Instant::ZERO,
            pacing_gain: HIGH_GAIN,
            cwnd_gain: HIGH_GAIN,
            pacing_rate: 0,
            round_count: 0,
            next_round_delivered: 0,
            round_start: false,
            full_bw: 0,
            full_bw_count: 0,
            filled_pipe: false,
            cycle_index: 0,
            cycle_stamp: Instant::ZERO,
            probe_rtt_done_stamp: None,
            prior_cwnd: 0,
            inflight_hi: u32::MAX,
            inflight_lo: u32::MAX,
            loss_in_round: false,
            was_in_recovery: false,
            inflight_latest: 0,
            extra_acked_filter: WindowedMax::new(BTLBW_WINDOW_ROUNDS),
            extra_acked: 0,
            ack_epoch_stamp: Instant::ZERO,
            ack_epoch_acked: 0,
            dup_acks: 0,
        }
    }

    fn min_cwnd(&self) -> u32 {
        MIN_CWND_SEGS * self.mss
    }

    /// Bandwidth-delay product in bytes (`BtlBw · RTprop`), or 0 until both are known.
    fn bdp(&self) -> u64 {
        if self.btlbw == 0 || self.min_rtt_us == u32::MAX {
            return 0;
        }
        self.btlbw.saturating_mul(self.min_rtt_us as u64) / 1_000_000
    }

    /// STARTUP exits once the bandwidth estimate stops growing by ≥ 25 % for `FULL_BW_COUNT` rounds.
    fn check_full_pipe(&mut self) {
        if self.filled_pipe || !self.round_start {
            return;
        }
        if self.btlbw as f64 >= self.full_bw as f64 * FULL_BW_THRESH {
            self.full_bw = self.btlbw;
            self.full_bw_count = 0;
            return;
        }
        self.full_bw_count += 1;
        if self.full_bw_count >= FULL_BW_COUNT {
            self.filled_pipe = true;
        }
    }

    fn enter_probe_bw(&mut self, now: Instant) {
        self.mode = Mode::ProbeBw;
        self.cwnd_gain = CWND_GAIN;
        // Start cruising (gain 1.0) rather than immediately probing up, then let the cycle advance.
        self.cycle_index = 2;
        self.pacing_gain = PROBE_BW_GAINS[self.cycle_index];
        self.cycle_stamp = now;
    }

    /// In PROBE_BW each pacing-gain phase lasts one min-RTT. (Full BBR advances the probe-up phase
    /// early once it reaches 1.25·BDP in flight and the probe-down phase once it falls back to the
    /// BDP; the fixed min-RTT timing here is deterministic and adequate for the comparison.)
    fn advance_probe_bw(&mut self, now: Instant) {
        if now.saturating_micros_since(self.cycle_stamp) >= self.min_rtt_us as u64 {
            self.cycle_index = (self.cycle_index + 1) % PROBE_BW_GAINS.len();
            self.pacing_gain = PROBE_BW_GAINS[self.cycle_index];
            self.cycle_stamp = now;
        }
    }

    /// Enter PROBE_RTT when RTprop has gone un-refreshed for its whole window. `expired` is computed
    /// by the caller *before* the min-RTT refresh resets the stamp (cf. Linux `bbr_update_min_rtt`,
    /// which derives `filter_expired` once and uses it for both the refresh and this trigger) — so
    /// the refresh cannot consume the staleness signal this entry depends on.
    fn maybe_enter_probe_rtt(&mut self, expired: bool) {
        if expired && self.mode != Mode::ProbeRtt {
            self.mode = Mode::ProbeRtt;
            self.pacing_gain = 1.0;
            self.cwnd_gain = 1.0;
            self.prior_cwnd = self.cwnd;
            self.probe_rtt_done_stamp = None;
        }
    }

    fn handle_probe_rtt(&mut self, now: Instant, inflight: u32) {
        match self.probe_rtt_done_stamp {
            None => {
                // Once in-flight has drained to the minimal window, time the probe.
                if inflight <= self.min_cwnd() {
                    self.probe_rtt_done_stamp = Some(now.plus_micros(PROBE_RTT_DURATION_US));
                }
            }
            Some(done) => {
                if now >= done {
                    // RTprop has been re-measured by samples during the probe; resume cruising.
                    self.min_rtt_stamp = now;
                    self.probe_rtt_done_stamp = None;
                    if self.filled_pipe {
                        self.enter_probe_bw(now);
                    } else {
                        self.mode = Mode::Startup;
                        self.pacing_gain = HIGH_GAIN;
                        self.cwnd_gain = HIGH_GAIN;
                    }
                    self.cwnd = self.cwnd.max(self.prior_cwnd);
                }
            }
        }
    }

    fn update_mode(&mut self, now: Instant, inflight: u32, min_rtt_expired: bool) {
        self.maybe_enter_probe_rtt(min_rtt_expired);
        match self.mode {
            Mode::Startup => {
                self.check_full_pipe();
                if self.filled_pipe {
                    self.mode = Mode::Drain;
                    self.pacing_gain = DRAIN_GAIN;
                    self.cwnd_gain = HIGH_GAIN; // hold the window high while the queue drains
                }
            }
            Mode::Drain => {
                if (inflight as u64) <= self.bdp() {
                    self.enter_probe_bw(now);
                }
            }
            Mode::ProbeBw => self.advance_probe_bw(now),
            Mode::ProbeRtt => self.handle_probe_rtt(now, inflight),
        }
    }

    /// Cut the short-term inflight bound on a loss episode (the multiplicative decrease). The first
    /// activation drops to half the peak inflight (`INFLIGHT_HARD_KEEP`, a reno-like halving);
    /// thereafter each loss trims the current bound more gently (×`(1 − INFLIGHT_LO_BETA)` = ×0.7,
    /// the BBRv2 default), so BBR settles at a fuller window than a reno halving would — relying on
    /// the now-fast go-back-N drain to absorb the occasional over-shoot. The long-term ceiling
    /// `inflight_hi` is touched only by an RTO (the severe signal), so on a path whose losses are all
    /// SACK-repaired it stays inactive and `inflight_lo` alone binds.
    fn cut_inflight_bounds(&mut self) {
        let floor = self.min_cwnd();
        let latest = self.inflight_latest.max(floor);
        self.inflight_lo = if self.inflight_lo == u32::MAX {
            ((latest as f64 * INFLIGHT_HARD_KEEP) as u32).max(floor)
        } else {
            ((self.inflight_lo as f64 * (1.0 - INFLIGHT_LO_BETA)) as u32).max(floor)
        };
    }

    /// Probe the inflight bounds back up one segment per round (the AIMD additive increase), like
    /// reno's congestion avoidance. Run once per round BETWEEN loss episodes (the caller gates it on
    /// `!in_recovery`); never during a repair, where the extra in-flight data would feed the wedge.
    /// The long-term ceiling (activated only by an RTO) climbs the same way; the short-term bound is
    /// released to `MAX` once it overtakes the ceiling, so cwnd reverts to the model target after loss
    /// subsides.
    fn raise_inflight_bounds(&mut self) {
        if self.inflight_hi != u32::MAX {
            self.inflight_hi = self.inflight_hi.saturating_add(self.mss);
        }
        if self.inflight_lo != u32::MAX {
            self.inflight_lo = self.inflight_lo.saturating_add(self.mss);
            if self.inflight_lo >= self.inflight_hi {
                self.inflight_lo = u32::MAX;
            }
        }
    }

    /// ACK-aggregation estimator (draft-cardwell-iccrg-bbr, `bbr_update_ack_aggregation`). Over a
    /// measurement epoch it compares the bytes actually acknowledged against what the bottleneck
    /// rate predicts; the windowed-max of the excess across the BtlBw round window is `extra_acked`,
    /// added to the cwnd target. This compensates for stretched/aggregated ACKs (delayed-ACK trains,
    /// bursty arrival): without it the window would size to the smooth rate and starve the pipe each
    /// time several ACKs land together. The epoch restarts whenever the ACK rate falls back to the
    /// bottleneck rate, so the excess is measured per burst rather than accumulated forever.
    fn update_ack_aggregation(&mut self, now: Instant, acked: u32) {
        if self.btlbw == 0 || acked == 0 {
            return;
        }
        let epoch_us = now.saturating_micros_since(self.ack_epoch_stamp);
        let mut expected = self.btlbw.saturating_mul(epoch_us) / 1_000_000;
        if self.ack_epoch_acked <= expected {
            self.ack_epoch_acked = 0;
            self.ack_epoch_stamp = now;
            expected = 0;
        }
        self.ack_epoch_acked = self.ack_epoch_acked.saturating_add(acked as u64);
        // Cap the excess at the BDP so a stale epoch can't inflate the window without bound.
        let extra = self
            .ack_epoch_acked
            .saturating_sub(expected)
            .min(self.bdp().max(self.min_cwnd() as u64));
        self.extra_acked = self.extra_acked_filter.update(self.round_count, extra).min(u32::MAX as u64) as u32;
    }

    fn set_pacing_and_cwnd(&mut self, acked: u32, pipe: u32, in_recovery: bool) {
        if self.btlbw == 0 || self.min_rtt_us == u32::MAX {
            // Not enough model yet: stay at the initial window and send unpaced (cwnd-limited).
            self.pacing_rate = 0;
            return;
        }
        self.pacing_rate = (self.btlbw as f64 * self.pacing_gain) as u64;
        let min_cwnd = self.min_cwnd() as u64;
        // The model target: ~cwnd_gain·BDP, plus the ACK-aggregation slack so a burst of ACKs does
        // not starve the pipe. The aggregation slack is only applied once the pipe is full (as
        // upstream BBR does): during STARTUP the doubling delivery rate registers as "aggregation",
        // and adding it there would inflate an already-aggressive ramp.
        let extra = if self.filled_pipe { self.extra_acked as u64 } else { 0 };
        let target = ((self.bdp() as f64 * self.cwnd_gain) as u64 + extra).max(min_cwnd);
        // The BBRv2 inflight bounds cap total inflight so a lossy path settles at a tolerable
        // headroom instead of re-bursting the whole BDP into the loss. Inactive (`MAX`) on a clean
        // path, so this is a no-op there and the 0 %-loss behaviour is unchanged.
        let bound = (self.inflight_hi as u64).min(self.inflight_lo as u64);
        let cwnd = if in_recovery {
            // BBRv2-style loss response. BBR v1 ignores loss and would refill its whole window,
            // burying SND.UNA behind more simultaneous holes than the 4-block SACK option can report
            // — recovery then wedges into one-segment-per-RTO go-back-N. Instead BBR operates at the
            // adaptive inflight bound `min(inflight_lo, inflight_hi)`: a PERSISTENT, reno-like window
            // (gently trimmed per SACK-recovered episode, probed back up every round, cut hard only on
            // an RTO) — NOT a per-episode reset to the floor, which is what pinned throughput at the
            // crawl. The send gate `cwnd − pipe` for new data is therefore as wide as that bound minus
            // the in-flight estimate, so a 1 %-loss flow can keep the pipe reasonably full instead of
            // trickling three segments. Floored at `pipe + 3·MSS`: that floor is the hard invariant —
            // `cwnd > pipe` so the selective retransmit always fires — and it is what makes the bound
            // safe to keep high, since at recovery entry (pipe ≈ full inflight) the floor dominates
            // and the bound only opens up as holes get SACKed and `pipe` drops. We never clamp DOWN to
            // the `target`/bound when it is ≤ pipe — that would close both send gates and re-wedge.
            let floor = pipe as u64 + RECOVERY_HEADROOM_SEGS as u64 * self.mss as u64;
            target.min(bound).max(floor).max(min_cwnd)
        } else {
            // GROW toward the bounded target by what this ACK delivered — never JUMP to it. After a
            // collapse (an RTO sets cwnd to one segment) this rebuilds gradually instead of
            // re-bursting the whole BDP straight into the next loss; the inflight bound keeps the
            // rebuild from overshooting the level the path was last shown to hold.
            (self.cwnd as u64 + acked as u64).min(target.min(bound)).max(min_cwnd)
        };
        // PROBE_RTT drains to a minimal window to re-read RTprop — but NOT while a loss is being
        // repaired: forcing cwnd to min_cwnd there would drop it below `pipe` and wedge recovery (the
        // same gate closure). Defer the drain until recovery completes.
        self.cwnd = if self.mode == Mode::ProbeRtt && !in_recovery {
            cwnd.min(min_cwnd)
        } else {
            cwnd
        }
        .min(u32::MAX as u64) as u32;
    }
}

impl CongestionControl for Bbr {
    #[inline]
    fn cwnd(&self) -> u32 {
        self.cwnd
    }

    #[inline]
    fn ssthresh(&self) -> u32 {
        u32::MAX // BBR has no slow-start threshold; it is rate-, not loss-, driven
    }

    fn on_ack(&mut self, _now: Instant, _acked: u32) {
        // BBR grows the window from its model in `on_ack_sample`, not per byte acked. A forward ACK
        // only clears the dup-ACK streak.
        self.dup_acks = 0;
    }

    fn on_dup_ack(&mut self, _now: Instant, _flight_size: u32) -> bool {
        // Count duplicates to trigger fast retransmit (reliability). BBR does NOT cut its bandwidth
        // model or window here, but it does *record* the loss so the inflight bounds pull in on the
        // next sample (the BBRv2 lower-bound response) — the round is marked lost on the 3rd dup-ACK,
        // the same point a non-SACK loss episode begins.
        self.dup_acks = self.dup_acks.saturating_add(1);
        if self.dup_acks == 3 {
            self.loss_in_round = true;
            true
        } else {
            false
        }
    }

    fn enter_recovery(&mut self, _now: Instant, _flight_size: u32) {
        // SACK declared loss early (RFC 6675 IsLost). BBR keeps its bandwidth model, but records the
        // loss so the inflight bounds pull in (the rising-edge cut is applied in `on_ack_sample`).
        self.loss_in_round = true;
    }

    fn on_rto(&mut self, _now: Instant, _flight_size: u32) {
        // A timeout is the strongest loss signal BBR heeds — a hole SACK could not repair in time, the
        // wedge precursor. The in-flight timing is now meaningless, so drop the rate-sample records and
        // restart from a minimal window. The bandwidth/RTT model is kept, so pacing recovers quickly
        // once ACKs resume. Pull BOTH inflight bounds down hard (to a reno-like half of the peak in
        // flight) and ACTIVATE the long-term ceiling, so the rebuild from one segment does not climb
        // straight back into the loss that just timed out.
        self.sampler.reset_in_flight();
        self.cwnd = self.mss;
        self.dup_acks = 0;
        self.loss_in_round = true;
        let floor = self.min_cwnd();
        let half = ((self.inflight_latest.max(floor) as f64 * INFLIGHT_HARD_KEEP) as u32).max(floor);
        self.inflight_hi = if self.inflight_hi == u32::MAX { half } else { (self.inflight_hi / 2).max(floor) };
        self.inflight_lo = if self.inflight_lo == u32::MAX { half } else { (self.inflight_lo / 2).max(floor) };
    }

    fn set_mss(&mut self, mss: u16) {
        self.mss = mss as u32;
        self.cwnd = self.cwnd.max(self.min_cwnd());
    }

    fn pacing_rate(&self) -> Option<u64> {
        if self.pacing_rate == 0 {
            None
        } else {
            Some(self.pacing_rate)
        }
    }

    fn on_transmit(&mut self, now: Instant, seq_end: SeqNumber, bytes: u32, inflight: u32, app_limited: bool) {
        self.sampler.on_transmit(now, seq_end, bytes, inflight, app_limited);
    }

    fn on_ack_sample(&mut self, now: Instant, snd_una: SeqNumber, inflight: u32, acked: u32, pipe: u32, in_recovery: bool) {
        let sample = match self.sampler.on_ack(now, snd_una) {
            Some(s) => s,
            None => return, // this ACK delivered nothing new
        };

        // Round-trip accounting: a round completes when the data outstanding at its start is acked.
        if sample.prior_delivered >= self.next_round_delivered {
            self.round_count += 1;
            self.next_round_delivered = self.sampler.delivered();
            self.round_start = true;
        } else {
            self.round_start = false;
        }

        // RTprop: refresh the minimum RTT on a lower sample, or when the 10 s window has expired.
        // Compute the expiry ONCE — it also drives PROBE_RTT entry in `update_mode` below — so the
        // refresh here can't reset the stamp before the trigger reads it (the bug this replaced).
        let rtt = sample.rtt_us;
        let min_rtt_expired = self.min_rtt_us != u32::MAX
            && now.saturating_micros_since(self.min_rtt_stamp) > MIN_RTT_WINDOW_US;
        if rtt > 0 && (rtt < self.min_rtt_us || min_rtt_expired) {
            self.min_rtt_us = rtt;
            self.min_rtt_stamp = now;
        }

        // BtlBw: feed the windowed-max, skipping samples too short to be reliable and app-limited
        // samples that don't already exceed the estimate (they bound capacity from below, not above).
        if sample.delivery_rate > 0
            && sample.interval_us >= self.min_rtt_us as u64
            && (!sample.is_app_limited || sample.delivery_rate >= self.btlbw)
        {
            self.btlbw = self.btlbw_filter.update(self.round_count, sample.delivery_rate);
        }

        self.update_ack_aggregation(now, acked);

        // BBRv2 inflight bounds. Track the round's peak inflight (the level a cut shrinks from).
        self.inflight_latest = self.inflight_latest.max(inflight);
        // First SND.UNA-advancing ACK of a fresh loss episode. (Recovery is armed on a possibly
        // non-advancing dup-ACK / SACK-IsLost, but `on_ack_sample` only runs on advancing ACKs, so
        // this is the earliest sample that observes it — within a fraction of an RTT, since the
        // selective retransmit of the first hole produces an advancing ACK right away.) Trim the
        // short-term bound here and now, so the episode operates below the level that just lost. Mark
        // the round lossy so the round boundary below does not probe the bounds back up this round.
        // (The other cut sites are immediate too: `on_rto` cuts directly. So the round boundary never
        // needs to cut — it only decides whether to probe up.)
        let entered_recovery = in_recovery && !self.was_in_recovery;
        if entered_recovery {
            self.cut_inflight_bounds();
            self.loss_in_round = true;
        }
        if self.round_start {
            if !self.loss_in_round && !in_recovery {
                // Between loss episodes (not currently repairing): probe the bounds back up — the AIMD
                // additive increase, exactly like reno's congestion avoidance. NOT during recovery:
                // growing the window while a hole is being repaired injects fresh data on top of the
                // existing holes, and that extra in-flight data is what tips a lightly-lossy flow over
                // the 4-block SACK limit into the sticky one-segment-per-RTO wedge. Freezing the bound
                // during recovery (like reno freezes cwnd at ssthresh) is what keeps BBR SACK-visible.
                self.raise_inflight_bounds();
            }
            self.loss_in_round = false;
            self.inflight_latest = inflight; // reset the round's peak
        }
        self.was_in_recovery = in_recovery;

        self.update_mode(now, inflight, min_rtt_expired);
        self.set_pacing_and_cwnd(acked, pipe, in_recovery);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seq(n: u32) -> SeqNumber {
        SeqNumber::new(n)
    }

    #[test]
    fn rate_sampler_measures_delivery_rate() {
        let mut rs = RateSampler::new();
        // Send three 1000-byte segments back to back at t = 0 (the first restarts from idle).
        let t0 = Instant::from_millis(0);
        rs.on_transmit(t0, seq(1000), 1000, 0, false);
        rs.on_transmit(t0, seq(2000), 1000, 1000, false);
        rs.on_transmit(t0, seq(3000), 1000, 2000, false);
        // All three are ACKed 100 ms later: 3000 bytes delivered over 0.1 s = 30_000 bytes/s.
        let t1 = Instant::from_millis(100);
        let s = rs.on_ack(t1, seq(3000)).expect("an ACK that delivers data yields a sample");
        assert_eq!(s.delivery_rate, 30_000, "3000 bytes / 0.1 s");
        assert_eq!(s.rtt_us, 100_000, "newest delivered segment was sent at t0");
        assert!(!s.is_app_limited);
        // Nothing new on a repeat.
        assert!(rs.on_ack(t1, seq(3000)).is_none());
    }

    #[test]
    fn rate_sampler_flags_app_limited() {
        let mut rs = RateSampler::new();
        let t0 = Instant::from_millis(0);
        rs.on_transmit(t0, seq(1000), 1000, 0, true); // app ran dry
        let s = rs.on_ack(Instant::from_millis(50), seq(1000)).unwrap();
        assert!(s.is_app_limited, "a sample from app-limited data is flagged");
    }

    #[test]
    fn windowed_max_tracks_and_expires() {
        let mut w = WindowedMax::new(3); // window of 3 "rounds"
        assert_eq!(w.update(0, 100), 100);
        assert_eq!(w.update(1, 50), 100, "max holds across a dip");
        assert_eq!(w.update(2, 80), 100);
        // By round 4 the round-0 peak (100) has aged out of the 3-round window.
        assert_eq!(w.update(4, 80), 80, "the old peak expired");
        assert_eq!(w.update(5, 200), 200, "a new max takes over immediately");
    }

    /// Drive BBR through a steady 10 MB/s, 20 ms-RTT path and return it mid-STARTUP.
    fn pump_startup() -> Bbr {
        let mut b = Bbr::new(1000);
        assert_eq!(b.mode, Mode::Startup);
        assert_eq!(b.cwnd(), initial_window(1000));
        assert!(b.pacing_rate().is_none(), "unpaced until the first sample");

        // 10 MB/s = 10_000 bytes/ms; 20 ms RTT. Send a window, ack it one RTT later, repeat.
        let rtt_ms = 20u64;
        let mut t = 0u64;
        let mut nxt = 1000u32;
        let mut una = 0u32;
        for _ in 0..6 {
            // Send everything cwnd allows this round (model it as `cwnd` bytes).
            let burst = b.cwnd();
            let mut sent = 0u32;
            let inflight_before = nxt.wrapping_sub(una);
            while sent < burst {
                let n = 1000u32.min(burst - sent);
                b.on_transmit(Instant::from_millis(t), seq(nxt + n), n, inflight_before + sent, false);
                nxt = nxt.wrapping_add(n);
                sent += n;
            }
            // ACK the burst one RTT later.
            t += rtt_ms;
            una = nxt;
            b.on_ack_sample(Instant::from_millis(t), seq(una), 0, burst, 0, false);
        }
        b
    }

    #[test]
    fn bbr_startup_builds_a_model_and_paces() {
        let b = pump_startup();
        assert!(b.btlbw > 0, "bandwidth estimated");
        assert!(b.min_rtt_us <= 20_000 && b.min_rtt_us > 0, "RTprop ~20 ms, got {}", b.min_rtt_us);
        assert!(b.pacing_rate().is_some(), "paces once the model exists");
        // STARTUP pacing gain is high (≈2.885·BtlBw).
        let pr = b.pacing_rate().unwrap();
        assert!(pr as f64 >= b.btlbw as f64 * 2.0, "STARTUP paces well above BtlBw: {pr} vs {}", b.btlbw);
        assert!(b.cwnd() > initial_window(1000), "cwnd grew past the initial window");
    }

    #[test]
    fn bbr_detects_full_pipe_and_drains() {
        // A path whose bandwidth plateaus: once BtlBw stops growing 25%/round for 3 rounds, STARTUP
        // ends. Feed flat-rate rounds until the pipe is declared full.
        let mut b = Bbr::new(1000);
        let rtt_ms = 10u64;
        let mut t = 0u64;
        let mut nxt = 1000u32;
        let mut una = 0u32;
        // A fixed delivery per round caps BtlBw, so after the ramp it plateaus and STARTUP exits.
        for _ in 0..12 {
            let burst = b.cwnd().min(50_000); // cap the burst so the rate plateaus
            let inflight_before = nxt.wrapping_sub(una);
            let mut sent = 0u32;
            while sent < burst {
                let n = 1000u32.min(burst - sent);
                b.on_transmit(Instant::from_millis(t), seq(nxt + n), n, inflight_before + sent, false);
                nxt = nxt.wrapping_add(n);
                sent += n;
            }
            t += rtt_ms;
            una = nxt;
            b.on_ack_sample(Instant::from_millis(t), seq(una), 0, burst, 0, false);
            if b.mode != Mode::Startup {
                break;
            }
        }
        assert!(b.filled_pipe, "the bandwidth plateau is detected");
        assert!(matches!(b.mode, Mode::Drain | Mode::ProbeBw), "STARTUP exited, got {:?}", b.mode);
    }

    #[test]
    fn bbr_rto_shrinks_window_but_keeps_model() {
        let mut b = pump_startup();
        let bw = b.btlbw;
        assert!(bw > 0);
        b.on_rto(Instant::from_millis(1000), 8000);
        assert_eq!(b.cwnd(), b.mss, "RTO collapses the window to one segment");
        assert_eq!(b.btlbw, bw, "but the bandwidth model is kept, so pacing recovers");
    }

    #[test]
    fn bbr_does_not_cut_window_on_dup_acks() {
        let mut b = pump_startup();
        let cwnd_before = b.cwnd();
        assert!(!b.on_dup_ack(Instant::from_millis(500), 8000));
        assert!(!b.on_dup_ack(Instant::from_millis(500), 8000));
        assert!(b.on_dup_ack(Instant::from_millis(500), 8000), "3rd dup-ACK still triggers retransmit");
        assert_eq!(b.cwnd(), cwnd_before, "but BBR does not reduce its window on dup-ACKs");
    }

    #[test]
    fn bbr_enters_probe_rtt_after_the_min_rtt_window() {
        // Regression (review finding): on a steady path the min-RTT refresh used to consume the same
        // staleness signal the PROBE_RTT trigger needed, so PROBE_RTT was never entered and RTprop
        // was never re-probed. Drive a constant-RTT path well past the 10 s window and require that
        // PROBE_RTT is reached at least once.
        let mut b = Bbr::new(1000);
        let rtt_ms = 20u64;
        let mut t = 0u64;
        let mut nxt = 1000u32;
        let mut una = 0u32;
        let mut saw_probe_rtt = false;
        for _ in 0..700 {
            // 700 rounds * 20 ms = 14 s > MIN_RTT_WINDOW_US (10 s).
            let burst = b.cwnd().min(60_000);
            let inflight_before = nxt.wrapping_sub(una);
            let mut sent = 0u32;
            while sent < burst {
                let n = 1000u32.min(burst - sent);
                b.on_transmit(Instant::from_millis(t), seq(nxt + n), n, inflight_before + sent, false);
                nxt = nxt.wrapping_add(n);
                sent += n;
            }
            t += rtt_ms;
            una = nxt;
            b.on_ack_sample(Instant::from_millis(t), seq(una), 0, burst, 0, false);
            saw_probe_rtt |= b.mode == Mode::ProbeRtt;
        }
        assert!(saw_probe_rtt, "PROBE_RTT is entered once the min-RTT window expires on a steady path");
    }

    #[test]
    fn bbr_recovery_window_is_pipe_floored_and_inflight_bounded() {
        // BBRv2-style loss response, with the adaptive inflight bound. While a loss is being repaired
        // (`in_recovery`), BBR caps total inflight by `inflight_lo`/`inflight_hi` instead of refilling
        // the whole BDP — but the window is FLOORED at `pipe + 3·MSS`, the hard invariant: cwnd must
        // stay > pipe so the selective retransmit always fires, even when pipe is large.
        let mut b = pump_startup(); // an established model (btlbw > 0, min-RTT set)
        let full = b.cwnd();
        let mss = b.mss;
        assert!(full > 40_000, "post-startup cwnd is well above one segment, got {full}");
        // Recovery entry with 40 KiB in flight: the rising-edge cut sets inflight_lo ≈ 0.7·40 KiB,
        // so cwnd is bounded near there — well ABOVE the old fixed `pipe + 3·MSS`, the throughput win,
        // yet still far below the un-throttled BDP target.
        b.on_transmit(Instant::from_millis(500), seq(2_000_000), 1000, 40_000, false);
        b.on_ack_sample(Instant::from_millis(520), seq(2_000_000), 40_000, 1000, 10_000, true);
        assert!(b.cwnd() > 10_000, "cwnd stays ABOVE pipe so the retransmit can fire");
        assert!(
            b.cwnd() > 10_000 + RECOVERY_HEADROOM_SEGS * mss,
            "the adaptive headroom now exceeds the old fixed 3·MSS floor, got {}",
            b.cwnd()
        );
        assert!(b.cwnd() <= 40_000, "but capped by the inflight bound (≈0.7·40 KiB), got {}", b.cwnd());
        assert!(b.cwnd() < full, "and below the un-throttled BDP target ({full})");
        // A LARGE pipe (recovery entry, little SACKed): cwnd must STILL exceed pipe, not collapse to
        // the BDP target or the inflight bound below it (the wedge bug the review caught twice).
        b.on_transmit(Instant::from_millis(540), seq(3_000_000), 1000, 40_000, false);
        b.on_ack_sample(Instant::from_millis(560), seq(3_000_000), 40_000, 1000, 200_000, true);
        assert!(b.cwnd() > 200_000, "cwnd > pipe even when pipe exceeds the BDP target, got {}", b.cwnd());
    }

    #[test]
    fn bbr_inflight_bounds_inactive_without_loss() {
        // The whole inflight-bound machinery must stay dormant on a clean path: with no loss signal
        // ever, both bounds stay at MAX (the `bound` is then non-binding), so the 0 %-loss window
        // computation is the pure model target — unchanged from before this feature.
        let b = pump_startup();
        assert_eq!(b.inflight_hi, u32::MAX, "no loss ⇒ the long-term ceiling never activates");
        assert_eq!(b.inflight_lo, u32::MAX, "no loss ⇒ the short-term bound never activates");
        assert!(!b.was_in_recovery, "no recovery was ever entered");
    }

    #[test]
    fn bbr_inflight_bounds_aimd_cut_then_probe_up() {
        // The AIMD dynamics in isolation: the FIRST loss activates inflight_lo at a reno-like half of
        // the peak inflight; subsequent non-loss rounds probe it back up additively. This is the
        // equilibrium-finder that lets a lightly-lossy path reclaim headroom while loss keeps it tight.
        let mut b = pump_startup();
        // Force the inflight peak this round, then signal a loss episode (rising edge of recovery).
        b.inflight_latest = 60_000;
        b.on_transmit(Instant::from_millis(600), seq(4_000_000), 1000, 60_000, false);
        b.on_ack_sample(Instant::from_millis(620), seq(4_000_000), 60_000, 1000, 30_000, true);
        let after_cut = b.inflight_lo;
        assert!(after_cut != u32::MAX, "the loss activated the short-term bound");
        assert_eq!(after_cut, 30_000, "first activation drops to a reno-like half of the 60 KiB peak");
        // Now feed clean, non-recovery rounds; each round boundary probes inflight_lo up by one MSS.
        let mut t = 700u64;
        let mut nxt = 4_000_000u32;
        let mut una = 4_000_000u32;
        let mut raised = false;
        for _ in 0..40 {
            let burst = 8000u32;
            let inflight_before = nxt.wrapping_sub(una);
            let mut sent = 0u32;
            while sent < burst {
                let n = 1000u32.min(burst - sent);
                b.on_transmit(Instant::from_millis(t), seq(nxt + n), n, inflight_before + sent, false);
                nxt = nxt.wrapping_add(n);
                sent += n;
            }
            t += 20;
            una = nxt;
            b.on_ack_sample(Instant::from_millis(t), seq(una), 0, burst, 0, false);
            if b.inflight_lo == u32::MAX || b.inflight_lo > after_cut {
                raised = true; // grew back (or was released once it overtook the ceiling)
                break;
            }
        }
        assert!(raised, "clean rounds probe the short-term bound back up (additive increase)");
    }

    #[test]
    fn bbr_under_steady_loss_holds_invariant_and_keeps_headroom() {
        // The end-to-end property the VPS bench measures, at the controller level: under a stream of
        // loss episodes BBR must (a) NEVER drop cwnd to or below pipe (the invariant — else recovery
        // wedges into one-seg-per-RTO go-back-N), and (b) keep meaningful headroom for new data
        // (more than the old fixed 3·MSS once the path proves it can hold it), while the bounds stay
        // bounded (no runaway). We simulate a 1 %-ish loss path: each episode repairs a small pipe
        // (most data SACKed) then briefly cruises clean.
        let mut b = pump_startup();
        let mss = b.mss;
        let mut t = 1000u64;
        let mut seqn = 5_000_000u32;
        let mut headroom_seen_above_floor = false;
        for episode in 0..30 {
            // A handful of in-recovery ACKs (pipe well below inflight: the holes are being drained).
            for k in 0..4 {
                let pipe = 12_000u32; // small pipe: most outstanding data already SACKed
                let inflight = 80_000u32; // a near-BDP window outstanding
                b.on_transmit(Instant::from_millis(t), seq(seqn + 1000), 1000, inflight, false);
                seqn = seqn.wrapping_add(1000);
                t += 5;
                b.on_ack_sample(Instant::from_millis(t), seq(seqn), inflight, 1000, pipe, true);
                assert!(
                    b.cwnd() > pipe,
                    "invariant: cwnd ({}) must stay > pipe ({pipe}) [episode {episode}, ack {k}]",
                    b.cwnd()
                );
                if b.cwnd() > pipe + RECOVERY_HEADROOM_SEGS * mss {
                    headroom_seen_above_floor = true;
                }
            }
            // A short clean stretch (recovery completed), so the bounds probe back up between losses.
            for _ in 0..3 {
                b.on_transmit(Instant::from_millis(t), seq(seqn + 1000), 1000, 12_000, false);
                seqn = seqn.wrapping_add(1000);
                t += 20;
                b.on_ack_sample(Instant::from_millis(t), seq(seqn), 12_000, 1000, 12_000, false);
            }
            // The bounds never collapse below a sendable window nor run away above the model.
            if b.inflight_lo != u32::MAX {
                assert!(b.inflight_lo >= b.min_cwnd(), "inflight_lo never collapses below min_cwnd");
            }
            if b.inflight_hi != u32::MAX {
                assert!(b.inflight_hi >= b.min_cwnd(), "inflight_hi never collapses below min_cwnd");
            }
        }
        assert!(
            headroom_seen_above_floor,
            "under light loss the adaptive headroom exceeds the fixed 3·MSS floor (the throughput win)"
        );
    }

    #[test]
    fn bbr_ack_aggregation_credits_extra_acked() {
        // A burst of ACKs that delivers more than the bottleneck rate predicts within an epoch must
        // register as `extra_acked` (capped at the BDP), the slack added to the cwnd target so the
        // pipe is not starved by stretched/aggregated ACKs. Drive the estimator directly with a known
        // model: 1 MB/s over a 20 ms RTT ⇒ a 20 000-byte BDP.
        let mut b = Bbr::new(1000);
        b.btlbw = 1_000_000;
        b.min_rtt_us = 20_000;
        // Prime the aggregation epoch (the first ACK of an epoch always credits its own size).
        b.update_ack_aggregation(Instant::from_millis(0), 1000);
        let baseline = b.extra_acked;
        // A large lump within the same epoch (no time elapsed): cumulative acked jumps while the
        // expected (rate·elapsed) barely moves, so the excess spikes — clamped to the BDP.
        b.update_ack_aggregation(Instant::from_millis(0), 30_000);
        assert!(b.extra_acked > baseline, "a super-rate ACK burst raises extra_acked, got {}", b.extra_acked);
        assert!(b.extra_acked <= 20_000, "but the credit is capped at the BDP, got {}", b.extra_acked);
    }

    #[test]
    fn bbr_ack_aggregation_gated_until_pipe_full() {
        // The measured aggregation must NOT inflate the window during STARTUP (where the doubling
        // delivery rate itself reads as "aggregation"); upstream BBR applies it only once the pipe is
        // full. After a short STARTUP pump the estimator has fired but the pipe is not yet declared
        // full, so the slack stays out of the target.
        let b = pump_startup();
        assert!(b.extra_acked > 0, "the STARTUP ramp registers ACK aggregation, got {}", b.extra_acked);
        assert!(!b.filled_pipe, "the pipe is not declared full yet, so the slack is gated out");
    }
}

