//! Pluggable TCP congestion control.
//!
//! The TCB drives congestion control through the [`CongestionControl`] trait and holds one concrete
//! controller in the [`Cc`] enum — **match-dispatched, not `Box<dyn>`**, so the hot send path stays
//! zero-allocation and sans-IO (no vtable, no heap). Today the only controller is [`Reno`] (RFC 5681,
//! with the RFC 6928 initial window); CUBIC and BBR slot in as additional [`Cc`] variants without
//! touching the TCB's call sites — which is the whole point of the seam, since the research value
//! is the Reno-vs-CUBIC-vs-BBR comparison.
//!
//! Every event method takes the current [`Instant`]. A time-based controller needs the clock —
//! CUBIC's window grows as a cubic function of the time since the last loss, and BBR paces to a
//! bottleneck-bandwidth/min-RTT model — while Reno is purely ACK-clocked and ignores it. Threading
//! `now` through the trait up front keeps those controllers a pure addition rather than a
//! signature change rippling across every TCB call site.
//!
//! Everything is in **bytes**. The verified Reno subtleties (see `docs/DESIGN.md` `congestion/*`):
//!
//! - Congestion avoidance counts **bytes acknowledged** with a `while` loop, not `+= MSS` per
//!   ACK — the latter under-grows under delayed/stretch ACKs and multi-segment recovery ACKs.
//! - On loss, `ssthresh = max(FlightSize/2, 2·MSS)` from the *passed* FlightSize, never `cwnd`
//!   (which may be far larger than what is truly in flight if the connection was rwnd-limited).
//! - On a triple-duplicate-ACK, **fast recovery** sets `cwnd = ssthresh` (halved) rather than
//!   collapsing to one segment — so the pipe stays full enough to keep recovering subsequent
//!   losses by fast retransmit (one RTT) instead of the slow RTO path. Only a real RTO (the
//!   stronger loss signal) collapses to `cwnd = 1·MSS` and restarts slow start. (The earlier
//!   Tahoe build collapsed to 1 on *both*, which made loss recovery pathological on a fast path.)
//! - The send gate is `min(cwnd, rwnd) − FlightSize`; the FlightSize subtraction uses wrapping
//!   sequence arithmetic (tested in `crate::seq`). The zero-window probe bypasses `cwnd`.

use crate::bbr::Bbr;
use crate::seq::SeqNumber;
use crate::time::Instant;

/// RFC 6928 initial window: `min(10·MSS, max(2·MSS, 14600))`.
pub fn initial_window(mss: u32) -> u32 {
    (10 * mss).min((2 * mss).max(14600))
}

/// CUBIC scaling constant `C` (RFC 8312 §4.1), in segments·s⁻³.
const CUBIC_C: f64 = 0.4;
/// CUBIC multiplicative-decrease factor `β` (RFC 8312 §4.5): cwnd drops to `β·cwnd` on loss — a
/// gentler cut than Reno's 0.5, which is what lets CUBIC hold a higher average window.
const CUBIC_BETA: f64 = 0.7;

/// A cube root by Newton's method using **only** the basic float ops (`+ − × ÷`), never the
/// `f64::cbrt` intrinsic — so the controller is deterministic and clean under Miri. It runs once
/// per loss event (to compute the cubic inflection `K`), so the fixed iteration count costs
/// nothing on the data path. Returns 0 for non-positive input.
fn cubic_root(a: f64) -> f64 {
    if a <= 0.0 {
        return 0.0;
    }
    // Start at or above the true root so the iteration converges monotonically downward: for
    // `a ≥ 1` the root is ≤ a; for `a < 1` the root is < 1 ≤ the start. 60 iterations is far past
    // f64 convergence for any window-sized argument (quadratic convergence near the root).
    let mut x = if a >= 1.0 { a } else { 1.0 };
    for _ in 0..60 {
        x = (2.0 * x + a / (x * x)) / 3.0;
    }
    x
}

/// The CUBIC window in **segments** at `t` seconds into the current epoch:
/// `W_cubic(t) = C·(t − K)³ + origin` (RFC 8312 eq. 1). We evaluate at `t`, not the RFC's
/// `t + RTT`: omitting the one-RTT look-ahead makes growth a touch less aggressive across the
/// curve (most visibly in the convex probing region above W_max), and the TCP-friendly region
/// provides the growth floor. The cube is written out (not
/// `powi`, which is an intrinsic) so a negative `t − K` — the concave region below W_max — keeps
/// its sign and pulls the window *below* the origin as the RFC intends.
fn cubic_window(origin_seg: f64, k: f64, t: f64) -> f64 {
    let d = t - k;
    origin_seg + CUBIC_C * d * d * d
}

/// The congestion-control contract the TCB drives. An implementor tracks a congestion window
/// (`cwnd`) and slow-start threshold (`ssthresh`) in **bytes** and reacts to the four signals the
/// TCB feeds it: new data acknowledged, a duplicate ACK, an explicit early loss declaration (RFC
/// 6675 `IsLost`, from SACK, before three dup-ACKs), and a retransmission timeout.
///
/// `now` is the current monotonic clock. Reno (purely ACK-clocked) ignores it; a time-based
/// controller (CUBIC/BBR) reads it. `new` is intentionally **not** a trait method — each controller
/// has its own constructor and the TCB rebuilds its [`Cc`] when it learns the negotiated MSS.
pub trait CongestionControl {
    /// The congestion window in bytes — the cap on bytes in flight the TCB enforces.
    fn cwnd(&self) -> u32;
    /// The slow-start threshold in bytes (below it: slow start; at or above: congestion avoidance).
    fn ssthresh(&self) -> u32;
    /// New data (`acked` bytes) was cumulatively acknowledged: reset dup-ACK state and grow `cwnd`.
    fn on_ack(&mut self, now: Instant, acked: u32);
    /// A duplicate ACK arrived (`flight_size` = bytes in flight). Returns `true` on exactly the
    /// third, when the caller must fast-retransmit and the window has just been reduced.
    fn on_dup_ack(&mut self, now: Instant, flight_size: u32) -> bool;
    /// Enter fast recovery directly from an early SACK-based loss declaration (RFC 6675 `IsLost`),
    /// before three duplicate ACKs. Applies the same FlightSize-based reduction the third dup-ACK
    /// would, and resets dup-ACK state so the threshold cannot fire a second reduction.
    fn enter_recovery(&mut self, now: Instant, flight_size: u32);
    /// The retransmission timer fired — the strongest loss signal. Collapse to one segment and
    /// restart slow start.
    fn on_rto(&mut self, now: Instant, flight_size: u32);
    /// Update the maximum segment size (e.g. once the handshake learns the peer's MSS); never let
    /// `cwnd` drop below one new segment.
    fn set_mss(&mut self, mss: u16);

    // ── rate-based control (BBR) ────────────────────────────────────────────────────────────────
    // These have no-op defaults so a window-only controller (Reno, CUBIC) is unaffected and the
    // TCB's send path stays byte-identical for them: `pacing_rate` returns `None` (unpaced), and
    // the sampling hooks do nothing. A model-based controller overrides them.

    /// The pacing rate in **bytes/second**, or `None` for a window-only controller that sends as
    /// fast as `cwnd` allows. A rate-based controller (BBR) returns the rate the tx path should
    /// space its sends at; `None` until it has measured enough to pace.
    fn pacing_rate(&self) -> Option<u64> {
        None
    }

    /// Record that `bytes` of **new** data ending at `seq_end` were transmitted at `now`, with
    /// `inflight` bytes outstanding *before* this send, and whether the send was application-limited
    /// (the app ran out of data while the window still had room). Feeds a rate-based controller's
    /// delivery-rate estimator; retransmissions are not reported here.
    fn on_transmit(&mut self, _now: Instant, _seq_end: SeqNumber, _bytes: u32, _inflight: u32, _app_limited: bool) {}

    /// An ACK advanced the cumulative acknowledgement to `snd_una`. `inflight` is the bytes still
    /// outstanding after it, `acked` the bytes this ACK newly delivered, `pipe` the RFC 6675
    /// in-flight estimate (≤ `inflight`, discounting SACKed data), and `in_recovery` whether a loss
    /// is currently being repaired. A rate-based controller produces a delivery-rate sample and
    /// updates its model here, growing its window by `acked` toward the model rather than jumping —
    /// and, while `in_recovery`, holding the window near `pipe` (a BBRv2-style loss response) so it
    /// stops overshooting into the loss. Runs on every advancing ACK, including during recovery.
    fn on_ack_sample(&mut self, _now: Instant, _snd_una: SeqNumber, _inflight: u32, _acked: u32, _pipe: u32, _in_recovery: bool) {}

    // ── ECN / L4S (DCTCP) ─────────────────────────────────────────────────────────────────────────

    /// An ACK delivered `acked` bytes, of which `marked` (≤ `acked`) were ECN-CE-marked — the
    /// receiver echoed them via the TCP ECE flag (RFC 3168/8257). DCTCP accumulates the marked
    /// *fraction* over a window into a smoothed estimate `α` and gently cuts `cwnd ×= 1 − α/2` once
    /// per window that saw any mark, holding a far shallower queue than a loss-based controller. The
    /// no-op default means Reno/CUBIC/BBR ignore the ECN signal and stay byte-identical — exactly as
    /// they do today, since the TCB only ever passes `marked > 0` on a DCTCP (ECN-enabled) connection.
    fn on_ecn(&mut self, _now: Instant, _acked: u32, _marked: u32) {}

    /// The smoothed round-trip time (µs) was updated. A delay/RTT-aware controller (TCP Prague) reads
    /// it to make its additive increase **RTT-independent**; the no-op default leaves every window-only
    /// controller — and the ACK-clocked ones — byte-identical. The TCB calls this once a measurement
    /// exists, on each advancing ACK; the controller applies it on its next additive-increase step (a
    /// one-ACK lag on a slowly-smoothed value, immaterial to the per-round window growth).
    fn on_rtt_sample(&mut self, _srtt_us: u32) {}
}

#[derive(Clone)]
pub struct Reno {
    cwnd: u32,
    ssthresh: u32,
    mss: u32,
    /// Bytes-acked accumulator for the congestion-avoidance `+1 MSS / RTT` rule.
    ca_acc: u32,
    dup_acks: u8,
}

impl Reno {
    pub fn new(mss: u16) -> Self {
        let mss = mss as u32;
        Reno {
            cwnd: initial_window(mss),
            ssthresh: u32::MAX, // effectively infinite: slow start until the first loss
            mss,
            ca_acc: 0,
            dup_acks: 0,
        }
    }

    #[inline]
    fn in_slow_start(&self) -> bool {
        self.cwnd < self.ssthresh
    }
}

impl CongestionControl for Reno {
    #[inline]
    fn cwnd(&self) -> u32 {
        self.cwnd
    }

    #[inline]
    fn ssthresh(&self) -> u32 {
        self.ssthresh
    }

    /// New data (`acked` bytes) was acknowledged: reset the dup-ACK counter and grow `cwnd`. Reno
    /// is ACK-clocked, so the clock is unused.
    fn on_ack(&mut self, _now: Instant, acked: u32) {
        self.dup_acks = 0;
        if acked == 0 {
            return;
        }
        if self.in_slow_start() {
            // Exponential: +1 MSS per ACK (capped at one MSS of growth, RFC 5681 default).
            self.cwnd = self.cwnd.saturating_add(acked.min(self.mss));
        } else {
            // Linear: +1 MSS per cwnd worth of acknowledged bytes. The `while` loop credits a
            // multi-segment cumulative ACK correctly.
            self.ca_acc = self.ca_acc.saturating_add(acked);
            while self.ca_acc >= self.cwnd {
                self.ca_acc -= self.cwnd;
                self.cwnd = self.cwnd.saturating_add(self.mss);
            }
        }
    }

    /// A duplicate ACK arrived (`flight_size` = bytes in flight). Returns `true` on exactly the
    /// third, when the caller must fast-retransmit.
    fn on_dup_ack(&mut self, _now: Instant, flight_size: u32) -> bool {
        self.dup_acks = self.dup_acks.saturating_add(1);
        if self.dup_acks == 3 {
            // Fast retransmit + fast recovery (Reno): halve the window, but do NOT collapse to
            // one segment. Keeping the pipe partly full means subsequent losses still generate
            // duplicate ACKs and recover via fast retransmit (one RTT) instead of falling onto
            // the slow RTO path — which is what made loss recovery pathological under Reno.
            self.ssthresh = (flight_size / 2).max(2 * self.mss);
            self.cwnd = self.ssthresh;
            self.ca_acc = 0;
            true
        } else {
            false
        }
    }

    /// Enter fast recovery directly (used when RFC 6675 `IsLost` declares loss from SACK
    /// information *before* the third duplicate ACK). Applies the same FlightSize-based window
    /// reduction as the `dup_acks == 3` branch of [`Reno::on_dup_ack`] — `cwnd = ssthresh =
    /// max(FlightSize/2, 2·MSS)` — and resets the dup-ACK counter so the internal threshold does
    /// not fire a second halving. Idempotent given the caller's "not already in recovery" guard.
    fn enter_recovery(&mut self, _now: Instant, flight_size: u32) {
        self.ssthresh = (flight_size / 2).max(2 * self.mss);
        self.cwnd = self.ssthresh;
        self.ca_acc = 0;
        self.dup_acks = 0;
    }

    /// The retransmission timer fired — a much stronger loss signal than dup-ACKs. Collapse to
    /// one segment and restart slow start.
    fn on_rto(&mut self, _now: Instant, flight_size: u32) {
        self.ssthresh = (flight_size / 2).max(2 * self.mss);
        self.cwnd = self.mss;
        self.ca_acc = 0;
    }

    /// Update the maximum segment size (e.g. after path-MTU discovery); never let `cwnd` drop
    /// below one new segment, and discard the now-stale CA accumulator.
    fn set_mss(&mut self, mss: u16) {
        self.mss = mss as u32;
        self.cwnd = self.cwnd.max(self.mss);
        self.ca_acc = 0;
    }
}

/// TCP CUBIC (RFC 8312) — the Linux default. Where Reno's window is a sawtooth driven purely by
/// ACKs, CUBIC grows its window as a **cubic function of the time since the last loss**: concave
/// (cautious) as it climbs back toward the window it lost (`W_max`), then convex (aggressive) as it
/// probes past it for new capacity. That time dependence is why every event takes `now`.
///
/// Everything is in **bytes** at the boundary (`cwnd`/`ssthresh`), but the cubic curve is naturally
/// expressed in **segments**, so the internal state below is segment-denominated `f64`. The growth
/// is clocked the way Linux's `tcp_cubic` does it: each ACK computes `cnt`, the number of ACKed
/// segments needed to grow the window by one segment, and an accumulator releases one MSS each time
/// it is reached. A **TCP-friendly region** (RFC 8312 §4.3) floors the rate at a Reno-using-β AIMD
/// so CUBIC never loses to standard TCP on low-bandwidth-delay paths.
///
/// Two deliberate departures from the letter of the RFC / Linux: the window is evaluated at `t`,
/// not `t + RTT` (the one-RTT look-ahead is dropped — see `cubic_window` — so CUBIC needs nothing
/// from the controller interface beyond `now`; Reno needs nothing and BBR will grow the interface
/// later), and `cnt` is floored at 1 (never faster than slow start) rather than Linux's 2. The
/// cubic shape, the β = 0.7 multiplicative decrease, fast convergence, and the TCP-friendly floor
/// are all present.
pub struct Cubic {
    cwnd: u32,
    ssthresh: u32,
    mss: u32,
    /// Segments: the window at the last loss (after fast convergence) — the cubic curve's target.
    w_max: f64,
    /// Segments: the previous `w_max`, used to detect a capacity drop for fast convergence.
    w_last_max: f64,
    /// Start of the current congestion-avoidance epoch; `None` until the first growing ACK after a
    /// loss re-anchors the curve.
    epoch_start: Option<Instant>,
    /// Seconds from the epoch start to reach `w_max` (the cubic inflection `K`, RFC 8312 eq. 2).
    cubic_k: f64,
    /// Segments: the cubic curve's origin point (`max(cwnd, w_max)` at epoch start).
    cubic_origin: f64,
    /// Segments: the TCP-friendly (Reno-with-β) window estimate, tracked incrementally.
    w_tcp: f64,
    /// Segments acked this epoch, feeding the `w_tcp` increment.
    ack_cnt: f64,
    /// Segments acked toward the next one-MSS `cwnd` increment.
    cwnd_cnt: f64,
    dup_acks: u8,
}

impl Cubic {
    pub fn new(mss: u16) -> Self {
        let mss = mss as u32;
        Cubic {
            cwnd: initial_window(mss),
            ssthresh: u32::MAX, // slow start until the first loss (identical to Reno here)
            mss,
            w_max: 0.0,
            w_last_max: 0.0,
            epoch_start: None,
            cubic_k: 0.0,
            cubic_origin: 0.0,
            w_tcp: 0.0,
            ack_cnt: 0.0,
            cwnd_cnt: 0.0,
            dup_acks: 0,
        }
    }

    /// A congestion event (3rd dup-ACK, early SACK loss, or RTO): record `W_max` with fast
    /// convergence, cut the window by β, and reset the cubic epoch. `is_rto` collapses to one
    /// segment and restarts slow start (the stronger loss signal); otherwise the window drops to
    /// `ssthresh` for fast recovery. Uses the controller's own `cwnd` as `W_max` (RFC 8312), so the
    /// `flight_size` the trait passes is unused here.
    fn congestion_event(&mut self, is_rto: bool) {
        let cwnd_seg = self.cwnd as f64 / self.mss as f64;
        // Fast convergence (RFC 8312 §4.6): if this loss is below the previous W_max, capacity has
        // dropped, so pull W_max in further to release bandwidth to the flows that displaced us.
        if cwnd_seg < self.w_last_max {
            self.w_last_max = cwnd_seg;
            self.w_max = cwnd_seg * (1.0 + CUBIC_BETA) / 2.0;
        } else {
            self.w_last_max = cwnd_seg;
            self.w_max = cwnd_seg;
        }
        self.ssthresh = ((self.cwnd as f64 * CUBIC_BETA) as u32).max(2 * self.mss);
        self.cwnd = if is_rto { self.mss } else { self.ssthresh };
        self.epoch_start = None; // re-anchor the curve on the next growing ACK
        self.ack_cnt = 0.0;
        self.cwnd_cnt = 0.0;
    }

    /// Congestion-avoidance window update along the cubic curve (RFC 8312 §4.1–4.3), called per ACK
    /// once `cwnd ≥ ssthresh`.
    fn cubic_update(&mut self, now: Instant, acked: u32) {
        let mss_f = self.mss as f64;
        let acked_seg = acked as f64 / mss_f;
        let cwnd_seg = self.cwnd as f64 / mss_f;

        match self.epoch_start {
            None => {
                // First ACK of a fresh epoch: anchor the cubic curve at the current window.
                self.epoch_start = Some(now);
                self.ack_cnt = acked_seg;
                self.cwnd_cnt = 0.0;
                self.w_tcp = cwnd_seg;
                if cwnd_seg < self.w_max {
                    // Concave region: aim back up at the prior W_max over `K` seconds.
                    self.cubic_k = cubic_root((self.w_max - cwnd_seg) / CUBIC_C);
                    self.cubic_origin = self.w_max;
                } else {
                    // Already at/above W_max: convex probing starts here and now.
                    self.cubic_k = 0.0;
                    self.cubic_origin = cwnd_seg;
                }
            }
            Some(_) => self.ack_cnt += acked_seg,
        }

        let t = now.saturating_micros_since(self.epoch_start.unwrap()) as f64 / 1_000_000.0;
        let target = cubic_window(self.cubic_origin, self.cubic_k, t);

        // `cnt` = ACKed segments per one-segment cwnd increase along the cubic curve. When the
        // curve is at/below cwnd (just after a loss, near `t = 0`), there is no cubic growth — the
        // TCP-friendly floor below takes over — so park `cnt` at a large value.
        let mut cnt = if target > cwnd_seg {
            cwnd_seg / (target - cwnd_seg)
        } else {
            100.0 * cwnd_seg
        };

        // TCP-friendly region (RFC 8312 §4.3): never grow slower than a Reno using the same β, so
        // CUBIC stays at least as aggressive as standard TCP on low-BDP paths. `w_tcp` tracks that
        // AIMD estimate incrementally — it gains one segment every `cwnd / α` acked segments, where
        // α = 3(1−β)/(1+β) — needing no RTT. If it overtakes cwnd, it tightens `cnt` to match.
        let alpha = 3.0 * (1.0 - CUBIC_BETA) / (1.0 + CUBIC_BETA);
        let delta = cwnd_seg / alpha;
        if delta > 0.0 {
            while self.ack_cnt > delta {
                self.ack_cnt -= delta;
                self.w_tcp += 1.0;
            }
        }
        if self.w_tcp > cwnd_seg {
            let tcp_cnt = cwnd_seg / (self.w_tcp - cwnd_seg);
            if tcp_cnt < cnt {
                cnt = tcp_cnt;
            }
        }
        if cnt < 1.0 {
            cnt = 1.0; // never grow faster than one segment per ACKed segment
        }

        // Release one MSS for every `cnt` ACKed segments.
        self.cwnd_cnt += acked_seg;
        while self.cwnd_cnt >= cnt {
            self.cwnd_cnt -= cnt;
            self.cwnd = self.cwnd.saturating_add(self.mss);
        }
    }
}

impl CongestionControl for Cubic {
    #[inline]
    fn cwnd(&self) -> u32 {
        self.cwnd
    }

    #[inline]
    fn ssthresh(&self) -> u32 {
        self.ssthresh
    }

    fn on_ack(&mut self, now: Instant, acked: u32) {
        self.dup_acks = 0;
        if acked == 0 {
            // A non-advancing or FIN-only ACK / the recovery-exit reset: clear dup-ACK state, but
            // neither grow the window nor advance the cubic epoch.
            return;
        }
        if self.cwnd < self.ssthresh {
            // Standard slow start (identical to Reno): exponential, capped at +1 MSS per ACK.
            self.cwnd = self.cwnd.saturating_add(acked.min(self.mss));
        } else {
            self.cubic_update(now, acked);
        }
    }

    fn on_dup_ack(&mut self, _now: Instant, _flight_size: u32) -> bool {
        self.dup_acks = self.dup_acks.saturating_add(1);
        if self.dup_acks == 3 {
            self.congestion_event(false);
            true
        } else {
            false
        }
    }

    fn enter_recovery(&mut self, _now: Instant, _flight_size: u32) {
        self.congestion_event(false);
        self.dup_acks = 0;
    }

    fn on_rto(&mut self, _now: Instant, _flight_size: u32) {
        self.congestion_event(true);
    }

    fn set_mss(&mut self, mss: u16) {
        // Not used in production (the TCB rebuilds the controller when it learns the MSS); kept for
        // contract parity with Reno. Segment-denominated state re-derives on the next epoch.
        self.mss = mss as u32;
        self.cwnd = self.cwnd.max(self.mss);
    }
}

/// DCTCP smoothing weight `g` for the marked-fraction EWMA (RFC 8257 §3.3 recommends `1/16`). A
/// small `g` means `α` reacts slowly, filtering per-window noise so the window cut tracks the
/// *persistent* level of congestion rather than a single marked round.
const DCTCP_G: f64 = 1.0 / 16.0;

/// Data Center TCP (RFC 8257) — the L4S-style controller. It behaves like Reno for additive
/// increase and for genuine packet loss (3 dup-ACKs / RTO), but reacts to **ECN** completely
/// differently: instead of a one-bit "congested?" signal that forces a halving, it reads the
/// *fraction* of bytes a CE-marking bottleneck flagged and cuts the window in proportion to it.
///
/// The receiver echoes each CE mark as TCP ECE; the TCB feeds those marks in via [`CongestionControl
/// ::on_ecn`]. DCTCP accumulates `marked / acked` over roughly one window of data (≈ one RTT — the
/// trait carries no sequence space, so a byte counter snapshotting `cwnd` stands in for the round),
/// folds it into a smoothed estimate `α ∈ [0, 1]` (`α ← (1−g)·α + g·fraction`), and, on any window
/// that saw a mark, applies `cwnd ← max(MSS, cwnd·(1 − α/2))` once. Lightly-marked traffic (small
/// `α`) is barely cut, so the flow holds a high window at a **sub-millisecond** standing queue;
/// heavy marking (`α → 1`) degrades to a Reno-style halving. `α` starts at 1.0 so the first reaction
/// is conservative until the EWMA learns the true marking level (RFC 8257 §3.3).
///
/// Everything is in **bytes** at the boundary; `α` is the only `f64`, updated with `+ − × ÷` alone
/// (no transcendental intrinsics), so the controller is deterministic and Miri-clean like CUBIC/BBR.
#[derive(Clone)]
pub struct Dctcp {
    cwnd: u32,
    ssthresh: u32,
    mss: u32,
    /// Bytes-acked accumulator for the Reno `+1 MSS / RTT` additive increase.
    ca_acc: u32,
    dup_acks: u8,
    /// Smoothed fraction of bytes marked CE, in `[0, 1]` (RFC 8257 `α`).
    alpha: f64,
    /// Bytes acked / bytes acked-and-marked since the current observation window opened.
    acked_in_window: u32,
    marked_in_window: u32,
    /// Bytes that must be acknowledged to close the window and refresh `α` — a snapshot of `cwnd`
    /// taken when the window opened, so one window ≈ one round-trip of data on a bulk flow.
    window_bytes: u32,
}

impl Dctcp {
    pub fn new(mss: u16) -> Self {
        let mss = mss as u32;
        Dctcp {
            cwnd: initial_window(mss),
            ssthresh: u32::MAX, // slow start until the first loss (identical to Reno)
            mss,
            ca_acc: 0,
            dup_acks: 0,
            alpha: 1.0, // conservative until the EWMA learns the real marking level (RFC 8257 §3.3)
            acked_in_window: 0,
            marked_in_window: 0,
            window_bytes: initial_window(mss),
        }
    }

    #[inline]
    fn in_slow_start(&self) -> bool {
        self.cwnd < self.ssthresh
    }
}

impl CongestionControl for Dctcp {
    #[inline]
    fn cwnd(&self) -> u32 {
        self.cwnd
    }

    #[inline]
    fn ssthresh(&self) -> u32 {
        self.ssthresh
    }

    /// Additive increase, identical to Reno: exponential in slow start (capped at +1 MSS/ACK),
    /// then +1 MSS per cwnd worth of acked bytes in congestion avoidance. The ECN reaction is
    /// separate ([`Dctcp::on_ecn`]); here DCTCP simply grows.
    fn on_ack(&mut self, _now: Instant, acked: u32) {
        self.dup_acks = 0;
        if acked == 0 {
            return;
        }
        if self.in_slow_start() {
            self.cwnd = self.cwnd.saturating_add(acked.min(self.mss));
        } else {
            self.ca_acc = self.ca_acc.saturating_add(acked);
            while self.ca_acc >= self.cwnd {
                self.ca_acc -= self.cwnd;
                self.cwnd = self.cwnd.saturating_add(self.mss);
            }
        }
    }

    /// Genuine loss — three duplicate ACKs — is handled exactly like Reno (halve from FlightSize,
    /// stay in fast recovery). DCTCP only *replaces* the ECN reaction, not the loss reaction.
    fn on_dup_ack(&mut self, _now: Instant, flight_size: u32) -> bool {
        self.dup_acks = self.dup_acks.saturating_add(1);
        if self.dup_acks == 3 {
            self.ssthresh = (flight_size / 2).max(2 * self.mss);
            self.cwnd = self.ssthresh;
            self.ca_acc = 0;
            true
        } else {
            false
        }
    }

    fn enter_recovery(&mut self, _now: Instant, flight_size: u32) {
        self.ssthresh = (flight_size / 2).max(2 * self.mss);
        self.cwnd = self.ssthresh;
        self.ca_acc = 0;
        self.dup_acks = 0;
    }

    fn on_rto(&mut self, _now: Instant, flight_size: u32) {
        self.ssthresh = (flight_size / 2).max(2 * self.mss);
        self.cwnd = self.mss;
        self.ca_acc = 0;
    }

    fn set_mss(&mut self, mss: u16) {
        self.mss = mss as u32;
        self.cwnd = self.cwnd.max(self.mss);
        self.ca_acc = 0;
    }

    /// The DCTCP heart: accumulate the marked fraction over a window, refresh `α`, and cut `cwnd`
    /// proportionally — at most **once per window**, and only if the window saw a mark. Reno's
    /// additive increase ([`Dctcp::on_ack`]) keeps running alongside; the balance of the two is
    /// what parks the queue near the marking threshold instead of filling the buffer.
    fn on_ecn(&mut self, _now: Instant, acked: u32, marked: u32) {
        if acked == 0 {
            return;
        }
        self.acked_in_window = self.acked_in_window.saturating_add(acked);
        self.marked_in_window = self.marked_in_window.saturating_add(marked.min(acked));
        if self.acked_in_window < self.window_bytes {
            return; // window still open — keep accumulating
        }
        // Window closed: update the EWMA toward this window's marked fraction (RFC 8257 §3.3).
        let fraction = self.marked_in_window as f64 / self.acked_in_window as f64;
        self.alpha = (1.0 - DCTCP_G) * self.alpha + DCTCP_G * fraction;
        let cwnd_before = self.cwnd;
        if self.marked_in_window > 0 {
            // Proportional multiplicative decrease, once for the whole window. `α` small → a gentle
            // trim (a shallow queue); `α → 1` → a Reno-style halving. Never below one segment, and
            // drop into congestion avoidance (ssthresh = cwnd) so growth resumes linearly.
            let reduced = (self.cwnd as f64 * (1.0 - self.alpha / 2.0)) as u32;
            self.cwnd = reduced.max(self.mss);
            self.ssthresh = self.cwnd;
            self.ca_acc = 0;
        }
        self.acked_in_window = 0;
        self.marked_in_window = 0;
        // The next window spans roughly one RTT of the data that was in flight *this* window (the
        // pre-cut window), not the post-cut window. This is what makes the reduction fire at most
        // once per RTT: the marks still arriving from before a cut keep accumulating but cannot
        // trigger a second cut until that whole window has been acked — by which time the cut has
        // had an RTT to drain the queue and marking subsides (RFC 8257 §3.3, "once per RTT").
        self.window_bytes = cwnd_before.max(self.mss);
    }
}

/// TCP Prague reference RTT (µs) for the RTT-independent additive increase. The per-RTT window
/// increase is scaled by `srtt / PRAGUE_RTT_REF_US`, so the increase *per unit time* — `step / srtt`
/// — is the constant `mss / PRAGUE_RTT_REF_US` regardless of a flow's RTT. That is the lever for the
/// L4S "reduce RTT dependence" requirement (RFC 9330 §5): a short-RTT and a long-RTT Prague flow
/// converge toward equal shares instead of the short-RTT one grabbing throughput ∝ 1/RTT as classic
/// AIMD (and DCTCP) do. 25 ms is a representative internet base RTT; at exactly this RTT Prague's step
/// is one MSS, identical to Reno/DCTCP.
const PRAGUE_RTT_REF_US: f64 = 25_000.0;

/// TCP Prague — the L4S scalable congestion control (RFC 9330 architecture + the "Prague requirements").
/// It is the natural consumer of the exact AccECN feedback this stack now carries: like [`Dctcp`] it
/// reacts to the smoothed *fraction* of CE-marked bytes with a proportional cut (`cwnd ×= 1 − α/2`), so
/// it holds a shallow sub-millisecond queue behind an L4S AQM. It differs from DCTCP in two faithful
/// ways. (1) Its additive increase is **RTT-independent**: the per-RTT step is scaled by `srtt /
/// PRAGUE_RTT_REF_US` (see [`PRAGUE_RTT_REF_US`]) so the growth *rate* in bytes/second does not depend
/// on RTT — flows of different RTT sharing a bottleneck converge to fair shares. (2) On genuine loss
/// (three dup-ACKs / RTO) it falls back to a **classic** Reno-style multiplicative decrease, the
/// "coexist safely with classic loss-based traffic" requirement, so behind a coupled dual-queue AQM
/// (dualPI2) an L4S Prague flow and a classic Reno flow get fair shares. `α` and the RTT scale are the
/// only `f64`s, updated with `+ − × ÷`/comparisons alone (no transcendental intrinsics), so it stays
/// deterministic and Miri-clean like the others.
#[derive(Clone)]
pub struct Prague {
    cwnd: u32,
    ssthresh: u32,
    mss: u32,
    /// Bytes-acked accumulator for the (RTT-scaled) additive increase.
    ca_acc: u32,
    dup_acks: u8,
    /// Smoothed fraction of bytes marked CE, in `[0, 1]` (DCTCP `α`, RFC 8257).
    alpha: f64,
    acked_in_window: u32,
    marked_in_window: u32,
    window_bytes: u32,
    /// Most recent smoothed RTT (µs), fed by [`CongestionControl::on_rtt_sample`]; 0 until the first
    /// measurement, when the additive increase falls back to Reno's one-MSS step.
    srtt_us: u32,
}

impl Prague {
    pub fn new(mss: u16) -> Self {
        let mss = mss as u32;
        Prague {
            cwnd: initial_window(mss),
            ssthresh: u32::MAX, // slow start until the first loss (identical to Reno/DCTCP)
            mss,
            ca_acc: 0,
            dup_acks: 0,
            alpha: 1.0, // conservative until the EWMA learns the marking level (RFC 8257 §3.3)
            acked_in_window: 0,
            marked_in_window: 0,
            window_bytes: initial_window(mss),
            srtt_us: 0,
        }
    }

    #[inline]
    fn in_slow_start(&self) -> bool {
        self.cwnd < self.ssthresh
    }

    /// The RTT-independent additive-increase step (bytes added per `cwnd`-worth of acked bytes, i.e.
    /// per RTT). Scaling the per-RTT step by `srtt / PRAGUE_RTT_REF_US` makes the increase *per unit
    /// time* constant; the result is clamped to `[mss/4, 4·mss]` so a pathological RTT can never make
    /// the controller grow unboundedly fast or stall. Before the first RTT sample it is one MSS (Reno).
    #[inline]
    fn ai_step(&self) -> u32 {
        if self.srtt_us == 0 {
            return self.mss;
        }
        let scaled = self.mss as f64 * (self.srtt_us as f64 / PRAGUE_RTT_REF_US);
        clamp_f64(scaled, (self.mss / 4).max(1) as f64, (self.mss * 4) as f64) as u32
    }

    /// The smoothed RTT (µs) the controller currently holds — 0 until the TCB feeds it one. Test-only,
    /// to verify the TCB→controller `on_rtt_sample` plumbing end-to-end (a deleted feed leaves it 0).
    #[cfg(test)]
    pub(crate) fn srtt_dbg(&self) -> u32 {
        self.srtt_us
    }
}

impl CongestionControl for Prague {
    #[inline]
    fn cwnd(&self) -> u32 {
        self.cwnd
    }

    #[inline]
    fn ssthresh(&self) -> u32 {
        self.ssthresh
    }

    /// Additive increase: exponential in slow start (capped at +1 MSS/ACK, like Reno), then the
    /// RTT-independent step ([`Prague::ai_step`]) per `cwnd`-worth of acked bytes in congestion
    /// avoidance. The ECN reaction is separate ([`Prague::on_ecn`]).
    fn on_ack(&mut self, _now: Instant, acked: u32) {
        self.dup_acks = 0;
        if acked == 0 {
            return;
        }
        if self.in_slow_start() {
            self.cwnd = self.cwnd.saturating_add(acked.min(self.mss));
        } else {
            self.ca_acc = self.ca_acc.saturating_add(acked);
            let step = self.ai_step();
            while self.ca_acc >= self.cwnd {
                self.ca_acc -= self.cwnd;
                self.cwnd = self.cwnd.saturating_add(step);
            }
        }
    }

    /// Genuine loss — three duplicate ACKs — is the *classic* fallback: halve from FlightSize and stay
    /// in fast recovery, exactly like Reno. Prague only replaces the ECN reaction, not the loss one, so
    /// it stays safe with classic drop-based traffic.
    fn on_dup_ack(&mut self, _now: Instant, flight_size: u32) -> bool {
        self.dup_acks = self.dup_acks.saturating_add(1);
        if self.dup_acks == 3 {
            self.ssthresh = (flight_size / 2).max(2 * self.mss);
            self.cwnd = self.ssthresh;
            self.ca_acc = 0;
            true
        } else {
            false
        }
    }

    fn enter_recovery(&mut self, _now: Instant, flight_size: u32) {
        self.ssthresh = (flight_size / 2).max(2 * self.mss);
        self.cwnd = self.ssthresh;
        self.ca_acc = 0;
        self.dup_acks = 0;
    }

    fn on_rto(&mut self, _now: Instant, flight_size: u32) {
        self.ssthresh = (flight_size / 2).max(2 * self.mss);
        self.cwnd = self.mss;
        self.ca_acc = 0;
    }

    fn set_mss(&mut self, mss: u16) {
        self.mss = mss as u32;
        self.cwnd = self.cwnd.max(self.mss);
        self.ca_acc = 0;
    }

    /// The scalable ECN reaction, identical to DCTCP: accumulate the marked fraction over a window,
    /// refresh `α`, and cut `cwnd ×= 1 − α/2` at most once per marked window. Fed by the exact AccECN
    /// mark count, so `α` tracks the true marking level.
    fn on_ecn(&mut self, _now: Instant, acked: u32, marked: u32) {
        if acked == 0 {
            return;
        }
        self.acked_in_window = self.acked_in_window.saturating_add(acked);
        self.marked_in_window = self.marked_in_window.saturating_add(marked.min(acked));
        if self.acked_in_window < self.window_bytes {
            return;
        }
        let fraction = self.marked_in_window as f64 / self.acked_in_window as f64;
        self.alpha = (1.0 - DCTCP_G) * self.alpha + DCTCP_G * fraction;
        let cwnd_before = self.cwnd;
        if self.marked_in_window > 0 {
            let reduced = (self.cwnd as f64 * (1.0 - self.alpha / 2.0)) as u32;
            self.cwnd = reduced.max(self.mss);
            self.ssthresh = self.cwnd;
            self.ca_acc = 0;
        }
        self.acked_in_window = 0;
        self.marked_in_window = 0;
        self.window_bytes = cwnd_before.max(self.mss);
    }

    fn on_rtt_sample(&mut self, srtt_us: u32) {
        self.srtt_us = srtt_us;
    }
}

/// Tunable parameters of the [`Learned`] congestion controller — the genome a search optimizes. Each
/// is a plain `f64`; the controller is a fixed AIMD skeleton (standard slow start; loss → multiplicative
/// decrease; congestion-avoidance additive increase; a once-per-round ECN proportional cut) whose
/// *gains* are these numbers. The vector therefore spans a controller family that contains Reno and
/// DCTCP as special points and can interpolate to a better latency-throughput frontier between them.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LearnedParams {
    /// Additive-increase gain: MSS added per cwnd-worth of acked bytes in congestion avoidance (Reno = 1).
    pub ai_gain: f64,
    /// Multiplicative-decrease factor on a packet-loss signal (Reno = 0.5, CUBIC = 0.7).
    pub md_loss: f64,
    /// ECN response curve: on a CE-marked round the window is cut by `clamp(ecn_a·α + ecn_b·α², 0,
    /// ecn_max)`, with `α` the smoothed marked fraction. DCTCP is the linear point `ecn_a = 0.5,
    /// ecn_b = 0` (`cwnd ×= 1 − α/2`); a non-zero `ecn_b` lets the search bend the curve.
    pub ecn_a: f64,
    pub ecn_b: f64,
    /// Cap on the per-round ECN cut fraction (never cut more than this much at once).
    pub ecn_max: f64,
}

impl LearnedParams {
    /// A sane hand-set starting genome: Reno's AIMD plus DCTCP's linear ECN response. The search
    /// departs from here, and until a trained genome is baked in this is also what ships.
    pub const DEFAULT: LearnedParams =
        LearnedParams { ai_gain: 1.0, md_loss: 0.5, ecn_a: 0.5, ecn_b: 0.0, ecn_max: 0.5 };

    /// The evolved genome the shipped [`CcKind::Learned`] runs — the best individual the CEM trainer
    /// in `sim` found (reproducible: `evolve(&train_set(), 30, 28, 0.25, 12345)` on the CE-marking
    /// bottleneck training set, hinge fitness "maximise goodput subject to a sub-ms queue"). On the
    /// held-out (unseen) bottlenecks it lands a distinctly better low-latency frontier point than
    /// hand-tuned DCTCP — ~30% more goodput at a comparable (still sub-millisecond) standing queue — by
    /// using a much gentler ECN response (`ecn_a ≈ 0.18` vs DCTCP's 0.5) that doesn't needlessly crush
    /// the window. (A better frontier *point*, not strict Pareto domination: DCTCP's queue is a hair
    /// lower, learned's goodput much higher; both well under a millisecond.)
    pub const BAKED: LearnedParams = LearnedParams {
        ai_gain: 0.860_860_080_762_661_4,
        md_loss: 0.176_650_191_977_447_08,
        ecn_a: 0.184_711_028_094_530_77,
        ecn_b: 0.011_656_344_382_528_598,
        ecn_max: 0.628_277_523_357_274_3,
    };

    /// Clamp every gene into the range the controller is defined on, so a search step can never produce
    /// a pathological controller (negative increase, window growth on loss, an unbounded ECN cut).
    pub fn sanitized(self) -> LearnedParams {
        LearnedParams {
            ai_gain: clamp_f64(self.ai_gain, 0.05, 8.0),
            md_loss: clamp_f64(self.md_loss, 0.1, 0.95),
            ecn_a: clamp_f64(self.ecn_a, 0.0, 2.0),
            ecn_b: clamp_f64(self.ecn_b, -1.0, 2.0),
            ecn_max: clamp_f64(self.ecn_max, 0.05, 0.95),
        }
    }
}

/// `f64::clamp` without relying on its total-ordering edge cases — plain comparisons, NaN-free here.
#[inline]
fn clamp_f64(x: f64, lo: f64, hi: f64) -> f64 {
    if x < lo {
        lo
    } else if x > hi {
        hi
    } else {
        x
    }
}

thread_local! {
    /// Training-time injection of a candidate genome. The CEM trainer sets this before each evaluation
    /// run; [`Learned::new`] reads it, falling back to [`LearnedParams::BAKED`] when unset — so the
    /// shipped `CcKind::Learned` (override `None`) is a deterministic, pure controller, while the
    /// trainer can score arbitrary genomes through the *same* sim path the real stack uses. The sim is
    /// single-threaded, so this is deterministic; it is std-only, so the zero-dependency rule holds.
    static LEARNED_OVERRIDE: std::cell::Cell<Option<LearnedParams>> = const { std::cell::Cell::new(None) };
}

/// Install a candidate genome for subsequently-constructed [`Learned`] controllers (training only).
/// `pub(crate)`, not public API: external users go through the [`crate::sim`] trainer (`evolve` /
/// `frontier_fitness`); this is the in-crate hook those use, and the shipped `CcKind::Learned` never
/// touches it (it resolves to [`LearnedParams::BAKED`]).
pub(crate) fn set_learned_override(params: Option<LearnedParams>) {
    LEARNED_OVERRIDE.with(|c| c.set(params));
}

/// The genome a new [`Learned`] controller uses right now: the override if one is installed, else the
/// baked genome — sanitized either way.
pub(crate) fn current_learned_params() -> LearnedParams {
    LEARNED_OVERRIDE.with(|c| c.get()).unwrap_or(LearnedParams::BAKED).sanitized()
}

/// A congestion controller whose AIMD/ECN *gains* are [`LearnedParams`] rather than RFC constants — so
/// a black-box optimizer (the CEM trainer in `sim`) can evolve them against the deterministic bottleneck
/// simulation and search for a better latency-throughput frontier than the hand-tuned controllers reach.
/// The skeleton (slow start, loss MD, CA additive increase, a once-per-round ECN proportional cut) is
/// fixed and contains Reno and DCTCP as special genomes, which keeps *every* genome a stable controller;
/// only the gains move. Everything is `+ − × ÷` and comparisons (no transcendental intrinsics), so it
/// stays deterministic and Miri-clean.
#[derive(Clone)]
pub struct Learned {
    cwnd: u32,
    ssthresh: u32,
    mss: u32,
    ca_acc: u32,
    dup_acks: u8,
    p: LearnedParams,
    // ECN round accounting (as in `Dctcp`).
    alpha: f64,
    acked_in_window: u32,
    marked_in_window: u32,
    window_bytes: u32,
}

impl Learned {
    pub fn new(mss: u16) -> Self {
        Learned::with_params(mss, current_learned_params())
    }

    pub fn with_params(mss: u16, p: LearnedParams) -> Self {
        Learned::with_raw_params(mss, p.sanitized())
    }

    /// Build a `Learned` from a genome **without** [`LearnedParams::sanitized`] clamping it. The
    /// production constructors always sanitise; this exists only so the bounded safety checker
    /// ([`crate::bmc`]) can drive a deliberately-pathological *unsanitised* genome and prove the
    /// safety envelope is violated — i.e. that `sanitized()` is load-bearing, not decorative.
    pub(crate) fn with_raw_params(mss: u16, p: LearnedParams) -> Self {
        let mss = mss as u32;
        Learned {
            cwnd: initial_window(mss),
            ssthresh: u32::MAX,
            mss,
            ca_acc: 0,
            dup_acks: 0,
            p,
            alpha: 1.0,
            acked_in_window: 0,
            marked_in_window: 0,
            window_bytes: initial_window(mss),
        }
    }

    #[inline]
    fn in_slow_start(&self) -> bool {
        self.cwnd < self.ssthresh
    }

    /// The evolved loss response: `ssthresh = max(FlightSize · md_loss, 2·MSS)`.
    #[inline]
    fn loss_ssthresh(&self, flight_size: u32) -> u32 {
        ((flight_size as f64 * self.p.md_loss) as u32).max(2 * self.mss)
    }
}

impl CongestionControl for Learned {
    #[inline]
    fn cwnd(&self) -> u32 {
        self.cwnd
    }

    #[inline]
    fn ssthresh(&self) -> u32 {
        self.ssthresh
    }

    fn on_ack(&mut self, _now: Instant, acked: u32) {
        self.dup_acks = 0;
        if acked == 0 {
            return;
        }
        if self.in_slow_start() {
            self.cwnd = self.cwnd.saturating_add(acked.min(self.mss));
        } else {
            self.ca_acc = self.ca_acc.saturating_add(acked);
            let step = ((self.p.ai_gain * self.mss as f64) as u32).max(1); // ≥ 1 byte/round
            while self.ca_acc >= self.cwnd {
                self.ca_acc -= self.cwnd;
                self.cwnd = self.cwnd.saturating_add(step);
            }
        }
    }

    fn on_dup_ack(&mut self, _now: Instant, flight_size: u32) -> bool {
        self.dup_acks = self.dup_acks.saturating_add(1);
        if self.dup_acks == 3 {
            self.ssthresh = self.loss_ssthresh(flight_size);
            self.cwnd = self.ssthresh;
            self.ca_acc = 0;
            true
        } else {
            false
        }
    }

    fn enter_recovery(&mut self, _now: Instant, flight_size: u32) {
        self.ssthresh = self.loss_ssthresh(flight_size);
        self.cwnd = self.ssthresh;
        self.ca_acc = 0;
        self.dup_acks = 0;
    }

    fn on_rto(&mut self, _now: Instant, flight_size: u32) {
        self.ssthresh = self.loss_ssthresh(flight_size);
        self.cwnd = self.mss;
        self.ca_acc = 0;
    }

    fn set_mss(&mut self, mss: u16) {
        self.mss = mss as u32;
        self.cwnd = self.cwnd.max(self.mss);
        self.ca_acc = 0;
    }

    fn on_ecn(&mut self, _now: Instant, acked: u32, marked: u32) {
        if acked == 0 {
            return;
        }
        self.acked_in_window = self.acked_in_window.saturating_add(acked);
        self.marked_in_window = self.marked_in_window.saturating_add(marked.min(acked));
        if self.acked_in_window < self.window_bytes {
            return;
        }
        let fraction = self.marked_in_window as f64 / self.acked_in_window as f64;
        self.alpha = (1.0 - DCTCP_G) * self.alpha + DCTCP_G * fraction;
        let cwnd_before = self.cwnd;
        if self.marked_in_window > 0 {
            // The learned ECN response curve: cut = clamp(ecn_a·α + ecn_b·α², 0, ecn_max).
            let a = self.alpha;
            let cut = clamp_f64(self.p.ecn_a * a + self.p.ecn_b * a * a, 0.0, self.p.ecn_max);
            let reduced = (self.cwnd as f64 * (1.0 - cut)) as u32;
            self.cwnd = reduced.max(self.mss);
            self.ssthresh = self.cwnd;
            self.ca_acc = 0;
        }
        self.acked_in_window = 0;
        self.marked_in_window = 0;
        self.window_bytes = cwnd_before.max(self.mss);
    }
}

// ── synthesised control law: a verified GP-searched register machine ───────────────────────────────
//
// Every controller above operates on KNOWN structure: Reno's `+1 MSS`, DCTCP's `α/2`; even [`Learned`]
// is a five-gene tuning of a hand-written AIMD skeleton. [`Synth`] removes the skeleton. Its three
// congestion responses — the congestion-avoidance increase, the loss multiplicative decrease, and the
// ECN cut — are each a tiny **program** ([`ControlProgram`]) over the live signals, discovered by the
// genetic search in [`crate::sim`] with the bounded safety checker ([`crate::bmc`]) as a HARD FILTER:
// a program that breaks the safety envelope is rejected before it is ever scored ("synthesis modulo
// verification"). So the *algorithm* is searched, not the gains — and unlike a learned/RL controller,
// every survivor is machine-checked safe. The machine is a fixed-length SSA register file evaluated
// with `+ − × ÷ min max` only (protected division, NaN/inf guarded), so it is deterministic,
// zero-transcendental and Miri-clean, exactly like the controllers it generalises.
//
// CRUCIAL: the program output is wired in **unsanitised**. A pathological program genuinely *can*
// shrink the window on a clean ACK, grow it on a mark, or inflate it past the pipe on loss. Only the
// liveness floors every shipped controller already has are applied (one MSS on the window; the RFC 5681
// `2·MSS` floor on the loss/ssthresh response); the gain-dependent safety clauses are left exposed, so
// the bmc filter has real teeth (it must actually reject the unsafe majority for the guarantee to mean
// anything). The floors are raises-only, so they never *mask* a violation — only the floor's own clause
// (`cwnd ≥ MSS`, `ssthresh ≥ 2·MSS`) is made structural; inflation-on-loss, growth-on-mark and
// shrink-on-ack stay checkable.

/// Input registers of the control-law machine: the live signals plus three constants. Indices are
/// referenced by name (below) when assembling the AIMD seed, and by [`synth_expr`] when decompiling.
const SYNTH_REGS_IN: usize = 8;
/// Instructions per sub-program (= computed registers appended after the inputs).
const SYNTH_PROG_LEN: usize = 8;
/// Magnitude cap applied to every register value (in *segment* units, far above any real window), so a
/// downstream `u32` cast can never overflow or trap.
const SYNTH_CAP: f64 = 1.0e9;
/// Upper bound on a synthesised `cwnd` in bytes (≈ 1 GiB) — caps the `f64 → u32` conversion safely.
const SYNTH_CWND_CAP: u32 = 1 << 30;

// Named input-register indices the AIMD seed references (must match the order in [`Synth::signals`]).
const R_FLIGHT: u8 = 1;
const R_ALPHA: u8 = 3;
#[cfg(test)]
const R_SRTT: u8 = 4; // only the test-only EXHAUSTED_ECN_OPTIMUM references it by name
const R_HALF: u8 = 5;
const R_ONE: u8 = 6;

/// One operation in the control-law register machine. Total over the reals — division is protected
/// (`y == 0 → 0`) and the result is NaN/inf-guarded — so evaluation never traps.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum SynthOp {
    Add,
    Sub,
    Mul,
    Div,
    Min,
    Max,
}

impl SynthOp {
    /// All six ops, so the genetic search can pick one by index.
    pub(crate) const ALL: [SynthOp; 6] =
        [SynthOp::Add, SynthOp::Sub, SynthOp::Mul, SynthOp::Div, SynthOp::Min, SynthOp::Max];
}

/// One SSA instruction `r[N + t] = op(r[a], r[b])`. `a`/`b` index any earlier register; the interpreter
/// clamps a forward/out-of-range index to the last valid register, so *every* genome is well-defined —
/// there is no parse or validation step and mutation can never produce an illegal program.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Instr {
    pub(crate) op: SynthOp,
    pub(crate) a: u8,
    pub(crate) b: u8,
}

impl Instr {
    pub(crate) fn new(op: SynthOp, a: u8, b: u8) -> Self {
        Instr { op, a, b }
    }
}

/// A synthesised congestion-control **law**: three SSA sub-programs over the shared signal vector, one
/// per response. The default ([`ControlProgram::AIMD`]) reproduces Reno's additive increase, Reno's
/// loss decrease and DCTCP's ECN response exactly, so a [`Synth`] controller with no override installed
/// is a faithful, deterministic re-expression of DCTCP; the genetic search departs from there.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ControlProgram {
    pub(crate) inc: [Instr; SYNTH_PROG_LEN],
    pub(crate) md: [Instr; SYNTH_PROG_LEN],
    pub(crate) ecn: [Instr; SYNTH_PROG_LEN],
}

/// Build a sub-program that computes `op(r[a], r[b])` in its first slot and carries the result through
/// to the output register with identity `max(x, x)` steps — used to assemble the AIMD/DCTCP seed.
const fn seed_prog(op: SynthOp, a: u8, b: u8) -> [Instr; SYNTH_PROG_LEN] {
    let mut prog = [Instr { op: SynthOp::Max, a: 0, b: 0 }; SYNTH_PROG_LEN];
    prog[0] = Instr { op, a, b };
    let mut i = 1;
    while i < SYNTH_PROG_LEN {
        let prev = (SYNTH_REGS_IN + i - 1) as u8;
        prog[i] = Instr { op: SynthOp::Max, a: prev, b: prev };
        i += 1;
    }
    prog
}

impl ControlProgram {
    /// The seed law: Reno additive increase (`+1 MSS / RTT`), Reno multiplicative decrease
    /// (`cwnd ← ½ · FlightSize`), DCTCP ECN response (`cut = α/2`). A [`Synth`] running this *is* DCTCP
    /// (up to one ULP of float rounding in the loss step), so it is both the search's safe warm start
    /// and the "did it just rediscover the hand-written law?" reference point.
    pub(crate) const AIMD: ControlProgram = ControlProgram {
        inc: seed_prog(SynthOp::Max, R_ONE, R_ONE),    // = 1.0 segment / RTT
        md: seed_prog(SynthOp::Mul, R_FLIGHT, R_HALF), // = 0.5 · flight_seg
        ecn: seed_prog(SynthOp::Mul, R_ALPHA, R_HALF), // = 0.5 · α
    };

    /// The law the GP synthesis actually discovered (`evolve_control_law(&train_set(), 24, 28, 7, 1460,
    /// 4, 0xC0FFEE_5717)` in `sim`, reproduced by the ignored `synth_control_law_derisk`). A **research
    /// artifact, not the shipped default** — `CcKind::Synth` keeps the safe AIMD/DCTCP law (above),
    /// because this one's loss response is degenerate (see below) and would tank throughput on a plain
    /// lossy path. Stripped of its introns (the redundant `max(x, x)` carries the genetic search leaves
    /// behind), the three responses are:
    ///
    /// - **increase**: `step = max(0.5, α, acked_seg)` segments/RTT — a genuinely *new structure* the
    ///   fixed AIMD/Learned skeleton cannot express: a signal-dependent increase, not a constant.
    /// - **loss**: `cwnd ← 1 segment` (→ the `2·MSS` floor) — degenerate, because on the ECN-marking
    ///   training bottlenecks the drop-based loss path almost never fires, so the search left it at the
    ///   floor. (This is why it is not shipped.)
    /// - **ecn**: `cut = α / 2` — DCTCP's response, **rediscovered exactly** (a unit test pins the value).
    ///   Free to pick *any* program, the search kept coming back to `α/2` — a fixed point of the GP under
    ///   this grammar/objective (the sharp negative; this is convergence, not a proof of optimality). It
    ///   does *not* reach `Learned`'s gentler `≈ α·0.185` — a constant the discrete grammar `{0.5, 1, 2}`
    ///   cannot build — which is exactly why this law, under the queue-penalised hinge fitness, tops every
    ///   *hand-tuned* controller on the held-out set yet loses raw goodput to the loss-based ones and loses
    ///   outright to the *gene-tuned* `Learned`. The characterised gap motivates a GP-structure +
    ///   CEM-constant hybrid.
    ///
    /// `#[cfg(test)]` because it is a research artifact, exercised only by the safety / frontier tests
    /// and the de-risk — the shipped `CcKind::Synth` deliberately runs the safe AIMD default, not this.
    #[cfg(test)]
    pub(crate) const BAKED_SYNTH: ControlProgram = ControlProgram {
        inc: [
            Instr { op: SynthOp::Max, a: 6, b: 6 },
            Instr { op: SynthOp::Max, a: 3, b: 5 },
            Instr { op: SynthOp::Max, a: 9, b: 9 },
            Instr { op: SynthOp::Max, a: 10, b: 10 },
            Instr { op: SynthOp::Max, a: 11, b: 2 },
            Instr { op: SynthOp::Max, a: 12, b: 12 },
            Instr { op: SynthOp::Max, a: 13, b: 13 },
            Instr { op: SynthOp::Max, a: 14, b: 14 },
        ],
        md: [
            Instr { op: SynthOp::Mul, a: 1, b: 5 },
            Instr { op: SynthOp::Max, a: 5, b: 8 },
            Instr { op: SynthOp::Div, a: 9, b: 9 },
            Instr { op: SynthOp::Max, a: 10, b: 10 },
            Instr { op: SynthOp::Max, a: 11, b: 11 },
            Instr { op: SynthOp::Max, a: 12, b: 11 },
            Instr { op: SynthOp::Div, a: 13, b: 13 },
            Instr { op: SynthOp::Max, a: 14, b: 14 },
        ],
        ecn: [
            Instr { op: SynthOp::Mul, a: 3, b: 5 },
            Instr { op: SynthOp::Max, a: 8, b: 8 },
            Instr { op: SynthOp::Max, a: 9, b: 9 },
            Instr { op: SynthOp::Max, a: 10, b: 10 },
            Instr { op: SynthOp::Max, a: 11, b: 11 },
            Instr { op: SynthOp::Max, a: 12, b: 12 },
            Instr { op: SynthOp::Max, a: 13, b: 13 },
            Instr { op: SynthOp::Max, a: 14, b: 14 },
        ],
    };

    /// The frontier-optimal **single-operation** ECN response found by **exhausting** the class (not the
    /// heuristic GP): `cut = srtt/rtt_min − 1` — a **delay-based** response that backs off proportional to
    /// the measured queuing delay, paired with AIMD's increase/loss. [`crate::sim::exhaust_ecn_response`]
    /// enumerates all 384 single-op ECN responses, proves the 352 safe ones, and finds this one maximal on
    /// the training frontier — strictly above DCTCP's `α/2` (the fixed point the GP got *stuck* at in M23).
    /// So it is a **proven in-class optimum**, and the lesson is that M23's `α/2` was a *search* artefact,
    /// not the grammar's true optimum. `#[cfg(test)]`: a research artifact (and a higher-queue operating
    /// point than the shipped sub-ms controllers), exercised by the exhaustion tests, not shipped.
    #[cfg(test)]
    pub(crate) const EXHAUSTED_ECN_OPTIMUM: ControlProgram = ControlProgram {
        inc: ControlProgram::AIMD.inc,
        md: ControlProgram::AIMD.md,
        ecn: seed_prog(SynthOp::Sub, R_SRTT, R_ONE), // cut = srtt_ratio − 1
    };

    /// Number of sub-programs and instructions each, so the genetic search can size its mutations
    /// without importing the machine's private constants.
    pub(crate) const SUBS: usize = 3;
    pub(crate) const PROG_LEN: usize = SYNTH_PROG_LEN;
    pub(crate) const REGS_IN: usize = SYNTH_REGS_IN;

    /// Immutable / mutable access to the `which`-th sub-program (0 = increase, 1 = loss, 2 = ecn) for
    /// the genetic search's crossover and mutation.
    pub(crate) fn sub(&self, which: usize) -> &[Instr; SYNTH_PROG_LEN] {
        match which {
            0 => &self.inc,
            1 => &self.md,
            _ => &self.ecn,
        }
    }
    pub(crate) fn sub_mut(&mut self, which: usize) -> &mut [Instr; SYNTH_PROG_LEN] {
        match which {
            0 => &mut self.inc,
            1 => &mut self.md,
            _ => &mut self.ecn,
        }
    }

    /// The second-to-last register — the register the output instruction reads *iff* that instruction is
    /// an identity carry. The loss/increase repairs clamp this register. (Output = the last register.)
    const OUT_PREV: u8 = (SYNTH_REGS_IN + SYNTH_PROG_LEN - 2) as u8;

    // ── CEGIS repair primitives ─────────────────────────────────────────────────────────────────────
    //
    // Each projects ONE response back into the safety envelope in answer to a specific bmc counterexample,
    // touching only that response (the other two stay byte-identical). All three are *sound* — the result
    // provably satisfies the named clause regardless of the input — but they are NOT uniformly minimal, and
    // the doc is precise about it:
    //   - `repair_loss` / `repair_increase` overwrite the offending response's OUTPUT instruction with a
    //     clamp of `OUT_PREV` (the second-to-last register). When the output instruction was an identity
    //     carry — the seed shape, and the only shape the live search's output slot usually holds — `OUT_PREV`
    //     IS the discovered output, so this is a faithful output clamp (an already-safe output is unchanged).
    //     When the search has rerolled the output slot into a real op, that op is *discarded* and the clamp
    //     is applied to `OUT_PREV` instead: still sound (the result is provably within the clause), but it is
    //     no longer a clamp of the discovered output — so "structure-preserving" holds only in the carry case.
    //   - `repair_ecn` is a wholesale RESET of the ECN response to the safe baseline `α/2` — NOT an output
    //     clamp — because a clean `max(cut, 0)` is not expressible without a zero constant in the signal
    //     vector. It discards the discovered ECN law.

    /// Clause 2 (a loss must not inflate `cwnd` past the pipe): overwrite the loss output instruction with
    /// `min(OUT_PREV, flight_seg)` — provably `≤ flight_seg`, so `cwnd ≤ flight` on loss. A faithful clamp
    /// of the discovered output only when the output instruction was an identity carry (see the note above).
    pub(crate) fn repair_loss(mut self) -> ControlProgram {
        self.md[SYNTH_PROG_LEN - 1] = Instr { op: SynthOp::Min, a: ControlProgram::OUT_PREV, b: R_FLIGHT };
        self
    }

    /// Clause 4 (a clean ACK must not shrink `cwnd`): overwrite the increase output instruction with
    /// `max(OUT_PREV, ½)` — provably `> 0`, so the additive increase never shrinks `cwnd`. Same carry-case
    /// faithfulness caveat as [`ControlProgram::repair_loss`].
    pub(crate) fn repair_increase(mut self) -> ControlProgram {
        self.inc[SYNTH_PROG_LEN - 1] = Instr { op: SynthOp::Max, a: ControlProgram::OUT_PREV, b: R_HALF };
        self
    }

    /// Clause 3 (an ECN mark must not grow `cwnd`): RESET the whole ECN response to the safe DCTCP baseline
    /// `cut = α/2`, discarding the discovered ECN law (a clean non-negativity clamp is not expressible
    /// without a zero constant, so the baseline is the projection here).
    pub(crate) fn repair_ecn(mut self) -> ControlProgram {
        self.ecn = ControlProgram::AIMD.ecn;
        self
    }

    /// AIMD's increase + loss with the ECN response replaced by a **single operation** `op(r[a], r[b])`
    /// (carried to the output) — the unit the exhaustive single-op ECN-response search
    /// ([`crate::sim::exhaust_ecn_response`]) enumerates. `a`/`b` index input registers (`0..REGS_IN`).
    pub(crate) fn aimd_with_ecn_op(op: SynthOp, a: u8, b: u8) -> ControlProgram {
        ControlProgram { inc: ControlProgram::AIMD.inc, md: ControlProgram::AIMD.md, ecn: seed_prog(op, a, b) }
    }
}

/// NaN → 0, ±inf → ±cap, otherwise clamp to ±cap. `is_nan` is a bit test (not a transcendental
/// intrinsic), so this stays deterministic with no cross-platform drift.
#[inline]
fn synth_guard(v: f64) -> f64 {
    if v.is_nan() {
        0.0
    } else {
        clamp_f64(v, -SYNTH_CAP, SYNTH_CAP)
    }
}

/// Evaluate one SSA sub-program over the input vector, returning the last register (the output). Each
/// instruction reads two earlier registers (operands clamped into range, so the program is always
/// well-defined), applies its op with protected division, and stores a guarded result.
fn synth_eval(prog: &[Instr; SYNTH_PROG_LEN], inputs: &[f64; SYNTH_REGS_IN]) -> f64 {
    let mut reg = [0.0_f64; SYNTH_REGS_IN + SYNTH_PROG_LEN];
    reg[..SYNTH_REGS_IN].copy_from_slice(inputs);
    for (t, ins) in prog.iter().enumerate() {
        let n = SYNTH_REGS_IN + t;
        let a = reg[(ins.a as usize).min(n - 1)];
        let b = reg[(ins.b as usize).min(n - 1)];
        let v = match ins.op {
            SynthOp::Add => a + b,
            SynthOp::Sub => a - b,
            SynthOp::Mul => a * b,
            SynthOp::Div => {
                if b == 0.0 {
                    0.0 // protected division
                } else {
                    a / b
                }
            }
            SynthOp::Min => {
                if a < b {
                    a
                } else {
                    b
                }
            }
            SynthOp::Max => {
                if a > b {
                    a
                } else {
                    b
                }
            }
        };
        reg[n] = synth_guard(v);
    }
    reg[SYNTH_REGS_IN + SYNTH_PROG_LEN - 1]
}

/// Convert a synthesised window (bytes, as an `f64`) to a `u32`, applying only the liveness `floor`
/// (one MSS for the increase / ECN responses, `2·MSS` for the loss response — the floors every shipped
/// controller already uses) and the overflow cap. It deliberately does **not** clamp the gain-dependent
/// safety properties, so an unsafe synthesised law stays visible to the bmc. A floor is a raise-only
/// operation, so it can never hide a violation — only its own clause becomes structural.
#[inline]
fn synth_to_cwnd(v: f64, floor: u32) -> u32 {
    if v < floor as f64 {
        floor
    } else if v > SYNTH_CWND_CAP as f64 {
        SYNTH_CWND_CAP
    } else {
        v as u32
    }
}

/// Decompile each sub-program's output register to an infix expression over the named signals — purely
/// for the synthesis de-risk readout, so a discovered law can be eyeballed (AIMD, or genuinely new?).
/// Returns `(increase, loss, ecn)`. `#[cfg(test)]`: a readout helper, not part of the shipped controller.
#[cfg(test)]
pub(crate) fn synth_describe(prog: &ControlProgram) -> (String, String, String) {
    let out = SYNTH_REGS_IN + SYNTH_PROG_LEN - 1;
    (synth_expr(&prog.inc, out), synth_expr(&prog.md, out), synth_expr(&prog.ecn, out))
}

#[cfg(test)]
fn synth_expr(prog: &[Instr; SYNTH_PROG_LEN], reg: usize) -> String {
    const NAMES: [&str; SYNTH_REGS_IN] = ["cwnd", "flight", "acked", "alpha", "srtt", "0.5", "1", "2"];
    if reg < SYNTH_REGS_IN {
        return NAMES[reg].to_string();
    }
    let ins = prog[reg - SYNTH_REGS_IN];
    let amax = reg - 1; // operands clamp to < reg, matching synth_eval — and strictly decreasing, so this terminates
    let a = synth_expr(prog, (ins.a as usize).min(amax));
    let b = synth_expr(prog, (ins.b as usize).min(amax));
    match ins.op {
        SynthOp::Add => format!("({a} + {b})"),
        SynthOp::Sub => format!("({a} - {b})"),
        SynthOp::Mul => format!("({a} * {b})"),
        SynthOp::Div => format!("({a} / {b})"),
        SynthOp::Min => format!("min({a}, {b})"),
        SynthOp::Max => format!("max({a}, {b})"),
    }
}

thread_local! {
    /// Training-time injection of a candidate [`ControlProgram`] for subsequently-built [`Synth`]
    /// controllers — the genetic search in [`crate::sim`] installs a candidate here before scoring it
    /// through the real bottleneck sim, exactly as the CEM trainer does with [`set_learned_override`].
    /// Single-threaded sim ⇒ deterministic; std-only ⇒ zero-dependency. The shipped `CcKind::Synth`
    /// (override `None`) resolves to [`ControlProgram::AIMD`].
    static SYNTH_OVERRIDE: std::cell::Cell<Option<ControlProgram>> = const { std::cell::Cell::new(None) };
}

/// Install a candidate program for subsequently-constructed [`Synth`] controllers (training only).
pub(crate) fn set_program_override(prog: Option<ControlProgram>) {
    SYNTH_OVERRIDE.with(|c| c.set(prog));
}

/// The program a new [`Synth`] uses right now: the installed override, else [`ControlProgram::AIMD`].
fn current_program() -> ControlProgram {
    SYNTH_OVERRIDE.with(|c| c.get()).unwrap_or(ControlProgram::AIMD)
}

/// A congestion controller whose three responses are a synthesised [`ControlProgram`] rather than
/// hand-written code — the unit the genetic search in [`crate::sim`] evolves under the bmc safety
/// filter. With no override installed it runs [`ControlProgram::AIMD`] (≡ DCTCP); the search installs a
/// candidate via [`set_program_override`]. Slow start is fixed-safe; only the three congestion responses
/// are program-driven, and they are wired **unsanitised** (see the module note) so the safety checker can
/// reject an unsafe law. Everything is `+ − × ÷`/comparisons, so it stays deterministic and Miri-clean.
#[derive(Clone)]
pub struct Synth {
    cwnd: u32,
    ssthresh: u32,
    mss: u32,
    ca_acc: u32,
    dup_acks: u8,
    prog: ControlProgram,
    // ECN round accounting (as in `Dctcp`).
    alpha: f64,
    acked_in_window: u32,
    marked_in_window: u32,
    window_bytes: u32,
    // RTT signals: the latest smoothed RTT and the running minimum, so the law can read the inflation
    // ratio `srtt / rtt_min` (a delay signal that needs no extra plumbing — the TCB already feeds RTT).
    srtt_us: u32,
    rtt_min_us: u32,
}

impl Synth {
    pub fn new(mss: u16) -> Self {
        Synth::with_program(mss, current_program())
    }

    /// Build a `Synth` running `prog` verbatim — no sanitisation, which is exactly what lets the bmc
    /// drive a deliberately-unsafe law and prove the synthesis filter has teeth.
    pub(crate) fn with_program(mss: u16, prog: ControlProgram) -> Self {
        let mss = mss as u32;
        Synth {
            cwnd: initial_window(mss),
            ssthresh: u32::MAX, // slow start until the first loss (identical to Reno/DCTCP)
            mss,
            ca_acc: 0,
            dup_acks: 0,
            prog,
            alpha: 1.0,
            acked_in_window: 0,
            marked_in_window: 0,
            window_bytes: initial_window(mss),
            srtt_us: 0,
            rtt_min_us: 0,
        }
    }

    #[inline]
    fn in_slow_start(&self) -> bool {
        self.cwnd < self.ssthresh
    }

    /// The live signal vector the program reads: window / flight / acked in **segments** (so magnitudes
    /// are O(1–1000) and the ops compose meaningfully across signals), the smoothed ECN fraction `α`,
    /// the RTT inflation ratio `srtt / rtt_min` (≥ 1; 1 before the first sample), and the constants ½,
    /// 1, 2 (so the machine can build halving, identity and doubling).
    fn signals(&self, flight: u32, acked: u32) -> [f64; SYNTH_REGS_IN] {
        let mss = self.mss.max(1) as f64;
        let srtt_ratio = if self.rtt_min_us > 0 && self.srtt_us > 0 {
            self.srtt_us as f64 / self.rtt_min_us as f64
        } else {
            1.0
        };
        [
            self.cwnd as f64 / mss, // r0 cwnd_seg
            flight as f64 / mss,    // r1 flight_seg
            acked as f64 / mss,     // r2 acked_seg
            self.alpha,             // r3 α
            srtt_ratio,             // r4 srtt / rtt_min
            0.5,                    // r5
            1.0,                    // r6
            2.0,                    // r7
        ]
    }

    /// The synthesised loss response: `cwnd ← md(signals)` segments, floored at `2·MSS` (the RFC 5681
    /// loss floor every controller shares). UNSANITISED above the floor, so a law that returns more than
    /// the FlightSize inflates the window past the pipe and the bmc flags it.
    #[inline]
    fn loss_target(&self, flight_size: u32) -> u32 {
        let target_seg = synth_eval(&self.prog.md, &self.signals(flight_size, 0));
        synth_to_cwnd(target_seg * self.mss as f64, 2 * self.mss)
    }
}

impl CongestionControl for Synth {
    #[inline]
    fn cwnd(&self) -> u32 {
        self.cwnd
    }

    #[inline]
    fn ssthresh(&self) -> u32 {
        self.ssthresh
    }

    fn on_ack(&mut self, _now: Instant, acked: u32) {
        self.dup_acks = 0;
        if acked == 0 {
            return;
        }
        if self.in_slow_start() {
            // Slow start is fixed-safe (not synthesised): +1 MSS per ACK, like every controller.
            self.cwnd = self.cwnd.saturating_add(acked.min(self.mss));
        } else {
            self.ca_acc = self.ca_acc.saturating_add(acked);
            // Synthesised additive increase: step (segments / RTT) = inc(signals), in bytes per
            // cwnd-worth of acked data. Unsanitised — a negative step shrinks cwnd on a clean ACK, which
            // the bmc's clean-ACK clause catches. The `2·MSS`-floored loop (cwnd ≥ MSS) always advances
            // ca_acc, so it terminates even for a zero/negative step.
            let step = synth_eval(&self.prog.inc, &self.signals(self.cwnd, acked)) * self.mss as f64;
            while self.ca_acc >= self.cwnd {
                self.ca_acc -= self.cwnd;
                self.cwnd = synth_to_cwnd(self.cwnd as f64 + step, self.mss);
            }
        }
    }

    fn on_dup_ack(&mut self, _now: Instant, flight_size: u32) -> bool {
        self.dup_acks = self.dup_acks.saturating_add(1);
        if self.dup_acks == 3 {
            self.ssthresh = self.loss_target(flight_size);
            self.cwnd = self.ssthresh;
            self.ca_acc = 0;
            true
        } else {
            false
        }
    }

    fn enter_recovery(&mut self, _now: Instant, flight_size: u32) {
        self.ssthresh = self.loss_target(flight_size);
        self.cwnd = self.ssthresh;
        self.ca_acc = 0;
        self.dup_acks = 0;
    }

    fn on_rto(&mut self, _now: Instant, flight_size: u32) {
        self.ssthresh = self.loss_target(flight_size);
        self.cwnd = self.mss; // collapse to one segment (fixed-safe, like every controller)
        self.ca_acc = 0;
    }

    fn set_mss(&mut self, mss: u16) {
        self.mss = mss as u32;
        self.cwnd = self.cwnd.max(self.mss);
        self.ca_acc = 0;
    }

    fn on_ecn(&mut self, _now: Instant, acked: u32, marked: u32) {
        if acked == 0 {
            return;
        }
        self.acked_in_window = self.acked_in_window.saturating_add(acked);
        self.marked_in_window = self.marked_in_window.saturating_add(marked.min(acked));
        if self.acked_in_window < self.window_bytes {
            return;
        }
        let fraction = self.marked_in_window as f64 / self.acked_in_window as f64;
        self.alpha = (1.0 - DCTCP_G) * self.alpha + DCTCP_G * fraction;
        let cwnd_before = self.cwnd;
        if self.marked_in_window > 0 {
            // Synthesised ECN response: cut fraction = ecn(signals); cwnd ← cwnd · (1 − cut). Unsanitised
            // — a negative cut would *grow* cwnd on a mark, which the bmc's ECN-monotonicity clause flags.
            let cut = synth_eval(&self.prog.ecn, &self.signals(self.cwnd, 0));
            self.cwnd = synth_to_cwnd(self.cwnd as f64 * (1.0 - cut), self.mss);
            self.ssthresh = self.cwnd;
            self.ca_acc = 0;
        }
        self.acked_in_window = 0;
        self.marked_in_window = 0;
        self.window_bytes = cwnd_before.max(self.mss);
    }

    fn on_rtt_sample(&mut self, srtt_us: u32) {
        self.srtt_us = srtt_us;
        if srtt_us > 0 {
            self.rtt_min_us = if self.rtt_min_us == 0 { srtt_us } else { self.rtt_min_us.min(srtt_us) };
        }
    }
}

/// Which controller a connection runs. The TCB defaults to [`CcKind::Reno`]; a backend can select
/// another (e.g. from `FERRUM_CC`) before connections form. Drives [`Cc::new`].
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum CcKind {
    #[default]
    Reno,
    Cubic,
    Bbr,
    /// Data Center TCP (RFC 8257) — the L4S/ECN controller; see [`Dctcp`].
    Dctcp,
    /// A controller whose gains are evolved in the deterministic sim; see [`Learned`].
    Learned,
    /// TCP Prague — the L4S scalable, RTT-independent controller; see [`Prague`].
    Prague,
    /// A controller whose control *law* (not just its gains) is a synthesised [`ControlProgram`]
    /// discovered by GP under the bmc safety filter; see [`Synth`].
    Synth,
}

/// The congestion controller the TCB holds. An **enum, not `Box<dyn CongestionControl>`**: dispatch
/// is a `match` with no vtable and no heap allocation, so the send path stays zero-alloc and the
/// whole engine stays sans-IO.
///
/// The `Bbr` variant is much larger than `Reno`/`Cubic` (it carries a delivery-rate sampler, two
/// windowed-max filters, and the BBRv2 inflight model), which trips `large_enum_variant`. We keep
/// it inline rather than `Box`-ing it: the controller is constructed once per connection (never on
/// the per-segment send path), so the variant size is off every hot path, and boxing would
/// reintroduce exactly the per-connection heap allocation this enum-over-`dyn` design exists to
/// avoid. The cost is one Bbr-sized slot per TCB — negligible for this single-host stack.
#[allow(clippy::large_enum_variant)]
pub enum Cc {
    Reno(Reno),
    Cubic(Cubic),
    Bbr(Bbr),
    Dctcp(Dctcp),
    Learned(Learned),
    Prague(Prague),
    Synth(Synth),
}

impl Cc {
    /// Build the controller `kind`, sized for `mss` (each starts at its RFC 6928 initial window).
    pub fn new(kind: CcKind, mss: u16) -> Cc {
        match kind {
            CcKind::Reno => Cc::Reno(Reno::new(mss)),
            CcKind::Cubic => Cc::Cubic(Cubic::new(mss)),
            CcKind::Bbr => Cc::Bbr(Bbr::new(mss)),
            CcKind::Dctcp => Cc::Dctcp(Dctcp::new(mss)),
            CcKind::Learned => Cc::Learned(Learned::new(mss)),
            CcKind::Prague => Cc::Prague(Prague::new(mss)),
            CcKind::Synth => Cc::Synth(Synth::new(mss)),
        }
    }

    /// The smoothed RTT (µs) a [`Cc::Prague`] controller holds, or `None` for any other variant.
    /// Test-only, so a TCB-level test can confirm the `on_rtt_sample` plumbing reached the controller.
    #[cfg(test)]
    pub(crate) fn prague_srtt_dbg(&self) -> Option<u32> {
        match self {
            Cc::Prague(c) => Some(c.srtt_dbg()),
            _ => None,
        }
    }
}

impl CongestionControl for Cc {
    #[inline]
    fn cwnd(&self) -> u32 {
        match self {
            Cc::Reno(c) => c.cwnd(),
            Cc::Cubic(c) => c.cwnd(),
            Cc::Bbr(c) => c.cwnd(),
            Cc::Dctcp(c) => c.cwnd(),
            Cc::Learned(c) => c.cwnd(),
            Cc::Prague(c) => c.cwnd(),
            Cc::Synth(c) => c.cwnd(),
        }
    }

    #[inline]
    fn ssthresh(&self) -> u32 {
        match self {
            Cc::Reno(c) => c.ssthresh(),
            Cc::Cubic(c) => c.ssthresh(),
            Cc::Bbr(c) => c.ssthresh(),
            Cc::Dctcp(c) => c.ssthresh(),
            Cc::Learned(c) => c.ssthresh(),
            Cc::Prague(c) => c.ssthresh(),
            Cc::Synth(c) => c.ssthresh(),
        }
    }

    fn on_ack(&mut self, now: Instant, acked: u32) {
        match self {
            Cc::Reno(c) => c.on_ack(now, acked),
            Cc::Cubic(c) => c.on_ack(now, acked),
            Cc::Bbr(c) => c.on_ack(now, acked),
            Cc::Dctcp(c) => c.on_ack(now, acked),
            Cc::Learned(c) => c.on_ack(now, acked),
            Cc::Prague(c) => c.on_ack(now, acked),
            Cc::Synth(c) => c.on_ack(now, acked),
        }
    }

    fn on_dup_ack(&mut self, now: Instant, flight_size: u32) -> bool {
        match self {
            Cc::Reno(c) => c.on_dup_ack(now, flight_size),
            Cc::Cubic(c) => c.on_dup_ack(now, flight_size),
            Cc::Bbr(c) => c.on_dup_ack(now, flight_size),
            Cc::Dctcp(c) => c.on_dup_ack(now, flight_size),
            Cc::Learned(c) => c.on_dup_ack(now, flight_size),
            Cc::Prague(c) => c.on_dup_ack(now, flight_size),
            Cc::Synth(c) => c.on_dup_ack(now, flight_size),
        }
    }

    fn enter_recovery(&mut self, now: Instant, flight_size: u32) {
        match self {
            Cc::Reno(c) => c.enter_recovery(now, flight_size),
            Cc::Cubic(c) => c.enter_recovery(now, flight_size),
            Cc::Bbr(c) => c.enter_recovery(now, flight_size),
            Cc::Dctcp(c) => c.enter_recovery(now, flight_size),
            Cc::Learned(c) => c.enter_recovery(now, flight_size),
            Cc::Prague(c) => c.enter_recovery(now, flight_size),
            Cc::Synth(c) => c.enter_recovery(now, flight_size),
        }
    }

    fn on_rto(&mut self, now: Instant, flight_size: u32) {
        match self {
            Cc::Reno(c) => c.on_rto(now, flight_size),
            Cc::Cubic(c) => c.on_rto(now, flight_size),
            Cc::Bbr(c) => c.on_rto(now, flight_size),
            Cc::Dctcp(c) => c.on_rto(now, flight_size),
            Cc::Learned(c) => c.on_rto(now, flight_size),
            Cc::Prague(c) => c.on_rto(now, flight_size),
            Cc::Synth(c) => c.on_rto(now, flight_size),
        }
    }

    fn set_mss(&mut self, mss: u16) {
        match self {
            Cc::Reno(c) => c.set_mss(mss),
            Cc::Cubic(c) => c.set_mss(mss),
            Cc::Bbr(c) => c.set_mss(mss),
            Cc::Dctcp(c) => c.set_mss(mss),
            Cc::Learned(c) => c.set_mss(mss),
            Cc::Prague(c) => c.set_mss(mss),
            Cc::Synth(c) => c.set_mss(mss),
        }
    }

    fn pacing_rate(&self) -> Option<u64> {
        match self {
            Cc::Reno(c) => c.pacing_rate(),
            Cc::Cubic(c) => c.pacing_rate(),
            Cc::Bbr(c) => c.pacing_rate(),
            Cc::Dctcp(c) => c.pacing_rate(),
            Cc::Learned(c) => c.pacing_rate(),
            Cc::Prague(c) => c.pacing_rate(),
            Cc::Synth(c) => c.pacing_rate(),
        }
    }

    fn on_transmit(&mut self, now: Instant, seq_end: SeqNumber, bytes: u32, inflight: u32, app_limited: bool) {
        match self {
            Cc::Reno(c) => c.on_transmit(now, seq_end, bytes, inflight, app_limited),
            Cc::Cubic(c) => c.on_transmit(now, seq_end, bytes, inflight, app_limited),
            Cc::Bbr(c) => c.on_transmit(now, seq_end, bytes, inflight, app_limited),
            Cc::Dctcp(c) => c.on_transmit(now, seq_end, bytes, inflight, app_limited),
            Cc::Learned(c) => c.on_transmit(now, seq_end, bytes, inflight, app_limited),
            Cc::Prague(c) => c.on_transmit(now, seq_end, bytes, inflight, app_limited),
            Cc::Synth(c) => c.on_transmit(now, seq_end, bytes, inflight, app_limited),
        }
    }

    fn on_ack_sample(&mut self, now: Instant, snd_una: SeqNumber, inflight: u32, acked: u32, pipe: u32, in_recovery: bool) {
        match self {
            Cc::Reno(c) => c.on_ack_sample(now, snd_una, inflight, acked, pipe, in_recovery),
            Cc::Cubic(c) => c.on_ack_sample(now, snd_una, inflight, acked, pipe, in_recovery),
            Cc::Bbr(c) => c.on_ack_sample(now, snd_una, inflight, acked, pipe, in_recovery),
            Cc::Dctcp(c) => c.on_ack_sample(now, snd_una, inflight, acked, pipe, in_recovery),
            Cc::Learned(c) => c.on_ack_sample(now, snd_una, inflight, acked, pipe, in_recovery),
            Cc::Prague(c) => c.on_ack_sample(now, snd_una, inflight, acked, pipe, in_recovery),
            Cc::Synth(c) => c.on_ack_sample(now, snd_una, inflight, acked, pipe, in_recovery),
        }
    }

    fn on_ecn(&mut self, now: Instant, acked: u32, marked: u32) {
        match self {
            Cc::Reno(c) => c.on_ecn(now, acked, marked),
            Cc::Cubic(c) => c.on_ecn(now, acked, marked),
            Cc::Bbr(c) => c.on_ecn(now, acked, marked),
            Cc::Dctcp(c) => c.on_ecn(now, acked, marked),
            Cc::Learned(c) => c.on_ecn(now, acked, marked),
            Cc::Prague(c) => c.on_ecn(now, acked, marked),
            Cc::Synth(c) => c.on_ecn(now, acked, marked),
        }
    }

    fn on_rtt_sample(&mut self, srtt_us: u32) {
        match self {
            Cc::Reno(c) => c.on_rtt_sample(srtt_us),
            Cc::Cubic(c) => c.on_rtt_sample(srtt_us),
            Cc::Bbr(c) => c.on_rtt_sample(srtt_us),
            Cc::Dctcp(c) => c.on_rtt_sample(srtt_us),
            Cc::Learned(c) => c.on_rtt_sample(srtt_us),
            Cc::Prague(c) => c.on_rtt_sample(srtt_us),
            Cc::Synth(c) => c.on_rtt_sample(srtt_us),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::Instant;

    // Reno is ACK-clocked: the instant is threaded through the trait (for CUBIC/BBR) but Reno
    // ignores it, so every test below can pass a fixed clock.
    const NOW: Instant = Instant::ZERO;

    #[test]
    fn initial_window_matches_rfc6928() {
        assert_eq!(initial_window(1460), 14600);
        assert_eq!(initial_window(536), 5360);
        assert_eq!(initial_window(64), 640);
        assert_eq!(initial_window(9000), 18000); // max(18000,14600) then min(90000, .)
    }

    #[test]
    fn slow_start_grows_by_acked_capped_at_mss() {
        let mut t = Reno::new(1460); // cwnd = 14600, ssthresh = MAX
        t.on_ack(NOW, 1460);
        assert_eq!(t.cwnd(), 16060);
        t.on_ack(NOW, 5000); // capped at one MSS of growth
        assert_eq!(t.cwnd(), 17520);
    }

    #[test]
    fn congestion_avoidance_counts_bytes_with_while_loop() {
        let mut t = Reno::new(1000);
        // Force CA: a loss drops ssthresh, then slow-start back up to it.
        t.on_rto(NOW, 4000); // ssthresh = max(2000, 2000) = 2000, cwnd = 1000
        assert_eq!(t.cwnd(), 1000);
        assert_eq!(t.ssthresh(), 2000);
        t.on_ack(NOW, 1000); // slow start: cwnd 1000 -> 2000 (now == ssthresh -> CA)
        assert_eq!(t.cwnd(), 2000);
        t.on_ack(NOW, 1000); // CA: ca_acc=1000 < cwnd -> no growth yet
        assert_eq!(t.cwnd(), 2000);
        t.on_ack(NOW, 1000); // CA: ca_acc=2000 >= cwnd -> +1 MSS
        assert_eq!(t.cwnd(), 3000);
        // A single large cumulative ACK credits multiple MSS via the while loop.
        t.on_ack(NOW, 7000); // ca_acc 0+7000; 7000>=3000 ->4000(acc4000); 4000>=4000 ->5000(acc0)
        assert_eq!(t.cwnd(), 5000);
    }

    #[test]
    fn loss_uses_flight_size_not_cwnd() {
        let mut t = Reno::new(1000);
        for _ in 0..20 {
            t.on_ack(NOW, 1000); // grow cwnd well past any plausible flight size
        }
        assert!(t.cwnd() > 14600);
        let third = t.on_dup_ack(NOW, 4000) || t.on_dup_ack(NOW, 4000) || t.on_dup_ack(NOW, 4000);
        assert!(third); // the 3rd dup ACK triggers recovery
        assert_eq!(t.ssthresh(), 2000); // 4000/2, from FlightSize — not cwnd/2
        assert_eq!(t.cwnd(), 2000); // Reno fast recovery: cwnd = ssthresh (not 1 MSS)
    }

    #[test]
    fn dup_ack_fires_only_on_third() {
        let mut t = Reno::new(1460);
        assert!(!t.on_dup_ack(NOW, 5000));
        assert!(!t.on_dup_ack(NOW, 5000));
        assert!(t.on_dup_ack(NOW, 5000));
        assert!(!t.on_dup_ack(NOW, 5000)); // 4th and beyond do not re-trigger
        assert!(!t.on_dup_ack(NOW, 5000));
    }

    #[test]
    fn enter_recovery_halves_from_flight_size() {
        let mut t = Reno::new(1000);
        for _ in 0..20 {
            t.on_ack(NOW, 1000); // grow cwnd well past any plausible flight size
        }
        assert!(t.cwnd() > 14600);
        t.enter_recovery(NOW, 8000); // halve from FlightSize, not cwnd
        assert_eq!(t.ssthresh(), 4000);
        assert_eq!(t.cwnd(), 4000); // fast recovery: cwnd = ssthresh (not 1 MSS)
    }

    #[test]
    fn rto_collapses_to_one_mss() {
        let mut t = Reno::new(1460);
        for _ in 0..10 {
            t.on_ack(NOW, 1460);
        }
        t.on_rto(NOW, 10_000);
        assert_eq!(t.cwnd(), 1460);
        assert_eq!(t.ssthresh(), 5000);
    }

    #[test]
    fn cc_enum_dispatches_to_reno() {
        // The seam itself: a `Cc` built as Reno must behave exactly like the bare controller —
        // the match dispatch adds no behavior, it only routes. (CUBIC/BBR add variants here.)
        let mut bare = Reno::new(1460);
        let mut cc = Cc::new(CcKind::Reno, 1460);
        assert_eq!(cc.cwnd(), bare.cwnd());
        assert_eq!(cc.ssthresh(), bare.ssthresh());
        cc.on_ack(NOW, 1460);
        bare.on_ack(NOW, 1460);
        assert_eq!(cc.cwnd(), bare.cwnd());
        assert!(!cc.on_dup_ack(NOW, 8000));
        assert!(!cc.on_dup_ack(NOW, 8000));
        assert!(cc.on_dup_ack(NOW, 8000)); // third dup-ACK fires through the enum
        assert_eq!(cc.cwnd(), cc.ssthresh());
        cc.set_mss(1000);
        cc.on_rto(NOW, 6000);
        assert_eq!(cc.cwnd(), 1000); // collapsed to the new one-MSS
    }

    // ── CUBIC (RFC 8312) ────────────────────────────────────────────────────────────────────────

    #[test]
    fn cubic_root_is_accurate() {
        assert!((cubic_root(27.0) - 3.0).abs() < 1e-9);
        assert!((cubic_root(8.0) - 2.0).abs() < 1e-9);
        assert!((cubic_root(1000.0) - 10.0).abs() < 1e-9);
        assert!((cubic_root(0.001) - 0.1).abs() < 1e-9);
        assert_eq!(cubic_root(0.0), 0.0);
        assert_eq!(cubic_root(-5.0), 0.0); // non-positive input is clamped to 0
    }

    #[test]
    fn cubic_window_passes_through_post_loss_and_w_max() {
        // After a β = 0.7 cut from W_max = 10 segments, the window is 7; K = cbrt((10 − 7)/C).
        let w_max = 10.0;
        let reduced = 7.0;
        let k = cubic_root((w_max - reduced) / CUBIC_C);
        // At t = 0 the curve sits at the reduced window; at t = K it reaches W_max exactly.
        assert!((cubic_window(w_max, k, 0.0) - reduced).abs() < 1e-9);
        assert!((cubic_window(w_max, k, k) - w_max).abs() < 1e-9);
        // Past K the curve is convex, probing above W_max for new capacity.
        assert!(cubic_window(w_max, k, k + 1.0) > w_max);
    }

    #[test]
    fn cubic_slow_starts_until_first_loss() {
        let mut c = Cubic::new(1000);
        assert_eq!(c.cwnd(), initial_window(1000)); // RFC 6928 IW, identical to Reno
        c.on_ack(NOW, 1000);
        assert_eq!(c.cwnd(), initial_window(1000) + 1000); // exponential, +1 MSS per ACK
    }

    #[test]
    fn cubic_cuts_to_beta_of_cwnd_on_three_dup_acks() {
        let mut c = Cubic::new(1000); // cwnd = 10000
        assert!(!c.on_dup_ack(NOW, 10000));
        assert!(!c.on_dup_ack(NOW, 10000));
        assert!(c.on_dup_ack(NOW, 10000)); // 3rd fires
        assert_eq!(c.ssthresh(), 7000); // 0.7 * 10000 (gentler than Reno's halving)
        assert_eq!(c.cwnd(), 7000); // fast recovery: cwnd = ssthresh
        assert!((c.w_max - 10.0).abs() < 1e-9); // W_max recorded in segments
    }

    #[test]
    fn cubic_rto_collapses_to_one_mss_and_restarts_slow_start() {
        let mut c = Cubic::new(1000);
        c.on_rto(NOW, 10000);
        assert_eq!(c.cwnd(), 1000); // one MSS
        assert_eq!(c.ssthresh(), 7000); // 0.7 * 10000
        assert!(c.cwnd() < c.ssthresh()); // below ssthresh -> slow start again
    }

    #[test]
    fn cubic_grows_along_the_curve_after_a_loss() {
        let t0 = Instant::from_millis(0);
        let mut c = Cubic::new(1000);
        // Loss from cwnd = 10000: W_max = 10 seg, cwnd = ssthresh = 7000.
        c.on_dup_ack(t0, 10000);
        c.on_dup_ack(t0, 10000);
        c.on_dup_ack(t0, 10000);
        assert_eq!(c.cwnd(), 7000);
        // Drive congestion avoidance: feed one segment per ACK while the clock advances past K
        // (≈ 1.957 s). cwnd must be monotonic non-decreasing and, in the convex region, climb back
        // past W_max (10000).
        let mut prev = c.cwnd();
        for ms in (0u64..4000).step_by(20) {
            c.on_ack(t0.plus_millis(ms), 1000);
            assert!(c.cwnd() >= prev, "cwnd is monotonic non-decreasing in congestion avoidance");
            prev = c.cwnd();
        }
        assert!(c.cwnd() > 10000, "the convex region probes past W_max; got {}", c.cwnd());
    }

    #[test]
    fn cubic_tcp_friendly_floor_grows_even_without_time() {
        let now = Instant::from_millis(0);
        let mut c = Cubic::new(1000);
        c.on_dup_ack(now, 10000);
        c.on_dup_ack(now, 10000);
        c.on_dup_ack(now, 10000);
        assert_eq!(c.cwnd(), 7000);
        // Hold the clock fixed so the cubic curve never advances (its target stays at the post-loss
        // window). Only the TCP-friendly (Reno-with-β) floor can grow cwnd here — and it must, or
        // CUBIC would stall below standard TCP on a low-BDP path.
        for _ in 0..100 {
            c.on_ack(now, 1000);
        }
        assert!(c.cwnd() > 7000, "TCP-friendly floor grows cwnd even at t = 0; got {}", c.cwnd());
    }

    #[test]
    fn cubic_fast_convergence_pulls_w_max_in_on_a_lower_loss() {
        let now = Instant::from_millis(0);
        let mut c = Cubic::new(1000);
        // First loss at cwnd = 10000 (10 seg): no prior max, so W_max = 10 (no fast convergence).
        c.on_dup_ack(now, 10000);
        c.on_dup_ack(now, 10000);
        c.on_dup_ack(now, 10000);
        assert!((c.w_max - 10.0).abs() < 1e-9);
        assert!((c.w_last_max - 10.0).abs() < 1e-9);
        // A second loss at a *lower* window (8 seg < W_last_max) means capacity dropped: fast
        // convergence pulls W_max in to 8 * (1 + 0.7)/2 = 6.8, below the loss window.
        c.cwnd = 8000;
        c.dup_acks = 0;
        c.on_dup_ack(now, 8000);
        c.on_dup_ack(now, 8000);
        c.on_dup_ack(now, 8000);
        assert!((c.w_max - 6.8).abs() < 1e-9, "fast convergence sets W_max below the loss window");
        assert!((c.w_last_max - 8.0).abs() < 1e-9);
    }

    #[test]
    fn cc_enum_dispatches_to_cubic() {
        let mut bare = Cubic::new(1460);
        let mut cc = Cc::new(CcKind::Cubic, 1460);
        assert!(matches!(cc, Cc::Cubic(_)));
        assert_eq!(cc.cwnd(), bare.cwnd());
        cc.on_ack(NOW, 1460);
        bare.on_ack(NOW, 1460);
        assert_eq!(cc.cwnd(), bare.cwnd());
        assert!(!cc.on_dup_ack(NOW, 14600));
        assert!(!cc.on_dup_ack(NOW, 14600));
        assert!(cc.on_dup_ack(NOW, 14600)); // 3rd dup-ACK fires through the enum
        assert_eq!(cc.cwnd(), cc.ssthresh()); // cut to β·cwnd
    }

    // ── DCTCP (RFC 8257) ──────────────────────────────────────────────────────────────────────────

    #[test]
    fn dctcp_slow_starts_and_grows_exactly_like_reno() {
        // Additive increase / slow start is byte-for-byte Reno (the ECN reaction is separate), so
        // an unmarked DCTCP flow is indistinguishable from Reno on the window.
        let mut d = Dctcp::new(1460);
        let mut r = Reno::new(1460);
        assert_eq!(d.cwnd(), r.cwnd()); // same RFC 6928 initial window
        for acked in [1460u32, 5000, 1460, 1460, 9999] {
            d.on_ack(NOW, acked);
            r.on_ack(NOW, acked);
            assert_eq!(d.cwnd(), r.cwnd(), "DCTCP additive increase must equal Reno's");
        }
    }

    #[test]
    fn dctcp_loss_response_is_reno_like() {
        // Genuine loss (3 dup-ACKs, then an RTO) is handled exactly as Reno — DCTCP only replaces
        // the *ECN* reaction, never the loss reaction.
        let mut d = Dctcp::new(1000);
        for _ in 0..20 {
            d.on_ack(NOW, 1000);
        }
        assert!(!d.on_dup_ack(NOW, 8000));
        assert!(!d.on_dup_ack(NOW, 8000));
        assert!(d.on_dup_ack(NOW, 8000)); // third dup-ACK
        assert_eq!(d.ssthresh(), 4000); // FlightSize/2, like Reno
        assert_eq!(d.cwnd(), 4000); // fast recovery: cwnd = ssthresh
        d.on_rto(NOW, 6000);
        assert_eq!(d.cwnd(), 1000); // RTO collapses to one MSS
        assert_eq!(d.ssthresh(), 3000);
    }

    #[test]
    fn dctcp_unmarked_window_never_cuts_and_decays_alpha() {
        let mut d = Dctcp::new(1000); // cwnd = 10000, window_bytes = 10000, alpha = 1.0
        // Two full windows of acks with zero marks: cwnd is untouched (on_ecn never grows it; only
        // on_ack does), and alpha decays toward 0 since no congestion is observed.
        for _ in 0..20 {
            d.on_ecn(NOW, 1000, 0);
        }
        assert_eq!(d.cwnd(), 10000, "an unmarked window must not cut cwnd");
        assert!(d.alpha < 1.0, "alpha decays without marks, got {}", d.alpha);
    }

    #[test]
    fn dctcp_fully_marked_window_halves() {
        let mut d = Dctcp::new(1000); // cwnd = 10000, window_bytes = 10000, alpha = 1.0
        // A whole window marked CE: fraction = 1, alpha stays 1, so the cut degrades to a Reno-style
        // halving — heavy marking earns a heavy response.
        for _ in 0..10 {
            d.on_ecn(NOW, 1000, 1000);
        }
        assert!((d.alpha - 1.0).abs() < 1e-9, "alpha stays 1 under full marking, got {}", d.alpha);
        assert_eq!(d.cwnd(), 5000, "cwnd ×= 1 − α/2 = 0.5 under full marking");
        assert_eq!(d.ssthresh(), 5000, "the cut drops into congestion avoidance");
    }

    #[test]
    fn dctcp_holds_a_high_window_under_light_marking() {
        // The defining DCTCP property: under a steady *light* marking level (~1/16 of bytes), alpha
        // converges near that fraction and the per-window cut is tiny, so the flow holds a high
        // window — where a loss-based controller halving on every marked round would collapse.
        let mut d = Dctcp::new(1000);
        d.on_rto(NOW, 20_000); // drop into congestion avoidance (ssthresh = 10000, cwnd = 1000)
        for _ in 0..3_000 {
            d.on_ack(NOW, 1000);
            d.on_ecn(NOW, 1000, 1000 / 16); // ~6% of bytes marked, every ack
        }
        // Converged: alpha near the ~1/16 marked fraction, and the window parked high — the additive
        // increase balances the gentle proportional cut at a large cwnd, not near one MSS.
        assert!(d.alpha < 0.2, "alpha converges near the ~1/16 marked fraction, got {}", d.alpha);
        assert!(d.cwnd() > 12_000, "DCTCP holds a high window under light marking; cwnd {}", d.cwnd());
    }

    #[test]
    fn on_ecn_is_a_noop_for_non_dctcp_controllers() {
        // The byte-identical guarantee: feeding ECN marks to Reno/CUBIC/BBR must not move their
        // windows at all (the TCB only ever passes marks on a DCTCP connection, but the trait
        // default must still be inert if it ever did).
        for kind in [CcKind::Reno, CcKind::Cubic, CcKind::Bbr] {
            let mut cc = Cc::new(kind, 1460);
            let before = cc.cwnd();
            for _ in 0..100 {
                cc.on_ecn(NOW, 1460, 1460);
            }
            assert_eq!(cc.cwnd(), before, "{kind:?} must ignore ECN marks");
        }
    }

    #[test]
    fn cc_enum_dispatches_to_dctcp() {
        let mut bare = Dctcp::new(1460);
        let mut cc = Cc::new(CcKind::Dctcp, 1460);
        assert!(matches!(cc, Cc::Dctcp(_)));
        assert_eq!(cc.cwnd(), bare.cwnd());
        // A full window of marked acks routed through the enum must match the bare controller —
        // the on_ecn dispatch arm adds no behavior, it only routes.
        for _ in 0..10 {
            cc.on_ecn(NOW, 1460, 1460);
            bare.on_ecn(NOW, 1460, 1460);
        }
        assert_eq!(cc.cwnd(), bare.cwnd());
        assert!(cc.cwnd() < initial_window(1460), "the marked window cut fired through the enum");
    }

    // ── Learned (evolved) ───────────────────────────────────────────────────────────────────────────

    #[test]
    fn learned_default_genome_is_reno_on_the_loss_path() {
        // The DEFAULT genome (ai_gain 1, md_loss 0.5) is exactly Reno on additive increase and loss.
        let mut l = Learned::with_params(1000, LearnedParams::DEFAULT);
        let mut r = Reno::new(1000);
        for _ in 0..20 {
            l.on_ack(NOW, 1000);
            r.on_ack(NOW, 1000);
        }
        assert_eq!(l.cwnd(), r.cwnd(), "additive increase matches Reno at ai_gain = 1");
        assert!(!l.on_dup_ack(NOW, 8000));
        assert!(!l.on_dup_ack(NOW, 8000));
        assert!(l.on_dup_ack(NOW, 8000));
        assert_eq!(l.ssthresh(), 4000); // FlightSize/2 at md_loss = 0.5
        assert_eq!(l.cwnd(), 4000);
        l.on_rto(NOW, 6000);
        assert_eq!(l.cwnd(), 1000);
    }

    #[test]
    fn learned_default_genome_matches_dctcp_ecn_response() {
        // DEFAULT ecn_a = 0.5, ecn_b = 0, ecn_max = 0.5: a fully-marked window cuts cwnd by α/2 = 0.5,
        // exactly DCTCP's response — the genome family contains DCTCP as a point.
        let mut l = Learned::with_params(1000, LearnedParams::DEFAULT); // cwnd 10000, window 10000, α 1
        for _ in 0..10 {
            l.on_ecn(NOW, 1000, 1000);
        }
        assert_eq!(l.cwnd(), 5000, "the DEFAULT genome reproduces DCTCP's fully-marked halving");
    }

    #[test]
    fn learned_baked_genome_holds_a_higher_window_than_dctcp_under_marking() {
        // The evolved (baked) genome uses a gentler ECN response than DCTCP, so under identical light
        // marking it parks a higher window — the source of its held-out throughput win over DCTCP.
        let mut baked = Learned::with_params(1000, LearnedParams::BAKED);
        let mut dctcp = Dctcp::new(1000);
        for _ in 0..2_000 {
            baked.on_ack(NOW, 1000);
            baked.on_ecn(NOW, 1000, 1000 / 16);
            dctcp.on_ack(NOW, 1000);
            dctcp.on_ecn(NOW, 1000, 1000 / 16);
        }
        assert!(
            baked.cwnd() > dctcp.cwnd(),
            "the gentler evolved ECN response holds a higher window: baked {} vs dctcp {}",
            baked.cwnd(),
            dctcp.cwnd()
        );
    }

    #[test]
    fn learned_sanitizes_a_pathological_genome() {
        // Out-of-range genes (negative increase, window-growing-on-loss, unbounded cut) are clamped...
        let bad = LearnedParams { ai_gain: -3.0, md_loss: 2.0, ecn_a: -1.0, ecn_b: 9.0, ecn_max: 5.0 };
        let s = bad.sanitized();
        assert!(s.ai_gain >= 0.05 && s.md_loss <= 0.95 && s.ecn_a >= 0.0 && s.ecn_max <= 0.95);
        // ...so a controller built from the worst genome is still stable: it grows on ACKs and never
        // grows on a loss (RTO collapses to one MSS).
        let mut l = Learned::with_params(1000, bad);
        let c0 = l.cwnd();
        l.on_ack(NOW, 1000);
        assert!(l.cwnd() >= c0);
        l.on_rto(NOW, 8000);
        assert_eq!(l.cwnd(), 1000);
    }

    #[test]
    fn cc_enum_dispatches_to_learned() {
        set_learned_override(None); // ensure the baked genome is used (no leaked training override)
        let mut cc = Cc::new(CcKind::Learned, 1460);
        assert!(matches!(cc, Cc::Learned(_)));
        let bare = Learned::with_params(1460, LearnedParams::BAKED);
        assert_eq!(cc.cwnd(), bare.cwnd(), "CcKind::Learned uses the baked genome");
        cc.on_ack(NOW, 1460);
        assert!(cc.cwnd() > bare.cwnd(), "slow start grows through the enum");
    }

    #[test]
    fn prague_additive_increase_is_rtt_independent() {
        let mut p = Prague::new(1000);
        // Before any RTT sample the step is one MSS (Reno's), so a Prague flow that hasn't measured
        // RTT yet behaves like DCTCP.
        assert_eq!(p.ai_step(), 1000);
        // At the reference RTT the step is exactly one MSS.
        p.on_rtt_sample(PRAGUE_RTT_REF_US as u32);
        assert_eq!(p.ai_step(), 1000);
        // At twice the reference RTT the per-RTT step doubles — so the increase *per second* (step /
        // RTT) is unchanged, and a long-RTT flow no longer loses to a short-RTT one.
        p.on_rtt_sample(2 * PRAGUE_RTT_REF_US as u32);
        assert_eq!(p.ai_step(), 2000);
        // A very short RTT is floored at mss/4, a very long one capped at 4·mss — the controller can
        // never stall or run away on a pathological RTT.
        p.on_rtt_sample(PRAGUE_RTT_REF_US as u32 / 8);
        assert_eq!(p.ai_step(), 250, "floored at mss/4");
        p.on_rtt_sample(100 * PRAGUE_RTT_REF_US as u32);
        assert_eq!(p.ai_step(), 4000, "capped at 4·mss");
    }

    #[test]
    fn prague_growth_per_second_is_constant_across_rtt() {
        // The RTT-independence property: two CA flows at 1× and 2× the reference RTT, driven over the
        // *same wall-clock span*. Because growth is RTT-clocked, the 2× flow sees half as many acks in
        // that span — so we hand it half the ack count. RTT-independence means the doubled per-RTT step
        // exactly compensates, and both flows grow by the same number of bytes (equal shares).
        fn grown_bytes(rtt_us: u32, acks_in_span: u32) -> u32 {
            let mut p = Prague::new(1000);
            p.on_rto(NOW, 20_000); // drop into congestion avoidance (ssthresh = 10000, cwnd = 1000)
            p.on_rtt_sample(rtt_us);
            let start = p.cwnd();
            for _ in 0..acks_in_span {
                p.on_ack(NOW, 1000);
            }
            p.cwnd() - start
        }
        // Equal wall-clock span: the 1× flow sees 200 acks, the 2× flow (half the RTTs) sees 100.
        let short = grown_bytes(PRAGUE_RTT_REF_US as u32, 200);
        let long = grown_bytes(2 * PRAGUE_RTT_REF_US as u32, 100);
        // The two grow by essentially the same number of bytes (within 10% either way) — neither RTT is
        // penalised. A classic +1-MSS-per-RTT controller would have grown the long flow only ~half as
        // much (it would fail the lower bound); a controller that ignored RTT and over-stepped the long
        // flow would fail the upper bound. Both directions are pinned.
        assert!(long * 10 >= short * 9, "the long-RTT flow is not RTT-penalised: long {long} vs short {short}");
        assert!(short * 10 >= long * 9, "the long-RTT flow does not over-grow either: long {long} vs short {short}");
    }

    #[test]
    fn prague_fully_marked_window_halves_like_dctcp() {
        // Prague's ECN reaction is DCTCP's exactly: a fully CE-marked window degrades to a Reno-style
        // halving (heavy marking earns a heavy response).
        let mut p = Prague::new(1000);
        for _ in 0..10 {
            p.on_ecn(NOW, 1000, 1000);
        }
        assert!((p.alpha - 1.0).abs() < 1e-9, "alpha stays 1 under full marking, got {}", p.alpha);
        assert_eq!(p.cwnd(), 5000, "cwnd ×= 1 − α/2 = 0.5 under full marking");
        assert_eq!(p.ssthresh(), 5000);
    }

    #[test]
    fn prague_holds_a_high_window_under_light_marking() {
        // The scalable property: under steady light marking Prague (like DCTCP) holds a high window
        // rather than collapsing. Driven at the reference RTT so the additive step is one MSS.
        let mut p = Prague::new(1000);
        p.on_rto(NOW, 20_000);
        p.on_rtt_sample(PRAGUE_RTT_REF_US as u32);
        for _ in 0..3_000 {
            p.on_ack(NOW, 1000);
            p.on_ecn(NOW, 1000, 1000 / 16); // ~6% marked
        }
        assert!(p.alpha < 0.2, "alpha converges near the ~1/16 marked fraction, got {}", p.alpha);
        assert!(p.cwnd() > 12_000, "Prague holds a high window under light marking; cwnd {}", p.cwnd());
    }

    #[test]
    fn prague_loss_response_is_classic_reno() {
        // Genuine loss falls back to the classic Reno halving — the "be safe with classic drop-based
        // traffic" Prague requirement — not the gentle ECN cut.
        let mut p = Prague::new(1000);
        for _ in 0..20 {
            p.on_ack(NOW, 1000);
        }
        let third = p.on_dup_ack(NOW, 8000) || p.on_dup_ack(NOW, 8000) || p.on_dup_ack(NOW, 8000);
        assert!(third, "the 3rd dup-ACK triggers recovery");
        assert_eq!(p.ssthresh(), 4000, "classic Reno halving from FlightSize (8000/2)");
        assert_eq!(p.cwnd(), 4000);
    }

    #[test]
    fn cc_enum_dispatches_to_prague() {
        let mut cc = Cc::new(CcKind::Prague, 1460);
        assert!(matches!(cc, Cc::Prague(_)));
        assert_eq!(cc.cwnd(), initial_window(1460));
        cc.on_ack(NOW, 1460);
        assert!(cc.cwnd() > initial_window(1460), "slow start grows through the enum");
        // The RTT hook reaches the Prague controller through the enum dispatch.
        cc.on_rtt_sample(2 * PRAGUE_RTT_REF_US as u32);
        if let Cc::Prague(p) = &cc {
            assert_eq!(p.ai_step(), 2920, "2·mss at twice the reference RTT");
        }
    }

    // ── synthesised control-law machine ────────────────────────────────────────────────────────────

    /// The SSA interpreter computes a hand-built program exactly, including protected division and the
    /// shared-register SSA discipline (a later instruction reading an earlier computed register).
    #[test]
    fn synth_interpreter_evaluates_a_hand_built_program() {
        // inputs: r0..r7 = [cwnd, flight, acked, alpha, srtt, 0.5, 1, 2]
        let inputs = [10.0, 8.0, 2.0, 0.25, 1.5, 0.5, 1.0, 2.0];
        // A program: r8 = r0 + r1 (=18); r9 = r8 * r5 (=9); then carry r9 to the output (r15).
        let mut prog = [Instr { op: SynthOp::Max, a: 0, b: 0 }; SYNTH_PROG_LEN];
        prog[0] = Instr { op: SynthOp::Add, a: 0, b: 1 }; // r8 = 18
        prog[1] = Instr { op: SynthOp::Mul, a: 8, b: 5 }; // r9 = 18 * 0.5 = 9
        for (i, slot) in prog.iter_mut().enumerate().skip(2) {
            let prev = (SYNTH_REGS_IN + i - 1) as u8;
            *slot = Instr { op: SynthOp::Max, a: prev, b: prev }; // identity carry
        }
        assert_eq!(synth_eval(&prog, &inputs), 9.0);

        // Protected division: r8 = r0 / (r5 - r5) = 10 / 0 -> 0 (not inf/NaN).
        let mut dz = [Instr { op: SynthOp::Max, a: 0, b: 0 }; SYNTH_PROG_LEN];
        dz[0] = Instr { op: SynthOp::Sub, a: 5, b: 5 }; // r8 = 0
        dz[1] = Instr { op: SynthOp::Div, a: 0, b: 8 }; // r9 = 10 / 0 -> protected 0
        for (i, slot) in dz.iter_mut().enumerate().skip(2) {
            let prev = (SYNTH_REGS_IN + i - 1) as u8;
            *slot = Instr { op: SynthOp::Max, a: prev, b: prev };
        }
        assert_eq!(synth_eval(&dz, &inputs), 0.0);

        // An out-of-range / forward operand index is clamped to the last valid register, so it never
        // reads uninitialised state — the program stays total.
        let oob = [Instr { op: SynthOp::Add, a: 200, b: 0 }; SYNTH_PROG_LEN];
        assert!(synth_eval(&oob, &inputs).is_finite());
    }

    /// The NaN/inf guard keeps every register finite and bounded — so a downstream `u32` cast is always
    /// safe — without using any transcendental intrinsic.
    #[test]
    fn synth_guard_bounds_every_register() {
        assert_eq!(synth_guard(0.0 / 1.0), 0.0);
        assert_eq!(synth_guard(f64::INFINITY), SYNTH_CAP);
        assert_eq!(synth_guard(f64::NEG_INFINITY), -SYNTH_CAP);
        assert_eq!(synth_guard(f64::NAN), 0.0); // v != v branch
        assert_eq!(synth_guard(1e30), SYNTH_CAP);
        assert_eq!(synth_guard(42.0), 42.0);
    }

    /// The AIMD seed program (`ControlProgram::AIMD`) reproduces DCTCP **exactly** — driven through an
    /// identical event sequence with FlightSizes that are whole multiples of the MSS (so the loss step's
    /// segment normalisation round-trips with no rounding), `Synth` and `Dctcp` track the same cwnd and
    /// ssthresh at every step. So the synthesised default is a faithful re-expression of the hand-written
    /// controller, and the GP's warm start is genuinely DCTCP — the reference for "did it find something
    /// new?".
    #[test]
    fn synth_aimd_program_reproduces_dctcp() {
        let mss = 1000u16;
        let mut s = Synth::with_program(mss, ControlProgram::AIMD);
        let mut d = Dctcp::new(mss);
        let w = 10 * mss as u32;
        // A mix of clean ACKs, ECN-marked rounds, and the three loss signals — flights are k·MSS.
        let acks = [w, mss as u32, w, w];
        let marks = [(w, 0u32), (w, mss as u32), (w, w)];
        let flights = [2 * mss as u32, 10 * mss as u32, 40 * mss as u32];
        for round in 0..6 {
            for &a in &acks {
                s.on_ack(NOW, a);
                d.on_ack(NOW, a);
                assert_eq!(s.cwnd(), d.cwnd(), "ack cwnd diverged at round {round}");
            }
            for &(a, m) in &marks {
                s.on_ecn(NOW, a, m);
                d.on_ecn(NOW, a, m);
                assert_eq!(s.cwnd(), d.cwnd(), "ecn cwnd diverged at round {round}");
                assert_eq!(s.ssthresh(), d.ssthresh(), "ecn ssthresh diverged at round {round}");
            }
            let f = flights[round % flights.len()];
            // A clean third dup-ACK loss, then an RTO, exercising both loss paths.
            let _ = s.on_dup_ack(NOW, f);
            let _ = s.on_dup_ack(NOW, f);
            let st = s.on_dup_ack(NOW, f);
            let dt = d.on_dup_ack(NOW, f) || d.on_dup_ack(NOW, f) || d.on_dup_ack(NOW, f);
            assert_eq!(st, dt);
            assert_eq!(s.cwnd(), d.cwnd(), "loss cwnd diverged at round {round}");
            assert_eq!(s.ssthresh(), d.ssthresh(), "loss ssthresh diverged at round {round}");
            s.on_rto(NOW, f);
            d.on_rto(NOW, f);
            assert_eq!(s.cwnd(), d.cwnd(), "rto cwnd diverged at round {round}");
            assert_eq!(s.ssthresh(), d.ssthresh(), "rto ssthresh diverged at round {round}");
        }
    }

    #[test]
    fn cc_enum_dispatches_to_synth() {
        let mut cc = Cc::new(CcKind::Synth, 1460);
        assert!(matches!(cc, Cc::Synth(_)));
        assert_eq!(cc.cwnd(), initial_window(1460));
        cc.on_ack(NOW, 1460);
        assert!(cc.cwnd() > initial_window(1460), "slow start grows through the enum");
    }

    /// The synthesised law's ECN sub-program (`BAKED_SYNTH.ecn`) **rediscovered DCTCP's exact `α/2`
    /// response**: free to pick any program over the signals, the GP returned `0.5 · α` for every `α`.
    /// This pins the *value* (the de-risk's sharp negative, machine-checked) — DCTCP's `α/2` is a fixed
    /// point the search keeps returning to. It is NOT a proof of optimality (the GP is a heuristic search,
    /// not an exhaustive neighbourhood check); proving `α/2` optimal in-class would need to exhaust a small
    /// ECN-response grammar, which this test does not do.
    #[test]
    fn synth_baked_ecn_response_rediscovered_dctcp() {
        for &alpha in &[0.0, 0.1, 0.3, 0.5, 0.9, 1.0] {
            // signals = [cwnd_seg, flight_seg, acked_seg, α, srtt_ratio, 0.5, 1, 2]
            let inputs = [12.0, 12.0, 0.0, alpha, 1.0, 0.5, 1.0, 2.0];
            let cut = synth_eval(&ControlProgram::BAKED_SYNTH.ecn, &inputs);
            assert!((cut - alpha * 0.5).abs() < 1e-12, "ecn cut at α={alpha} is {cut}, not α/2");
        }
        // The increase, by contrast, is genuinely new structure — max(0.5, α, acked_seg), not a constant.
        let inputs = [12.0, 12.0, 3.0, 0.2, 1.0, 0.5, 1.0, 2.0]; // acked_seg = 3
        let step = synth_eval(&ControlProgram::BAKED_SYNTH.inc, &inputs);
        assert_eq!(step, 3.0, "increase rises with acked_seg (= max(0.5, 0.2, 3.0))");
    }

    /// The **exhaustively-proven** single-op ECN optimum is a **delay-based** response: `cut = srtt/rtt_min
    /// − 1`. Unlike the GP's `α/2` (which ignores delay), it backs off proportional to the measured queuing
    /// delay — zero cut when the RTT is at its minimum (no queue), rising as the queue builds. This pins the
    /// value the exhaustive search (`crate::sim::exhaust_ecn_response`) returns as optimal; it does NOT read
    /// the ECN fraction `α` at all.
    #[test]
    fn exhausted_ecn_optimum_is_the_delay_law() {
        for &srtt in &[1.0, 1.25, 2.0, 3.5] {
            // signals = [cwnd_seg, flight_seg, acked_seg, α, srtt_ratio, 0.5, 1, 2]
            let inputs = [12.0, 12.0, 0.0, 0.7, srtt, 0.5, 1.0, 2.0];
            let cut = synth_eval(&ControlProgram::EXHAUSTED_ECN_OPTIMUM.ecn, &inputs);
            assert!((cut - (srtt - 1.0)).abs() < 1e-12, "ecn cut at srtt_ratio={srtt} is {cut}, not srtt−1");
        }
        // It is invariant to α (a genuine delay response, not an ECN-fraction one).
        let a = synth_eval(&ControlProgram::EXHAUSTED_ECN_OPTIMUM.ecn, &[12.0, 12.0, 0.0, 0.1, 2.0, 0.5, 1.0, 2.0]);
        let b = synth_eval(&ControlProgram::EXHAUSTED_ECN_OPTIMUM.ecn, &[12.0, 12.0, 0.0, 0.9, 2.0, 0.5, 1.0, 2.0]);
        assert_eq!(a, b, "the delay law ignores α");
    }
}
