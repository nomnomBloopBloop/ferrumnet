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
}

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

/// Which controller a connection runs. The TCB defaults to [`CcKind::Reno`]; a backend can select
/// another (e.g. from `FERRUM_CC`) before connections form. Drives [`Cc::new`].
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum CcKind {
    #[default]
    Reno,
    Cubic,
}

/// The congestion controller the TCB holds. An **enum, not `Box<dyn CongestionControl>`**: dispatch
/// is a `match` with no vtable and no heap allocation, so the send path stays zero-alloc and the
/// whole engine stays sans-IO.
pub enum Cc {
    Reno(Reno),
    Cubic(Cubic),
}

impl Cc {
    /// Build the controller `kind`, sized for `mss` (each starts at its RFC 6928 initial window).
    pub fn new(kind: CcKind, mss: u16) -> Cc {
        match kind {
            CcKind::Reno => Cc::Reno(Reno::new(mss)),
            CcKind::Cubic => Cc::Cubic(Cubic::new(mss)),
        }
    }
}

impl CongestionControl for Cc {
    #[inline]
    fn cwnd(&self) -> u32 {
        match self {
            Cc::Reno(c) => c.cwnd(),
            Cc::Cubic(c) => c.cwnd(),
        }
    }

    #[inline]
    fn ssthresh(&self) -> u32 {
        match self {
            Cc::Reno(c) => c.ssthresh(),
            Cc::Cubic(c) => c.ssthresh(),
        }
    }

    fn on_ack(&mut self, now: Instant, acked: u32) {
        match self {
            Cc::Reno(c) => c.on_ack(now, acked),
            Cc::Cubic(c) => c.on_ack(now, acked),
        }
    }

    fn on_dup_ack(&mut self, now: Instant, flight_size: u32) -> bool {
        match self {
            Cc::Reno(c) => c.on_dup_ack(now, flight_size),
            Cc::Cubic(c) => c.on_dup_ack(now, flight_size),
        }
    }

    fn enter_recovery(&mut self, now: Instant, flight_size: u32) {
        match self {
            Cc::Reno(c) => c.enter_recovery(now, flight_size),
            Cc::Cubic(c) => c.enter_recovery(now, flight_size),
        }
    }

    fn on_rto(&mut self, now: Instant, flight_size: u32) {
        match self {
            Cc::Reno(c) => c.on_rto(now, flight_size),
            Cc::Cubic(c) => c.on_rto(now, flight_size),
        }
    }

    fn set_mss(&mut self, mss: u16) {
        match self {
            Cc::Reno(c) => c.set_mss(mss),
            Cc::Cubic(c) => c.set_mss(mss),
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
}
