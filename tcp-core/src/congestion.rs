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

/// The congestion controller the TCB holds. An **enum, not `Box<dyn CongestionControl>`**: dispatch
/// is a `match` with no vtable and no heap allocation, so the send path stays zero-alloc and the
/// whole engine stays sans-IO. Additional controllers (CUBIC, BBR) are added as variants here.
pub enum Cc {
    Reno(Reno),
}

impl Cc {
    /// A Reno controller sized for `mss` (its RFC 6928 initial window).
    pub fn reno(mss: u16) -> Cc {
        Cc::Reno(Reno::new(mss))
    }
}

impl CongestionControl for Cc {
    #[inline]
    fn cwnd(&self) -> u32 {
        match self {
            Cc::Reno(c) => c.cwnd(),
        }
    }

    #[inline]
    fn ssthresh(&self) -> u32 {
        match self {
            Cc::Reno(c) => c.ssthresh(),
        }
    }

    fn on_ack(&mut self, now: Instant, acked: u32) {
        match self {
            Cc::Reno(c) => c.on_ack(now, acked),
        }
    }

    fn on_dup_ack(&mut self, now: Instant, flight_size: u32) -> bool {
        match self {
            Cc::Reno(c) => c.on_dup_ack(now, flight_size),
        }
    }

    fn enter_recovery(&mut self, now: Instant, flight_size: u32) {
        match self {
            Cc::Reno(c) => c.enter_recovery(now, flight_size),
        }
    }

    fn on_rto(&mut self, now: Instant, flight_size: u32) {
        match self {
            Cc::Reno(c) => c.on_rto(now, flight_size),
        }
    }

    fn set_mss(&mut self, mss: u16) {
        match self {
            Cc::Reno(c) => c.set_mss(mss),
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
        let mut cc = Cc::reno(1460);
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
}
