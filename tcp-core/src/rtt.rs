//! RFC 6298 retransmission-timeout estimator: Jacobson's SRTT/RTTVAR with Karn's amendment.
//!
//! All values are in **microseconds**, so the estimator tracks sub-millisecond RTTs faithfully
//! instead of flooring everything to 1 ms. The verified subtleties (`docs/DESIGN.md` `retx/*`):
//!
//! - RTTVAR is updated using the **old** SRTT and **before** SRTT (order matters).
//! - Integer `div_ceil` (not truncating division), which would bias both estimators low.
//! - Initial RTO is 1 s; the RTO is clamped to **[200 ms, 60 s]**. The 200 ms floor is Linux's
//!   `TCP_RTO_MIN` rather than the RFC's 1 s SHOULD — on a sub-millisecond path a 1 s minimum
//!   makes every timeout-based recovery pathologically slow, and 200 ms still guards against
//!   spurious retransmits.
//! - On timeout the RTO **doubles** (Karn backoff), capped; after several timeouts the
//!   measurement is discarded so a genuinely changed path re-bootstraps.
//! - A clean ACK of never-retransmitted data **clears the backoff** back to the base RTO.

const INITIAL_RTO: u32 = 1_000_000; // 1 s, before any measurement (RFC 6298)
const MIN_RTO: u32 = 200_000; // 200 ms (Linux TCP_RTO_MIN)
const MAX_RTO: u32 = 60_000_000; // 60 s
const CLOCK_GRANULARITY: u32 = 1_000; // 1 ms — the RFC's `G` floor on the variance margin
const K: u32 = 4; // RTO = SRTT + max(G, K * RTTVAR)
/// After this many consecutive timeouts, drop the measurement so the next sample re-bootstraps.
const REBOOTSTRAP_AFTER: u32 = 3;

pub struct RttEstimator {
    srtt: u32,
    rttvar: u32,
    /// The RTO computed from SRTT/RTTVAR, before any backoff doubling.
    base_rto: u32,
    /// The currently effective RTO, including backoff.
    rto: u32,
    have_measurement: bool,
    consecutive_timeouts: u32,
}

impl Default for RttEstimator {
    fn default() -> Self {
        RttEstimator {
            srtt: 0,
            rttvar: 0,
            base_rto: INITIAL_RTO,
            rto: INITIAL_RTO,
            have_measurement: false,
            consecutive_timeouts: 0,
        }
    }
}

impl RttEstimator {
    pub fn new() -> Self {
        Self::default()
    }

    /// The current retransmission timeout in **microseconds** (includes backoff).
    #[inline]
    pub fn rto_micros(&self) -> u32 {
        self.rto
    }

    /// The smoothed round-trip time in **microseconds**, or `None` until the first measurement.
    /// Used by a delay/RTT-aware controller (TCP Prague's RTT-independent additive increase).
    #[inline]
    pub fn srtt_micros(&self) -> Option<u32> {
        if self.have_measurement {
            Some(self.srtt)
        } else {
            None
        }
    }

    /// Incorporate a fresh RTT measurement `r` (µs) from a non-retransmitted segment.
    pub fn on_sample(&mut self, r: u32) {
        // A sample longer than the max RTO is meaningless; clamping it also keeps the
        // SRTT/RTTVAR arithmetic below from overflowing on a pathological measurement.
        let r = r.min(MAX_RTO);
        if !self.have_measurement {
            self.srtt = r;
            self.rttvar = r / 2;
            self.have_measurement = true;
        } else {
            let delta = self.srtt.abs_diff(r);
            self.rttvar = (3 * self.rttvar + delta).div_ceil(4); // uses the OLD srtt, first
            self.srtt = (7 * self.srtt + r).div_ceil(8);
        }
        let margin = (K * self.rttvar).max(CLOCK_GRANULARITY);
        self.base_rto = self.srtt.saturating_add(margin).clamp(MIN_RTO, MAX_RTO);
        self.rto = self.base_rto;
        self.consecutive_timeouts = 0;
    }

    /// A clean ACK acknowledged never-retransmitted data: clear backoff back to the base RTO.
    pub fn on_clean_ack(&mut self) {
        self.rto = self.base_rto;
        self.consecutive_timeouts = 0;
    }

    /// The retransmission timer fired: back off (double, capped), and after several in a row,
    /// discard the measurement so the next sample re-bootstraps.
    pub fn on_timeout(&mut self) {
        self.rto = (self.rto * 2).min(MAX_RTO);
        self.consecutive_timeouts += 1;
        if self.consecutive_timeouts >= REBOOTSTRAP_AFTER {
            self.have_measurement = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_sample_sets_srtt_and_rttvar() {
        let mut e = RttEstimator::new();
        assert_eq!(e.rto_micros(), 1_000_000); // initial 1 s before any sample
        e.on_sample(1_000_000); // 1 s RTT
        // srtt=1e6, rttvar=5e5, rto = 1e6 + 4*5e5 = 3e6
        assert_eq!(e.rto_micros(), 3_000_000);
    }

    #[test]
    fn subsequent_sample_uses_old_srtt_first() {
        let mut e = RttEstimator::new();
        e.on_sample(1_000_000);
        e.on_sample(1_000_000);
        // rttvar = ceil((3*5e5 + 0)/4) = 375000; srtt = 1e6; rto = 1e6 + 4*375000 = 2.5e6
        assert_eq!(e.rto_micros(), 2_500_000);
    }

    #[test]
    fn timeout_backs_off_and_clean_ack_restores() {
        let mut e = RttEstimator::new();
        e.on_sample(1_000_000); // base 3e6
        e.on_timeout();
        assert_eq!(e.rto_micros(), 6_000_000);
        e.on_timeout();
        assert_eq!(e.rto_micros(), 12_000_000);
        e.on_clean_ack();
        assert_eq!(e.rto_micros(), 3_000_000);
    }

    #[test]
    fn backoff_is_capped_at_max() {
        let mut e = RttEstimator::new();
        e.on_sample(20_000_000); // base clamps to 60 s (20e6 + 40e6)
        assert_eq!(e.rto_micros(), 60_000_000);
        e.on_timeout();
        assert_eq!(e.rto_micros(), 60_000_000);
    }

    #[test]
    fn rebootstraps_after_three_timeouts() {
        let mut e = RttEstimator::new();
        e.on_sample(2_000_000); // base = 2e6 + 4e6 = 6e6
        e.on_timeout();
        e.on_timeout();
        e.on_timeout(); // >= 3 -> drop the measurement
        e.on_sample(1_000_000);
        assert_eq!(e.rto_micros(), 3_000_000); // treated as a fresh first sample
    }

    #[test]
    fn rto_floored_at_200ms() {
        let mut e = RttEstimator::new();
        e.on_sample(10_000); // 10 ms RTT: computed RTO ~30 ms clamps up to the 200 ms floor
        assert_eq!(e.rto_micros(), 200_000);
    }
}
