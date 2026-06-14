//! RFC 6298 retransmission-timeout estimator: Jacobson's SRTT/RTTVAR with Karn's amendment.
//!
//! All values are in milliseconds. The verified subtleties (see `docs/DESIGN.md` `retx/*`):
//!
//! - RTTVAR is updated using the **old** SRTT and **before** SRTT (order matters).
//! - Integer `div_ceil` (not truncating division), which would bias both estimators low.
//! - Initial RTO is 1 s; the RTO is clamped to `[1 s, 60 s]`.
//! - On timeout the RTO **doubles** (Karn backoff); after several consecutive timeouts the
//!   measurement is discarded so a genuinely changed path re-bootstraps.
//! - A clean ACK of never-retransmitted data **clears the backoff** back to the base RTO.
//! - Karn: an RTT sample is only ever taken from a segment that was not retransmitted (the
//!   caller enforces this; this type just consumes valid samples).

const INITIAL_RTO: u32 = 1000;
const MIN_RTO: u32 = 1000;
const MAX_RTO: u32 = 60_000;
const CLOCK_GRANULARITY: u32 = 1; // ms; the RFC's `G` floor on the variance margin
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

    /// The current retransmission timeout in milliseconds (includes backoff).
    #[inline]
    pub fn rto_millis(&self) -> u32 {
        self.rto
    }

    /// Incorporate a fresh RTT measurement `r` (ms) from a non-retransmitted segment.
    pub fn on_sample(&mut self, r: u32) {
        // A sample longer than the max RTO is meaningless; clamping it also keeps the
        // SRTT/RTTVAR arithmetic below from overflowing on a pathological measurement.
        let r = r.min(MAX_RTO);
        if !self.have_measurement {
            // RFC 6298 (2.2): first measurement.
            self.srtt = r;
            self.rttvar = r / 2;
            self.have_measurement = true;
        } else {
            // RFC 6298 (2.3): RTTVAR uses the OLD srtt and is updated FIRST.
            let delta = self.srtt.abs_diff(r);
            self.rttvar = (3 * self.rttvar + delta).div_ceil(4);
            self.srtt = (7 * self.srtt + r).div_ceil(8);
        }
        let margin = (K * self.rttvar).max(CLOCK_GRANULARITY);
        self.base_rto = (self.srtt + margin).clamp(MIN_RTO, MAX_RTO);
        // A successful measurement clears any backoff.
        self.rto = self.base_rto;
        self.consecutive_timeouts = 0;
    }

    /// A clean ACK acknowledged never-retransmitted data: clear backoff back to the base RTO
    /// even if no new sample was taken.
    pub fn on_clean_ack(&mut self) {
        self.rto = self.base_rto;
        self.consecutive_timeouts = 0;
    }

    /// The retransmission timer fired: back off (double, capped), and after several in a row,
    /// discard the measurement so the next sample re-bootstraps a path whose RTT really grew.
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
        assert_eq!(e.rto_millis(), 1000); // initial RTO before any sample
        e.on_sample(1000);
        // srtt=1000, rttvar=500, rto = 1000 + 4*500 = 3000
        assert_eq!(e.rto_millis(), 3000);
    }

    #[test]
    fn subsequent_sample_uses_old_srtt_first() {
        let mut e = RttEstimator::new();
        e.on_sample(1000); // srtt=1000, rttvar=500
        e.on_sample(1000);
        // rttvar = ceil((3*500 + 0)/4) = 375; srtt = ceil((7*1000 + 1000)/8) = 1000
        // rto = 1000 + 4*375 = 2500
        assert_eq!(e.rto_millis(), 2500);
    }

    #[test]
    fn timeout_backs_off_and_clean_ack_restores() {
        let mut e = RttEstimator::new();
        e.on_sample(1000); // base_rto = 3000
        e.on_timeout();
        assert_eq!(e.rto_millis(), 6000);
        e.on_timeout();
        assert_eq!(e.rto_millis(), 12000);
        e.on_clean_ack();
        assert_eq!(e.rto_millis(), 3000); // backoff cleared to the base RTO
    }

    #[test]
    fn backoff_is_capped_at_max() {
        let mut e = RttEstimator::new();
        e.on_sample(20_000); // base_rto clamps to 60_000 (20000 + 40000)
        assert_eq!(e.rto_millis(), 60_000);
        e.on_timeout();
        assert_eq!(e.rto_millis(), 60_000); // doubling stays capped
    }

    #[test]
    fn rebootstraps_after_three_timeouts() {
        let mut e = RttEstimator::new();
        e.on_sample(2000); // base_rto = 2000 + 4000 = 6000
        e.on_timeout();
        e.on_timeout();
        e.on_timeout(); // >= 3 -> drop the measurement
                        // Next sample is treated as the first again: srtt=R, rttvar=R/2.
        e.on_sample(1000);
        assert_eq!(e.rto_millis(), 3000); // 1000 + 4*500, not blended with the stale 2000
    }

    #[test]
    fn rto_floored_at_one_second() {
        let mut e = RttEstimator::new();
        e.on_sample(10); // tiny LAN RTT: 10 + max(1, 4*5)=30 -> clamps up to MIN_RTO 1000
        assert_eq!(e.rto_millis(), 1000);
    }
}
