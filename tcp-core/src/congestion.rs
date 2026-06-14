//! TCP Tahoe congestion control (RFC 5681 + RFC 6928 initial window).
//!
//! Everything is in **bytes**. The verified subtleties (see `docs/DESIGN.md` `congestion/*`):
//!
//! - Congestion avoidance counts **bytes acknowledged** with a `while` loop, not `+= MSS` per
//!   ACK — the latter under-grows under delayed/stretch ACKs and multi-segment recovery ACKs.
//! - On loss, `ssthresh = max(FlightSize/2, 2·MSS)` from the *passed* FlightSize, never `cwnd`
//!   (which may be far larger than what is truly in flight if the connection was rwnd-limited).
//! - Tahoe collapses to `cwnd = 1·MSS` on *both* a triple-duplicate-ACK and an RTO, and has
//!   **no** fast recovery (no window inflation, no deflate-to-ssthresh).
//! - The send gate is `min(cwnd, rwnd) − FlightSize`; the FlightSize subtraction uses wrapping
//!   sequence arithmetic (tested in `crate::seq`). The zero-window probe bypasses `cwnd`.

/// RFC 6928 initial window: `min(10·MSS, max(2·MSS, 14600))`.
pub fn initial_window(mss: u32) -> u32 {
    (10 * mss).min((2 * mss).max(14600))
}

pub struct Tahoe {
    cwnd: u32,
    ssthresh: u32,
    mss: u32,
    /// Bytes-acked accumulator for the congestion-avoidance `+1 MSS / RTT` rule.
    ca_acc: u32,
    dup_acks: u8,
}

impl Tahoe {
    pub fn new(mss: u16) -> Self {
        let mss = mss as u32;
        Tahoe {
            cwnd: initial_window(mss),
            ssthresh: u32::MAX, // effectively infinite: slow start until the first loss
            mss,
            ca_acc: 0,
            dup_acks: 0,
        }
    }

    #[inline]
    pub fn cwnd(&self) -> u32 {
        self.cwnd
    }

    #[inline]
    pub fn ssthresh(&self) -> u32 {
        self.ssthresh
    }

    #[inline]
    fn in_slow_start(&self) -> bool {
        self.cwnd < self.ssthresh
    }

    /// New data (`acked` bytes) was acknowledged: reset the dup-ACK counter and grow `cwnd`.
    pub fn on_ack(&mut self, acked: u32) {
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
    /// third, when the caller must fast-retransmit and we enter loss recovery.
    pub fn on_dup_ack(&mut self, flight_size: u32) -> bool {
        self.dup_acks = self.dup_acks.saturating_add(1);
        if self.dup_acks == 3 {
            self.enter_loss(flight_size);
            true
        } else {
            false
        }
    }

    /// The retransmission timer fired.
    pub fn on_rto(&mut self, flight_size: u32) {
        self.enter_loss(flight_size);
    }

    fn enter_loss(&mut self, flight_size: u32) {
        self.ssthresh = (flight_size / 2).max(2 * self.mss);
        self.cwnd = self.mss; // Tahoe: back to one segment, no fast recovery
        self.ca_acc = 0;
    }

    /// Update the maximum segment size (e.g. after path-MTU discovery); never let `cwnd` drop
    /// below one new segment, and discard the now-stale CA accumulator.
    pub fn set_mss(&mut self, mss: u16) {
        self.mss = mss as u32;
        self.cwnd = self.cwnd.max(self.mss);
        self.ca_acc = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_window_matches_rfc6928() {
        assert_eq!(initial_window(1460), 14600);
        assert_eq!(initial_window(536), 5360);
        assert_eq!(initial_window(64), 640);
        assert_eq!(initial_window(9000), 18000); // max(18000,14600) then min(90000, .)
    }

    #[test]
    fn slow_start_grows_by_acked_capped_at_mss() {
        let mut t = Tahoe::new(1460); // cwnd = 14600, ssthresh = MAX
        t.on_ack(1460);
        assert_eq!(t.cwnd(), 16060);
        t.on_ack(5000); // capped at one MSS of growth
        assert_eq!(t.cwnd(), 17520);
    }

    #[test]
    fn congestion_avoidance_counts_bytes_with_while_loop() {
        let mut t = Tahoe::new(1000);
        // Force CA: a loss drops ssthresh, then slow-start back up to it.
        t.on_rto(4000); // ssthresh = max(2000, 2000) = 2000, cwnd = 1000
        assert_eq!(t.cwnd(), 1000);
        assert_eq!(t.ssthresh(), 2000);
        t.on_ack(1000); // slow start: cwnd 1000 -> 2000 (now == ssthresh -> CA)
        assert_eq!(t.cwnd(), 2000);
        t.on_ack(1000); // CA: ca_acc=1000 < cwnd -> no growth yet
        assert_eq!(t.cwnd(), 2000);
        t.on_ack(1000); // CA: ca_acc=2000 >= cwnd -> +1 MSS
        assert_eq!(t.cwnd(), 3000);
        // A single large cumulative ACK credits multiple MSS via the while loop.
        t.on_ack(7000); // ca_acc 0+7000; 7000>=3000 ->4000(acc4000); 4000>=4000 ->5000(acc0)
        assert_eq!(t.cwnd(), 5000);
    }

    #[test]
    fn loss_uses_flight_size_not_cwnd() {
        let mut t = Tahoe::new(1000);
        for _ in 0..20 {
            t.on_ack(1000); // grow cwnd well past any plausible flight size
        }
        assert!(t.cwnd() > 14600);
        let third = t.on_dup_ack(4000) || t.on_dup_ack(4000) || t.on_dup_ack(4000);
        assert!(third); // the 3rd dup ACK triggers recovery
        assert_eq!(t.ssthresh(), 2000); // 4000/2, from FlightSize — not cwnd/2
        assert_eq!(t.cwnd(), 1000); // Tahoe: collapse to 1 MSS
    }

    #[test]
    fn dup_ack_fires_only_on_third() {
        let mut t = Tahoe::new(1460);
        assert!(!t.on_dup_ack(5000));
        assert!(!t.on_dup_ack(5000));
        assert!(t.on_dup_ack(5000));
        assert!(!t.on_dup_ack(5000)); // 4th and beyond do not re-trigger
        assert!(!t.on_dup_ack(5000));
    }

    #[test]
    fn rto_collapses_to_one_mss() {
        let mut t = Tahoe::new(1460);
        for _ in 0..10 {
            t.on_ack(1460);
        }
        t.on_rto(10_000);
        assert_eq!(t.cwnd(), 1460);
        assert_eq!(t.ssthresh(), 5000);
    }
}
