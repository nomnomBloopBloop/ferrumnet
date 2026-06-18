//! Sender-side SACK scoreboard and RFC 6675 conservative loss-recovery predicates.
//!
//! The scoreboard records, over the unacknowledged send range `(SND.UNA, SND.NXT]`, two interval
//! sets: the byte ranges the peer has selectively acknowledged (`sacked`), and the ranges we
//! have retransmitted in the current recovery episode (`rexmit`, RFC 6675's "Rexmit" / HighRxt).
//! From those it derives the RFC 6675 predicates — `IsLost`, `SetPipe` (the pipe estimate), and
//! `NextSeg` (which hole to repair next) — plus the recovery-episode bookkeeping (`RecoveryPoint`
//! and the rule-3/rescue retransmission guard).
//!
//! Everything is in **bytes** in **sequence space**; every comparison uses [`SeqNumber`] serial
//! arithmetic, so the scoreboard is correct across the 2³² wrap. The structure stays small (the
//! ≤64 KiB receive window bounds the number of runs), so the linear scans are cheap.

use crate::seq::SeqNumber;

/// RFC 5681 / RFC 6675 duplicate-ACK threshold.
pub const DUP_THRESH: u32 = 3;

/// Anti-DoS cap on stored runs. Sized above the worst-case hole count for our 256 KiB window at
/// a typical MSS (≈180 segments ⇒ ≤90 alternating holes); a conforming peer never reaches it. On
/// overflow we drop SACK info so the affected bytes revert to "unsacked", biasing toward a
/// redundant retransmission and never toward skipping a genuine hole.
const MAX_RUNS: usize = 128;

type Run = (SeqNumber, SeqNumber); // half-open [left, right) in sequence space

#[derive(Clone)]
pub struct Scoreboard {
    /// SACKed runs, sorted ascending by left edge (serial), coalesced, within `(SND.UNA, SND.NXT]`.
    sacked: Vec<Run>,
    /// Ranges retransmitted in the current recovery episode (cleared on exit and on RTO).
    rexmit: Vec<Run>,
    /// RFC 6675 RecoveryPoint (= SND.NXT captured at entry); `Some` iff in SACK-based recovery.
    recovery_point: Option<SeqNumber>,
    /// RFC 6675 rule-3 rescue retransmission: at most once per recovery episode.
    rescue_done: bool,
}

impl Default for Scoreboard {
    fn default() -> Self {
        Scoreboard::new()
    }
}

impl Scoreboard {
    pub fn new() -> Self {
        Scoreboard {
            sacked: Vec::new(),
            rexmit: Vec::new(),
            recovery_point: None,
            rescue_done: false,
        }
    }

    // ── recovery-episode bookkeeping ─────────────────────────────────────────────────────────

    #[inline]
    pub fn in_recovery(&self) -> bool {
        self.recovery_point.is_some()
    }

    /// Begin a SACK recovery episode with `RecoveryPoint = recovery_point` (= SND.NXT at entry).
    pub fn begin_recovery(&mut self, recovery_point: SeqNumber) {
        self.recovery_point = Some(recovery_point);
        self.rescue_done = false;
    }

    /// Recovery ends once the cumulative ACK reaches `RecoveryPoint`.
    pub fn recovery_reached(&self, snd_una: SeqNumber) -> bool {
        matches!(self.recovery_point, Some(rp) if snd_una.ge(rp))
    }

    /// Leave recovery cleanly (cumulative ACK reached RecoveryPoint): clear the rexmit set.
    pub fn exit_recovery(&mut self) {
        self.recovery_point = None;
        self.rexmit.clear();
        self.rescue_done = false;
    }

    /// An RTO fired: abandon SACK recovery and let the legacy go-back-N path take over. The
    /// `sacked` set is **kept** (RFC 6675 §5.1 — the peer still holds that data, so a
    /// non-reneging peer's cumulative ACK will jump past it once the hole is refilled).
    pub fn on_rto(&mut self) {
        self.rexmit.clear();
        self.recovery_point = None;
        self.rescue_done = false;
    }

    // ── updates from the wire / from the sender ──────────────────────────────────────────────

    /// Apply parsed SACK blocks. Each block is validated to lie within `(snd_una, snd_nxt]`
    /// **before** any clipping: empty/inverted blocks, blocks at or below the cumulative ACK
    /// (stale or D-SACK), and blocks acknowledging unsent data are all rejected. A block
    /// straddling `snd_una` is clipped to it.
    pub fn update(&mut self, snd_una: SeqNumber, snd_nxt: SeqNumber, blocks: &[Run]) {
        for &(l, r) in blocks {
            if !l.lt(r) {
                continue; // empty or inverted
            }
            if r.le(snd_una) {
                continue; // entirely at/below the cumulative ACK (stale / D-SACK): ignore
            }
            if l.gt(snd_nxt) || r.gt(snd_nxt) {
                continue; // acknowledges data we never sent: reject
            }
            let l = if l.lt(snd_una) { snd_una } else { l };
            if l.lt(r) {
                insert_run(&mut self.sacked, l, r);
            }
        }
        // Anti-DoS: drop the highest runs (revert to unsacked) rather than merge across a gap.
        while self.sacked.len() > MAX_RUNS {
            self.sacked.pop();
        }
    }

    /// Drop everything at or below the new `snd_una` and clip straddling runs to it, pinning the
    /// scoreboard to `(snd_una, snd_nxt]`.
    pub fn trim(&mut self, snd_una: SeqNumber) {
        trim_runs(&mut self.sacked, snd_una);
        trim_runs(&mut self.rexmit, snd_una);
    }

    /// Record that `[l, r)` has been retransmitted this episode.
    pub fn mark_rexmit(&mut self, l: SeqNumber, r: SeqNumber) {
        if l.lt(r) {
            insert_run(&mut self.rexmit, l, r);
        }
    }

    pub fn set_rescue_done(&mut self) {
        self.rescue_done = true;
    }

    /// The scoreboard's internal well-formedness invariant: both run lists (`sacked`, `rexmit`) are
    /// each non-empty-run, strictly ascending, and disjoint-with-a-gap (consecutive runs satisfy
    /// `r_i < l_{i+1}`, since [`insert_run`] coalesces overlapping *and* adjacent runs). The
    /// bounded model checker ([`crate::bmc`]) asserts this holds after every operation sequence; it
    /// is the structural contract the RFC 6675 predicates rely on. (`pub(crate)`: a verification hook,
    /// not public API.)
    pub(crate) fn invariants_hold(&self) -> bool {
        run_list_well_formed(&self.sacked) && run_list_well_formed(&self.rexmit)
    }

    // ── interval queries ─────────────────────────────────────────────────────────────────────

    pub fn is_sacked(&self, seq: SeqNumber) -> bool {
        self.sacked.iter().any(|&(l, r)| seq.ge(l) && seq.lt(r))
    }

    pub fn is_rexmit(&self, seq: SeqNumber) -> bool {
        self.rexmit.iter().any(|&(l, r)| seq.ge(l) && seq.lt(r))
    }

    /// The highest right edge among SACKed runs, if any (= the rightmost SACKed octet boundary).
    pub fn highest_sacked_edge(&self) -> Option<SeqNumber> {
        self.sacked.last().map(|&(_, r)| r)
    }

    /// The next sequence above `s` (but at/below `limit`) at which sacked- or rexmit-membership
    /// changes; `limit` if none. So sacked/rexmit status is uniform over `[s, next_boundary)`.
    fn next_boundary(&self, s: SeqNumber, limit: SeqNumber) -> SeqNumber {
        let mut b = limit;
        for &(l, r) in self.sacked.iter().chain(self.rexmit.iter()) {
            if l.gt(s) && l.lt(b) {
                b = l;
            }
            if r.gt(s) && r.lt(b) {
                b = r;
            }
        }
        b
    }

    /// Length of the contiguous **unsacked** span starting at `seq`, bounded by the next SACKed
    /// left edge above `seq` and by `limit` (so a retransmit never crosses into SACKed data).
    pub fn unsacked_run_len(&self, seq: SeqNumber, limit: SeqNumber) -> u32 {
        let mut end = limit;
        for &(l, _) in &self.sacked {
            if l.gt(seq) && l.lt(end) {
                end = l;
            }
        }
        if end.le(seq) {
            0
        } else {
            end.offset_from(seq)
        }
    }

    // ── RFC 6675 predicates ──────────────────────────────────────────────────────────────────

    /// RFC 6675 §4 `IsLost(seq)`: true if at least `DupThresh` discontiguous SACKed runs lie
    /// above `seq`, **or** more than `(DupThresh − 1) · SMSS` bytes have been SACKed above it.
    pub fn is_lost(&self, seq: SeqNumber, smss: u32) -> bool {
        let mut blocks_above = 0u32;
        let mut bytes_above = 0u32;
        for &(l, r) in &self.sacked {
            if l.gt(seq) {
                blocks_above += 1;
                bytes_above = bytes_above.saturating_add(r.offset_from(l));
            }
        }
        blocks_above >= DUP_THRESH || bytes_above > (DUP_THRESH - 1) * smss
    }

    /// RFC 6675 §4 `SetPipe()`: the estimated number of bytes outstanding in the path. Walk
    /// `[snd_una, snd_nxt)` in uniform-status spans; an unsacked span counts its length **once**
    /// if it is either still in flight (`!IsLost`) or has an outstanding retransmission
    /// (`is_rexmit`) — never twice (the corrected single-count rule).
    pub fn pipe(&self, snd_una: SeqNumber, snd_nxt: SeqNumber, smss: u32) -> u32 {
        let mut pipe = 0u32;
        let mut s = snd_una;
        while s.lt(snd_nxt) {
            let end = self.next_boundary(s, snd_nxt);
            if !self.is_sacked(s) && (self.is_rexmit(s) || !self.is_lost(s, smss)) {
                pipe = pipe.saturating_add(end.offset_from(s));
            }
            s = end;
        }
        pipe
    }

    /// RFC 6675 §4 `NextSeg()`: the start of the next segment to (re)transmit, and whether it is
    /// a rule-3 rescue. Rule (1): the lowest unsacked, not-yet-retransmitted, `IsLost` hole.
    /// Rule (2) (new data) is handled by the caller's normal send path, not here. Rule (3)
    /// rescue: if no `IsLost` hole remains but unsacked data sits below the highest SACK and we
    /// have not yet rescued this episode, return the lowest such hole once.
    pub fn next_seg(
        &self,
        snd_una: SeqNumber,
        snd_nxt: SeqNumber,
        smss: u32,
    ) -> Option<(SeqNumber, bool)> {
        let mut s = snd_una;
        while s.lt(snd_nxt) {
            let end = self.next_boundary(s, snd_nxt);
            if !self.is_sacked(s) && !self.is_rexmit(s) && self.is_lost(s, smss) {
                return Some((s, false));
            }
            s = end;
        }
        if !self.rescue_done {
            if let Some(high) = self.highest_sacked_edge() {
                let mut s = snd_una;
                while s.lt(snd_nxt) {
                    let end = self.next_boundary(s, snd_nxt);
                    if !self.is_sacked(s) && !self.is_rexmit(s) && s.lt(high) {
                        return Some((s, true));
                    }
                    s = end;
                }
            }
        }
        None
    }
}

/// Insert `[l, r)` into a sorted, disjoint run list, coalescing with overlapping or adjacent
/// runs. Used for both the sacked and rexmit sets.
fn insert_run(runs: &mut Vec<Run>, mut l: SeqNumber, mut r: SeqNumber) {
    let mut first = runs.len();
    let mut count = 0;
    for (i, &(rl, rr)) in runs.iter().enumerate() {
        if rl.le(r) && l.le(rr) {
            // overlap or adjacency
            if count == 0 {
                first = i;
            }
            count += 1;
            if rl.lt(l) {
                l = rl;
            }
            if rr.gt(r) {
                r = rr;
            }
        }
    }
    for _ in 0..count {
        runs.remove(first);
    }
    let pos = runs.iter().position(|&(rl, _)| l.lt(rl)).unwrap_or(runs.len());
    runs.insert(pos, (l, r));
}

/// A run list is well-formed iff every run is non-empty (`l < r`) and consecutive runs are strictly
/// ascending with a gap (`r_i < l_{i+1}`) — the sorted, disjoint, coalesced invariant. All comparisons
/// are [`SeqNumber`] serial; the list spans far less than 2³¹ (one receive window), so the order is
/// total and the pairwise check is sound across the wrap.
fn run_list_well_formed(runs: &[Run]) -> bool {
    for &(l, r) in runs {
        if !l.lt(r) {
            return false;
        }
    }
    runs.windows(2).all(|w| w[0].1.lt(w[1].0))
}

/// Drop runs entirely at/below `snd_una`; clip a straddling run's left edge up to it.
fn trim_runs(runs: &mut Vec<Run>, snd_una: SeqNumber) {
    runs.retain(|&(_, r)| r.gt(snd_una));
    for run in runs.iter_mut() {
        if run.0.lt(snd_una) {
            run.0 = snd_una;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: u32) -> SeqNumber {
        SeqNumber::new(v)
    }

    /// The well-formedness predicate the bounded model checker relies on has teeth: it accepts a
    /// sorted/disjoint/non-empty list and rejects every malformation (empty run, inverted run, out of
    /// order, overlapping, adjacent-without-gap). So a regression that made `invariants_hold` a
    /// tautology fails here, not silently.
    #[test]
    fn run_list_well_formed_has_teeth() {
        assert!(run_list_well_formed(&[])); // vacuously well-formed
        assert!(run_list_well_formed(&[(s(0), s(10))]));
        assert!(run_list_well_formed(&[(s(0), s(10)), (s(20), s(30))])); // sorted, disjoint, a gap
        assert!(!run_list_well_formed(&[(s(10), s(10))])); // empty run
        assert!(!run_list_well_formed(&[(s(20), s(10))])); // inverted
        assert!(!run_list_well_formed(&[(s(20), s(30)), (s(0), s(10))])); // out of order
        assert!(!run_list_well_formed(&[(s(0), s(20)), (s(10), s(30))])); // overlapping
        assert!(!run_list_well_formed(&[(s(0), s(10)), (s(10), s(20))])); // adjacent: must be coalesced
    }

    #[test]
    fn update_validates_window() {
        let mut sb = Scoreboard::new();
        let (una, nxt) = (s(1000), s(9000));
        sb.update(una, nxt, &[
            (s(500), s(900)),   // entirely below una: ignored (stale / D-SACK)
            (s(2000), s(1500)), // inverted: ignored
            (s(8000), s(9500)), // right edge past nxt: acks unsent: rejected
            (s(2000), s(3000)), // valid
            (s(800), s(2000)),  // straddles una: clipped to [1000,2000)
        ]);
        assert!(sb.is_sacked(s(1500)));
        assert!(sb.is_sacked(s(2500)));
        assert!(!sb.is_sacked(s(900)));
        assert!(!sb.is_sacked(s(8500))); // the unsent-data block was rejected
    }

    #[test]
    fn coalesces_and_trims() {
        let mut sb = Scoreboard::new();
        sb.update(s(0), s(10000), &[(s(100), s(200)), (s(200), s(300)), (s(150), s(250))]);
        // All three coalesce into one [100,300).
        assert!(sb.is_sacked(s(100)));
        assert!(sb.is_sacked(s(299)));
        assert!(!sb.is_sacked(s(300)));
        assert_eq!(sb.highest_sacked_edge(), Some(s(300)));
        // A cumulative ACK to 150 trims the left edge.
        sb.trim(s(150));
        assert!(!sb.is_sacked(s(149)));
        assert!(sb.is_sacked(s(150)));
    }

    /// Hand-computed RFC 6675 §4 walk. 8 segments of SMSS=1000 in flight over [1000, 9000);
    /// segments 2, 4, 6 SACKed. Verifies IsLost (both clauses) and the single-count pipe.
    #[test]
    fn is_lost_and_pipe_match_rfc6675_walk() {
        let smss = 1000;
        let (una, nxt) = (s(1000), s(9000));
        let mut sb = Scoreboard::new();
        sb.update(una, nxt, &[(s(2000), s(3000)), (s(4000), s(5000)), (s(6000), s(7000))]);

        // IsLost: 3 blocks above 1000 => lost (block-count clause).
        assert!(sb.is_lost(s(1000), smss));
        // Above 3000: 2 blocks, 2000 bytes SACKed; 2000 > (3-1)*1000=2000 is false => not lost.
        assert!(!sb.is_lost(s(3000), smss));
        // Above 5000: 1 block, 1000 bytes => not lost.
        assert!(!sb.is_lost(s(5000), smss));

        // pipe: inflight 8000 − sacked 3000 − lost 1000 (segment 1) = 4000.
        assert_eq!(sb.pipe(una, nxt, smss), 4000);

        // NextSeg rule (1): the lost hole at SND.UNA.
        assert_eq!(sb.next_seg(una, nxt, smss), Some((s(1000), false)));

        // After retransmitting it, that hole is no longer eligible; no other IsLost hole, so
        // the rule-3 rescue returns the lowest unsacked, un-rexmitted hole below the high SACK.
        sb.mark_rexmit(s(1000), s(2000));
        assert_eq!(sb.pipe(una, nxt, smss), 5000); // the rexmit hole now counts as in flight
        assert_eq!(sb.next_seg(una, nxt, smss), Some((s(3000), true))); // rescue, below 7000
    }

    #[test]
    fn rescue_only_once_per_episode() {
        let smss = 1000;
        let (una, nxt) = (s(0), s(4000));
        let mut sb = Scoreboard::new();
        // One SACK block, only 1000 bytes above => no IsLost hole anywhere.
        sb.update(una, nxt, &[(s(3000), s(4000))]);
        assert!(!sb.is_lost(s(0), smss));
        let (seq, rescue) = sb.next_seg(una, nxt, smss).unwrap();
        assert!(rescue);
        assert_eq!(seq, s(0));
        sb.set_rescue_done();
        assert_eq!(sb.next_seg(una, nxt, smss), None); // no second rescue
    }

    #[test]
    fn on_rto_keeps_sacked_clears_recovery() {
        let mut sb = Scoreboard::new();
        sb.update(s(0), s(5000), &[(s(2000), s(3000))]);
        sb.begin_recovery(s(5000));
        sb.mark_rexmit(s(0), s(1000));
        assert!(sb.in_recovery());
        sb.on_rto();
        assert!(!sb.in_recovery());
        assert!(!sb.is_rexmit(s(500))); // rexmit cleared
        assert!(sb.is_sacked(s(2500))); // sacked retained (RFC 6675 §5.1)
    }

    #[test]
    fn recovery_reached_at_recovery_point() {
        let mut sb = Scoreboard::new();
        sb.begin_recovery(s(5000));
        assert!(!sb.recovery_reached(s(4999)));
        assert!(sb.recovery_reached(s(5000)));
        assert!(sb.recovery_reached(s(6000)));
    }

    #[test]
    fn wraparound_scoreboard() {
        let smss = 1000;
        let una = s(0xFFFF_F000);
        let nxt = una + 8000;
        let mut sb = Scoreboard::new();
        // Three SACK blocks above una, spanning the 2^32 wrap.
        sb.update(una, nxt, &[
            (una + 1000, una + 2000),
            (una + 3000, una + 4000),
            (una + 5000, una + 6000),
        ]);
        assert!(sb.is_lost(una, smss)); // 3 blocks above
        assert_eq!(sb.next_seg(una, nxt, smss), Some((una, false)));
        // inflight 8000 − sacked 3000 − lost 1000 (the segment at una) = 4000.
        assert_eq!(sb.pipe(una, nxt, smss), 4000);
    }
}
