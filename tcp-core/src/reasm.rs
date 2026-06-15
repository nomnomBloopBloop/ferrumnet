//! Out-of-order receive reassembly (used only when SACK is negotiated).
//!
//! When a segment arrives above `RCV.NXT` (a gap below it), its bytes are buffered here as a
//! small, sorted list of coalesced *runs* — contiguous `[start, start+len)` spans — instead of
//! being dropped. When a later segment fills the gap, the now-contiguous runs are drained into
//! the in-order receive ring without forcing the peer to retransmit data it already delivered.
//! The set of buffered runs is also what the SACK option reports to the sender (RFC 2018).
//!
//! Each run owns its bytes in a `Vec<u8>`: [`crate::buffers::RingBuffer`] has no random-access
//! insert, so owned runs are the clean, provably-bounded representation. Total buffered bytes
//! are bounded by the receive window (the caller clips every insert to a byte budget; see
//! `Tcb::reasm_right_edge`), so the run count stays small (single digits) in practice.
//!
//! Every sequence comparison goes through [`SeqNumber`]'s serial arithmetic; the recency
//! `stamp` is an ordinary `u64` counter where plain `Ord` is legitimate.

use crate::seq::SeqNumber;

/// One contiguous run of out-of-order bytes occupying `[start, start + data.len())`.
struct Segment {
    start: SeqNumber,
    data: Vec<u8>,
    /// Monotonic recency stamp; the run with the highest stamp was most recently touched.
    /// RFC 2018 §4: the first emitted SACK block should report the most recently received data.
    stamp: u64,
}

/// The out-of-order reassembly buffer for one connection.
pub struct Reasm {
    /// Runs sorted ascending by `start` (serial order), pairwise non-overlapping and
    /// non-adjacent (touching runs are always coalesced on insert), every run strictly above
    /// `RCV.NXT`.
    runs: Vec<Segment>,
    /// `Σ runs[i].data.len()`, maintained incrementally so [`Reasm::buffered`] is O(1).
    bytes: usize,
    /// Source of monotonic recency stamps; bumped on every insert/coalesce.
    next_stamp: u64,
}

impl Default for Reasm {
    fn default() -> Self {
        Reasm::new()
    }
}

impl Reasm {
    pub fn new() -> Self {
        Reasm {
            runs: Vec::new(),
            bytes: 0,
            next_stamp: 0,
        }
    }

    /// Total out-of-order bytes currently buffered (counts against the advertised window).
    #[inline]
    pub fn buffered(&self) -> usize {
        self.bytes
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.runs.is_empty()
    }

    /// Buffer `payload` (which begins at sequence `seg_seq`, expected to be above `rcv_nxt`).
    ///
    /// The bytes are clipped to `(rcv_nxt, right_edge)` — never buffer data we have already
    /// delivered, nor past the byte budget the caller can hold (so total buffered stays within
    /// the receive window) — then coalesced with any overlapping or adjacent runs. On overlap,
    /// the **already-buffered** bytes win (first-writer-wins), so a later overlapping segment
    /// cannot rewrite data we are committed to.
    pub fn insert(
        &mut self,
        rcv_nxt: SeqNumber,
        right_edge: SeqNumber,
        seg_seq: SeqNumber,
        payload: &[u8],
    ) {
        // Clip to the bufferable window [lo, hi) = (max(seg_seq, rcv_nxt), min(seg_end, edge)).
        let seg_end = seg_seq + payload.len() as u32;
        let lo = seg_seq.max(rcv_nxt);
        let hi = seg_end.min(right_edge);
        if lo.ge(hi) {
            return; // nothing left after clipping (duplicate, or wholly past the budget)
        }
        let off = lo.offset_from(seg_seq) as usize;
        let len = hi.offset_from(lo) as usize;
        let new_bytes = &payload[off..off + len];

        // Find every existing run overlapping or adjacent to [lo, hi); compute the merged span.
        // Sorted, disjoint runs that touch a contiguous interval are themselves contiguous in
        // `runs`, so the collected indices form one removable block.
        let new_end = lo + len as u32;
        let mut merged_start = lo;
        let mut merged_end = new_end;
        let mut first_idx = self.runs.len();
        let mut count = 0;
        for (idx, run) in self.runs.iter().enumerate() {
            let run_end = run.start + run.data.len() as u32;
            if run.start.le(new_end) && lo.le(run_end) {
                if count == 0 {
                    first_idx = idx;
                }
                count += 1;
                if run.start.lt(merged_start) {
                    merged_start = run.start;
                }
                if run_end.gt(merged_end) {
                    merged_end = run_end;
                }
            }
        }

        // Build the merged run: lay down the new bytes, then overwrite with existing bytes so
        // already-buffered data wins on any overlap. Every byte of [merged_start, merged_end)
        // is covered (the new run bridges any gap between the existing runs it touches), so no
        // zero-fill slack survives.
        let span = merged_end.offset_from(merged_start) as usize;
        let mut data = vec![0u8; span];
        let n_off = lo.offset_from(merged_start) as usize;
        data[n_off..n_off + len].copy_from_slice(new_bytes);
        for run in self.runs.iter().skip(first_idx).take(count) {
            let r_off = run.start.offset_from(merged_start) as usize;
            data[r_off..r_off + run.data.len()].copy_from_slice(&run.data);
        }

        // Replace the merged-away runs with the single combined run.
        for _ in 0..count {
            let removed = self.runs.remove(first_idx);
            self.bytes -= removed.data.len();
        }
        self.next_stamp += 1;
        let seg = Segment {
            start: merged_start,
            data,
            stamp: self.next_stamp,
        };
        self.bytes += seg.data.len();
        let pos = self
            .runs
            .iter()
            .position(|r| merged_start.lt(r.start))
            .unwrap_or(self.runs.len());
        self.runs.insert(pos, seg);
    }

    /// If the lowest buffered run begins exactly at `rcv_nxt`, remove and return its bytes (the
    /// caller writes them to the in-order ring and advances `RCV.NXT`). Returns an empty `Vec`
    /// when a gap still separates `rcv_nxt` from the buffered data.
    pub fn pop_contiguous(&mut self, rcv_nxt: SeqNumber) -> Vec<u8> {
        if let Some(first) = self.runs.first() {
            if first.start == rcv_nxt {
                let seg = self.runs.remove(0);
                self.bytes -= seg.data.len();
                return seg.data;
            }
        }
        Vec::new()
    }

    /// Drop buffered data the advancing `rcv_nxt` has overtaken: runs entirely at or below it are
    /// removed (they duplicate data just delivered in order), and a run straddling it has its
    /// already-delivered `[start, rcv_nxt)` prefix dropped and its left edge clipped up to
    /// `rcv_nxt`. Without this, an in-order segment that overlaps a buffered run would leave the
    /// run stranded below `rcv_nxt` — leaking the receive budget and emitting a SACK block below
    /// the cumulative ACK.
    pub fn discard_below(&mut self, rcv_nxt: SeqNumber) {
        while let Some(first) = self.runs.first_mut() {
            let run_end = first.start + first.data.len() as u32;
            if run_end.le(rcv_nxt) {
                let seg = self.runs.remove(0);
                self.bytes -= seg.data.len();
            } else if first.start.lt(rcv_nxt) {
                let drop = rcv_nxt.offset_from(first.start) as usize;
                first.data.drain(..drop);
                first.start = rcv_nxt;
                self.bytes -= drop;
                break; // only the lowest run can straddle rcv_nxt
            } else {
                break; // the lowest run is already at or above rcv_nxt
            }
        }
    }

    /// Re-buffer the unwritten tail of a popped run at the front (used only by the defensive
    /// drain guard — unreachable under the window invariant, but it must not lose bytes).
    /// `start` is below every remaining run's start, so it goes at index 0.
    pub fn reinsert_front(&mut self, start: SeqNumber, data: Vec<u8>) {
        if data.is_empty() {
            return;
        }
        self.next_stamp += 1;
        self.bytes += data.len();
        self.runs.insert(
            0,
            Segment {
                start,
                data,
                stamp: self.next_stamp,
            },
        );
    }

    /// Fill `out` with the buffered runs as `(left, right)` edges, most recently received first
    /// (RFC 2018 §4). Returns the number written (≤ `out.len()`).
    pub fn report(&self, out: &mut [(SeqNumber, SeqNumber)]) -> usize {
        let mut order: Vec<usize> = (0..self.runs.len()).collect();
        order.sort_by(|&a, &b| self.runs[b].stamp.cmp(&self.runs[a].stamp));
        let mut n = 0;
        for &i in &order {
            if n >= out.len() {
                break;
            }
            let r = &self.runs[i];
            out[n] = (r.start, r.start + r.data.len() as u32);
            n += 1;
        }
        n
    }

    /// Debug-only invariant check used by tests: runs sorted, disjoint, non-adjacent, all above
    /// `rcv_nxt`, and `bytes` consistent.
    #[cfg(test)]
    fn check(&self, rcv_nxt: SeqNumber) {
        let mut total = 0;
        for (i, run) in self.runs.iter().enumerate() {
            assert!(run.start.gt(rcv_nxt), "run not strictly above rcv_nxt");
            assert!(!run.data.is_empty(), "empty run");
            total += run.data.len();
            if i + 1 < self.runs.len() {
                let run_end = run.start + run.data.len() as u32;
                let next = self.runs[i + 1].start;
                assert!(run_end.lt(next), "runs adjacent or overlapping (should coalesce)");
            }
        }
        assert_eq!(total, self.bytes, "byte count out of sync");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seq(v: u32) -> SeqNumber {
        SeqNumber::new(v)
    }

    // A right edge effectively unbounded for tests not exercising the budget clip.
    fn wide(rcv_nxt: SeqNumber) -> SeqNumber {
        rcv_nxt + 60_000
    }

    fn report_vec(r: &Reasm) -> Vec<(u32, u32)> {
        let mut out = [(seq(0), seq(0)); crate::wire::MAX_SACK_BLOCKS];
        let n = r.report(&mut out);
        out[..n].iter().map(|&(l, h)| (l.raw(), h.raw())).collect()
    }

    #[test]
    fn insert_then_pop_when_gap_fills() {
        let nxt = seq(1000);
        let mut r = Reasm::new();
        // A gap: buffer [1100, 1200).
        r.insert(nxt, wide(nxt), seq(1100), &[7u8; 100]);
        r.check(nxt);
        assert_eq!(r.buffered(), 100);
        assert!(r.pop_contiguous(nxt).is_empty()); // gap at 1000..1100 remains
        // The gap [1000,1100) arrives; now 1100 is contiguous.
        // (The caller writes [1000,1100) to rx and advances rcv_nxt to 1100 first.)
        let popped = r.pop_contiguous(seq(1100));
        assert_eq!(popped.len(), 100);
        assert!(r.is_empty());
        assert_eq!(r.buffered(), 0);
    }

    #[test]
    fn coalesces_adjacent_and_overlapping_existing_wins() {
        let nxt = seq(0);
        let mut r = Reasm::new();
        r.insert(nxt, wide(nxt), seq(10), b"BBBB"); // [10,14)
        r.insert(nxt, wide(nxt), seq(20), b"DDDD"); // [20,24)
        r.check(nxt);
        assert_eq!(report_vec(&r), vec![(20, 24), (10, 14)]); // newest (20) first
        // A bridging segment [12,22) overlaps both; existing bytes win in the overlaps.
        r.insert(nxt, wide(nxt), seq(12), b"xxxxxxxxxx"); // [12,22)
        r.check(nxt);
        // One coalesced run [10,24).
        assert_eq!(report_vec(&r), vec![(10, 24)]);
        assert_eq!(r.buffered(), 14);
        // Drain it (after rcv_nxt reaches 10) and confirm existing-wins content.
        let data = r.pop_contiguous(seq(10));
        // [10,14)=BBBB (existing), [14,20)=xxxxxx (new fills the gap), [20,24)=DDDD (existing).
        assert_eq!(&data, b"BBBBxxxxxxDDDD");
    }

    #[test]
    fn clips_below_rcv_nxt_and_above_right_edge() {
        let nxt = seq(1000);
        let mut r = Reasm::new();
        // Left clip: part of the segment is at/below rcv_nxt; only [1000,1010) is buffered...
        // but reasm only holds strictly-above data, so a segment starting below rcv_nxt that
        // reaches rcv_nxt clips to start == rcv_nxt — which is contiguous, not OOO. Use a
        // strictly-above segment with a right-edge clip instead.
        let edge = seq(1050);
        r.insert(nxt, edge, seq(1030), &[1u8; 100]); // [1030,1130) clipped to [1030,1050)
        r.check(nxt);
        assert_eq!(r.buffered(), 20);
        assert_eq!(report_vec(&r), vec![(1030, 1050)]);
        // Wholly past the edge: dropped.
        r.insert(nxt, edge, seq(1060), &[2u8; 10]);
        assert_eq!(r.buffered(), 20);
    }

    #[test]
    fn duplicate_ooo_is_idempotent() {
        let nxt = seq(0);
        let mut r = Reasm::new();
        r.insert(nxt, wide(nxt), seq(100), b"hello");
        r.insert(nxt, wide(nxt), seq(100), b"hello"); // exact duplicate
        r.check(nxt);
        assert_eq!(r.buffered(), 5);
        assert_eq!(report_vec(&r), vec![(100, 105)]);
    }

    #[test]
    fn report_is_most_recent_first_and_capped() {
        let nxt = seq(0);
        let mut r = Reasm::new();
        for k in 0..6u32 {
            // Six disjoint runs at 100, 200, ... inserted in ascending order.
            r.insert(nxt, wide(nxt), seq(100 + k * 100), &[0u8; 10]);
        }
        r.check(nxt);
        let v = report_vec(&r);
        assert_eq!(v.len(), crate::wire::MAX_SACK_BLOCKS); // capped at 4
        // Most recently inserted (600) first, then 500, 400, 300.
        assert_eq!(v, vec![(600, 610), (500, 510), (400, 410), (300, 310)]);
    }

    #[test]
    fn wraparound_around_zero() {
        // rcv_nxt just below the 2^32 wrap; OOO data spans the wrap.
        let nxt = seq(0xFFFF_FF00);
        let mut r = Reasm::new();
        r.insert(nxt, wide(nxt), seq(0xFFFF_FF80), &[9u8; 200]); // crosses 0
        r.check(nxt);
        assert_eq!(r.buffered(), 200);
        let v = report_vec(&r);
        assert_eq!(v, vec![(0xFFFF_FF80, 0x48)]); // 0xFFFFFF80 + 200 wraps to 0x48
    }

    #[test]
    fn discard_below_purges_and_clips_overtaken_runs() {
        let nxt = seq(0);
        let mut r = Reasm::new();
        r.insert(nxt, wide(nxt), seq(100), &[1u8; 50]); // [100,150)
        r.insert(nxt, wide(nxt), seq(300), &[2u8; 50]); // [300,350)
        assert_eq!(r.buffered(), 100);
        // An in-order write overtook rcv_nxt to 320: [100,150) is wholly below (purged), and
        // [300,350) straddles 320 -> clipped to [320,350). The clipped run sits exactly at
        // rcv_nxt, so the caller's pop_contiguous drains it next (the steady-state "strictly
        // above" invariant is restored after that pop).
        r.discard_below(seq(320));
        assert_eq!(r.buffered(), 30); // only [320,350) survives
        let popped = r.pop_contiguous(seq(320));
        assert_eq!(popped.len(), 30);
        assert!(r.is_empty());
        assert_eq!(r.buffered(), 0);
        // Discarding past everything empties without surprises.
        let mut r2 = Reasm::new();
        r2.insert(nxt, wide(nxt), seq(100), &[1u8; 50]);
        r2.discard_below(seq(500));
        assert!(r2.is_empty());
    }
}
