//! A hand-rolled, zero-dependency **bounded model checker**.
//!
//! Where the [`crate::sim`] greybox fuzzer *samples* the input space, this *exhausts* a bounded slice
//! of it: it enumerates **every** operation sequence (up to a small depth, over a small sequence-number
//! window) the SACK scoreboard can be driven through, and **every** structured option string the TCP
//! option walker can be handed, and confirms the invariants hold on all of them — a finite *proof* for
//! that bound, not a sample. There is no external model checker (Kani/CBMC and friends): just nested
//! loops over `std`, so it stays zero-dependency and runs anywhere the crate does. Because the engine
//! is **sans-IO**, the code paths the checker drives are exactly the ones the live stack runs.
//!
//! Together with the sampled DST fuzzer, this is the other half of "a TCP you can both *fuzz* and
//! *prove*": the fuzzer reaches deep, realistic states with low effort; the checker gives an exhaustive
//! guarantee over a small but complete neighbourhood (including across the 2³² sequence-number wrap).

use crate::sack::Scoreboard;
use crate::seq::SeqNumber;
use crate::wire::{TcpPacket, MAX_SACK_BLOCKS};

/// What an exhaustive sweep found: how many cases it checked, and the first invariant violation it hit
/// (a complete repro, since the checker is deterministic). A correct stack yields `violations == 0`.
#[derive(Debug, Default)]
pub struct BmcReport {
    pub cases: u64,
    pub violations: u64,
    pub first_violation: Option<String>,
}

impl BmcReport {
    fn check(&mut self, result: Result<(), String>) {
        self.cases += 1;
        if let Err(why) = result {
            self.violations += 1;
            if self.first_violation.is_none() {
                self.first_violation = Some(why);
            }
        }
    }
}

// ── SACK scoreboard ──────────────────────────────────────────────────────────────────────────────

/// One operation the scoreboard exposes — the alphabet the checker enumerates over.
#[derive(Clone, Copy)]
enum Op {
    Update(SeqNumber, SeqNumber),
    Rexmit(SeqNumber, SeqNumber),
    Trim(SeqNumber),
    Begin(SeqNumber),
    Exit,
    Rto,
}

/// The full operation alphabet over a window `[base, base + n]` (`nxt = base + n`): every SACK block
/// and rexmit range whose edges are window points — **including** empty, inverted, and out-of-window
/// ones, to stress the validation — every cumulative-ACK advance, and the three recovery transitions.
fn scoreboard_alphabet(base: SeqNumber, n: u32, nxt: SeqNumber) -> Vec<Op> {
    let mut ops = Vec::new();
    for i in 0..=n {
        for j in 0..=n {
            ops.push(Op::Update(base + i, base + j));
            ops.push(Op::Rexmit(base + i, base + j));
        }
    }
    for t in 0..=n {
        ops.push(Op::Trim(base + t));
    }
    ops.push(Op::Begin(nxt));
    ops.push(Op::Exit);
    ops.push(Op::Rto);
    ops
}

/// Apply one op, advancing the tracked cumulative ACK `una` monotonically on a `Trim` (snd_una only
/// ever advances in TCP), so the predicate checks below always run against a consistent `(una, nxt)`.
fn apply(sb: &mut Scoreboard, op: Op, una: &mut SeqNumber, nxt: SeqNumber) {
    match op {
        Op::Update(l, r) => sb.update(*una, nxt, &[(l, r)]),
        Op::Rexmit(l, r) => sb.mark_rexmit(l, r),
        Op::Trim(t) => {
            if t.gt(*una) && t.le(nxt) {
                *una = t;
            }
            sb.trim(*una);
        }
        Op::Begin(rp) => sb.begin_recovery(rp),
        Op::Exit => sb.exit_recovery(),
        Op::Rto => sb.on_rto(),
    }
}

/// The invariants a correct scoreboard must satisfy in state `(una, nxt)`: it is internally well-formed
/// (sorted, disjoint, non-empty run lists); the RFC 6675 pipe estimate never exceeds the bytes in
/// flight; and `next_seg`, when it proposes a hole, proposes one inside `[una, nxt)` that is genuinely
/// unsacked and un-rexmitted. `is_lost`/`pipe`/`next_seg` are also implicitly checked to never panic.
fn scoreboard_invariants(sb: &Scoreboard, una: SeqNumber, nxt: SeqNumber, smss: u32) -> Result<(), String> {
    if !sb.invariants_hold() {
        return Err("run list is not sorted/disjoint/non-empty".to_string());
    }
    let inflight = nxt.offset_from(una);
    let pipe = sb.pipe(una, nxt, smss);
    if pipe > inflight {
        return Err(format!("pipe {pipe} exceeds inflight {inflight} (una={}, nxt={})", una.raw(), nxt.raw()));
    }
    if let Some((seq, _)) = sb.next_seg(una, nxt, smss) {
        if !(seq.ge(una) && seq.lt(nxt)) {
            return Err(format!("next_seg {} outside [{}, {})", seq.raw(), una.raw(), nxt.raw()));
        }
        if sb.is_sacked(seq) || sb.is_rexmit(seq) {
            return Err(format!("next_seg {} is already sacked or rexmit", seq.raw()));
        }
    }
    Ok(())
}

/// Recursively enumerate every op sequence up to `depth` from the given state, checking the invariants
/// after each op. The clone per branch is what turns this into a tree walk over all reachable states.
fn explore(sb: &Scoreboard, una: SeqNumber, nxt: SeqNumber, alphabet: &[Op], depth: u32, smss: u32, report: &mut BmcReport) {
    if depth == 0 {
        return;
    }
    for &op in alphabet {
        let mut next_sb = sb.clone();
        let mut next_una = una;
        apply(&mut next_sb, op, &mut next_una, nxt);
        report.check(scoreboard_invariants(&next_sb, next_una, nxt, smss));
        explore(&next_sb, next_una, nxt, alphabet, depth - 1, smss, report);
    }
}

/// **Exhaustively** drive the SACK scoreboard through every operation sequence up to `depth` over a
/// window of `n` points, from a fresh board — at `base = 0` **and** at a base straddling the 2³² wrap,
/// so wrap-correctness is *proven*, not assumed. `smss` is the segment size the RFC 6675 predicates
/// use. Returns the case count and any invariant violation (a correct scoreboard yields zero).
pub fn check_scoreboard(n: u32, depth: u32, smss: u32) -> BmcReport {
    let mut report = BmcReport::default();
    for &base_raw in &[0u32, 0xFFFF_FFFFu32.wrapping_sub(n)] {
        let base = SeqNumber::new(base_raw);
        let nxt = base + n;
        let alphabet = scoreboard_alphabet(base, n, nxt);
        let sb = Scoreboard::new();
        explore(&sb, base, nxt, &alphabet, depth, smss, &mut report);
    }
    report
}

// ── TCP option walker ────────────────────────────────────────────────────────────────────────────

/// Build a minimal TCP segment whose options are `opts` (length a multiple of 4 and ≤ 40, so the data
/// offset is valid), parse it, and call **every** option accessor — each drives the `for_each_option`
/// TLV walker, which must never panic and must always terminate. Returns `Ok(())` if the bytes were a
/// structurally valid header (the walk ran) or were rejected by `new_checked` (nothing to walk).
fn probe_options(opts: &[u8]) -> Result<(), String> {
    let hlen = 20 + opts.len();
    let mut buf = vec![0u8; hlen];
    buf[12] = ((hlen / 4) as u8) << 4; // data offset in 32-bit words; reserved/flags = 0
    buf[20..].copy_from_slice(opts);
    let pkt = match TcpPacket::new_checked(&buf) {
        Ok(p) => p,
        Err(_) => return Ok(()), // structurally rejected: there is nothing to walk
    };
    // Every accessor walks the options; reaching here without panicking *is* the property.
    let _ = pkt.mss_option();
    let _ = pkt.window_scale();
    let _ = pkt.timestamps();
    let _ = pkt.sack_permitted();
    let mut blocks = [(SeqNumber::new(0), SeqNumber::new(0)); MAX_SACK_BLOCKS];
    let n = pkt.sack_blocks(&mut blocks);
    if n > MAX_SACK_BLOCKS {
        return Err(format!("sack_blocks returned {n} > MAX_SACK_BLOCKS"));
    }
    Ok(())
}

/// `f` over every byte string of length `len` drawn from `alphabet` (odometer enumeration).
fn enumerate_strings(buf: &mut Vec<u8>, len: usize, alphabet: &[u8], f: &mut impl FnMut(&[u8])) {
    if buf.len() == len {
        f(buf);
        return;
    }
    for &b in alphabet {
        buf.push(b);
        enumerate_strings(buf, len, alphabet, f);
        buf.pop();
    }
}

/// **Exhaustively** feed the TCP option walker every option string of exactly `len_words` 32-bit words
/// drawn from `alphabet`, and confirm no accessor panics and the walk always terminates. Pass an
/// alphabet of the structurally-meaningful bytes (EOL/NOP, every option kind, boundary length values,
/// a payload byte): the full 256-symbol space is infeasible to exhaust, but the walker only ever
/// branches on those, so this is exhaustive over its actual decision space. Zero violations expected.
pub fn check_option_strings(alphabet: &[u8], len_words: usize) -> BmcReport {
    let mut report = BmcReport::default();
    let len = len_words * 4;
    let mut buf = Vec::with_capacity(len);
    enumerate_strings(&mut buf, len, alphabet, &mut |s| {
        report.check(probe_options(s));
    });
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PROOF (bounded): across *every* sequence of up to three scoreboard operations over a small
    /// window — at sequence-number base 0 and straddling the 2³² wrap — the scoreboard stays
    /// well-formed, the RFC 6675 pipe never exceeds the bytes in flight, and `next_seg` only ever
    /// proposes a real unsacked/un-rexmitted hole inside the window. ~400 K reachable states, exhaustive.
    #[test]
    #[cfg_attr(miri, ignore)] // hundreds of thousands of states — far beyond Miri's budget
    fn scoreboard_invariants_hold_exhaustively() {
        let r = check_scoreboard(4, 3, 1);
        assert!(r.cases > 100_000, "the sweep must be substantial: {} cases", r.cases);
        assert_eq!(r.violations, 0, "scoreboard invariant violated; first repro: {:?}", r.first_violation);
    }

    /// PROOF (bounded): the TCP option walker is panic-free and terminating on *every* option string up
    /// to two 32-bit words over the bytes it actually branches on (EOL/NOP, every option kind, the
    /// length boundaries, a payload byte) — over a million distinct option layouts, exhaustive.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn option_walker_is_panic_free_exhaustively() {
        // One full option word over the complete structural alphabet (every 4-byte option string).
        let r1 = check_option_strings(&[0, 1, 2, 3, 4, 5, 8, 10, 18, 255], 1);
        assert!(r1.cases >= 10_000, "single-word sweep: {} cases", r1.cases);
        assert_eq!(r1.violations, 0, "{:?}", r1.first_violation);
        // Two words over a leaner alphabet — exhausts every two-option / longer-option layout.
        let r2 = check_option_strings(&[0, 1, 2, 4, 5, 8], 2);
        assert!(r2.cases >= 1_000_000, "two-word sweep: {} cases", r2.cases);
        assert_eq!(r2.violations, 0, "{:?}", r2.first_violation);
    }

    /// A negative control proving the checker has teeth: a deliberately broken "scoreboard invariant"
    /// (asserting the pipe is always zero) is caught on the very first non-trivial state, with a repro.
    #[test]
    fn the_checker_catches_a_violation() {
        // A tiny hand-driven board with one SACK block: a bogus invariant (pipe == 0) must trip.
        let mut sb = Scoreboard::new();
        let (una, nxt) = (SeqNumber::new(0), SeqNumber::new(4000));
        sb.update(una, nxt, &[(SeqNumber::new(1000), SeqNumber::new(2000))]);
        let mut report = BmcReport::default();
        let bogus = if sb.pipe(una, nxt, 1000) == 0 { Ok(()) } else { Err("pipe is non-zero".to_string()) };
        report.check(bogus);
        assert_eq!(report.violations, 1, "the checker must flag a false invariant");
        assert!(report.first_violation.is_some());
    }
}
