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

use crate::congestion::{CongestionControl, Learned, LearnedParams};
use crate::sack::Scoreboard;
use crate::seq::SeqNumber;
use crate::time::Instant;
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

/// A predicate the sweep evaluates after every op. The production checker passes [`scoreboard_invariants`];
/// the negative-control test passes a deliberately-false one to prove the enumeration actually surfaces
/// violations (so the proof can't silently degrade to checking nothing).
type Invariant = fn(&Scoreboard, SeqNumber, SeqNumber, u32) -> Result<(), String>;

/// The parameters fixed for one whole sweep — bundled so the recursive [`explore`] stays few-argument.
struct Sweep<'a> {
    alphabet: &'a [Op],
    nxt: SeqNumber,
    smss: u32,
    inv: Invariant,
}

/// Recursively enumerate every op sequence up to `depth` from the given state, evaluating the sweep's
/// invariant after each op. The clone per branch is what turns this into a tree walk over all reachable
/// states.
fn explore(ctx: &Sweep, sb: &Scoreboard, una: SeqNumber, depth: u32, report: &mut BmcReport) {
    if depth == 0 {
        return;
    }
    for &op in ctx.alphabet {
        let mut next_sb = sb.clone();
        let mut next_una = una;
        apply(&mut next_sb, op, &mut next_una, ctx.nxt);
        report.check((ctx.inv)(&next_sb, next_una, ctx.nxt, ctx.smss));
        explore(ctx, &next_sb, next_una, depth - 1, report);
    }
}

/// Run the exhaustive scoreboard sweep evaluating `inv` after every op, at `base = 0` and at a base
/// straddling the 2³² wrap. Factored out so the negative-control test can drive the *same* enumeration
/// with a false invariant.
fn run_scoreboard_sweep(n: u32, depth: u32, smss: u32, inv: Invariant) -> BmcReport {
    let mut report = BmcReport::default();
    for &base_raw in &[0u32, 0xFFFF_FFFFu32.wrapping_sub(n)] {
        let base = SeqNumber::new(base_raw);
        let nxt = base + n;
        let alphabet = scoreboard_alphabet(base, n, nxt);
        let ctx = Sweep { alphabet: &alphabet, nxt, smss, inv };
        explore(&ctx, &Scoreboard::new(), base, depth, &mut report);
    }
    report
}

/// **Exhaustively** drive the SACK scoreboard through every operation sequence up to `depth` over a
/// window of `n` points, from a fresh board — at `base = 0` **and** at a base straddling the 2³² wrap,
/// so wrap-correctness is *proven*, not assumed. `smss` is the segment size the RFC 6675 predicates
/// use. Returns the case count and any invariant violation (a correct scoreboard yields zero).
pub fn check_scoreboard(n: u32, depth: u32, smss: u32) -> BmcReport {
    run_scoreboard_sweep(n, depth, smss, scoreboard_invariants)
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

// ── congestion-control safety envelope ────────────────────────────────────────────────────────────

/// The clock the controller events are stamped with. Reno/DCTCP/Learned are ACK-clocked and ignore it;
/// Prague reads RTT (delivered via [`CcEvent::Rtt`]), not this. Fixed, so the sweep is deterministic.
const CC_NOW: Instant = Instant::ZERO;

/// The **FlightSize** a loss event reports — the bytes outstanding (`snd_nxt − snd_una`). The live TCB
/// derives this *independently* of `cwnd` and never caps it to the window, so it **can exceed the
/// current `cwnd`**: a controller cuts `cwnd` mid-flight (an ECN mark, or an RTO that collapses it to
/// one segment) while the data already on the wire — and thus `snd_nxt` — stays put. Modelling flight
/// as a fixed set of MSS-scaled byte counts (independent of `cwnd`) is therefore the *real* contract;
/// an earlier version keyed it off the live `cwnd` and the adversarial review proved that under-modelled
/// the stack — it hid exactly the `flight > cwnd` loss responses the live TCB reaches.
#[derive(Clone, Copy)]
enum Flight {
    Small,  // 2·MSS
    Window, // ≈ one initial window
    Large,  // a big stale flight, well above a freshly-cut cwnd
}

/// One event the TCB can deliver to a [`CongestionControl`] — the alphabet the checker enumerates over.
/// `Ack`/`Ecn` carry absolute byte counts (scaled to the MSS); the loss events carry a [`Flight`].
#[derive(Clone, Copy)]
enum CcEvent {
    Ack(u32),
    Ecn(u32, u32),
    Rtt(u32),
    DupAck(Flight),
    Rto(Flight),
    EnterRecovery(Flight),
}

/// The bounded event alphabet at segment size `mss`: clean ACKs (none / one segment / a full initial
/// window — enough to close an ECN observation window in one event), ECN rounds at no / light / full
/// marking, a short and a long RTT sample (for Prague's RTT-independent step), and the three loss
/// signals at each of the three FlightSizes (including one **larger than any cwnd a short sequence can
/// reach**, so the `flight > cwnd` loss response is actually exercised). The walker only branches on
/// these, so a sweep over them is exhaustive over the controller's actual decision space.
fn cc_alphabet(mss: u32) -> Vec<CcEvent> {
    let w = 10 * mss; // ≈ one RFC 6928 initial window — closes a DCTCP/Learned observation window
    vec![
        CcEvent::Ack(0),
        CcEvent::Ack(mss),
        CcEvent::Ack(w),
        CcEvent::Ecn(w, 0),
        CcEvent::Ecn(w, mss),
        CcEvent::Ecn(w, w),
        CcEvent::Rtt(1_000),
        CcEvent::Rtt(200_000),
        CcEvent::DupAck(Flight::Small),
        CcEvent::DupAck(Flight::Window),
        CcEvent::DupAck(Flight::Large),
        CcEvent::Rto(Flight::Small),
        CcEvent::Rto(Flight::Window),
        CcEvent::Rto(Flight::Large),
        CcEvent::EnterRecovery(Flight::Small),
        CcEvent::EnterRecovery(Flight::Window),
        CcEvent::EnterRecovery(Flight::Large),
    ]
}

#[inline]
fn flight_bytes(mss: u32, fl: Flight) -> u32 {
    match fl {
        Flight::Small => 2 * mss,
        Flight::Window => 10 * mss,
        Flight::Large => 40 * mss,
    }
}

/// Apply one event to the controller, returning `Some(flight)` if it was a **loss** signal that actually
/// engaged the loss response (with the FlightSize it reported), else `None`. A 1st/2nd duplicate ACK only
/// counts toward the threshold and is not yet a loss, so it returns `None`.
fn apply_cc<C: CongestionControl>(c: &mut C, ev: CcEvent, mss: u32) -> Option<u32> {
    match ev {
        CcEvent::Ack(a) => {
            c.on_ack(CC_NOW, a);
            None
        }
        CcEvent::Ecn(a, m) => {
            c.on_ecn(CC_NOW, a, m);
            None
        }
        CcEvent::Rtt(s) => {
            c.on_rtt_sample(s);
            None
        }
        CcEvent::DupAck(fl) => {
            let f = flight_bytes(mss, fl);
            if c.on_dup_ack(CC_NOW, f) {
                Some(f) // the threshold (3rd) dup-ACK engaged the loss response
            } else {
                None
            }
        }
        CcEvent::Rto(fl) => {
            let f = flight_bytes(mss, fl);
            c.on_rto(CC_NOW, f);
            Some(f)
        }
        CcEvent::EnterRecovery(fl) => {
            let f = flight_bytes(mss, fl);
            c.enter_recovery(CC_NOW, f);
            Some(f)
        }
    }
}

// The three *gain-dependent* clauses (2/3/4) each open their violation message with a stable tag below.
// `crate::sim`'s CEGIS repair routes a counterexample to the matching response by `contains`-ing these
// tags, so they are part of the cross-module contract: both sides reference these consts (not a literal
// copy), so a reword is a single compile-coupled edit and the teeth tests pin that the message carries it.
/// Violation-message tag for clause 2 (a loss inflated `cwnd` past the pipe).
pub(crate) const CLAUSE_LOSS_INFLATED: &str = "loss inflated cwnd";
/// Violation-message tag for clause 3 (an ECN mark grew `cwnd`).
pub(crate) const CLAUSE_ECN_GREW: &str = "ECN mark grew cwnd";
/// Violation-message tag for clause 4 (a clean ACK shrank `cwnd`).
pub(crate) const CLAUSE_ACK_SHRANK: &str = "clean ACK shrank cwnd";

/// The **safety envelope** a congestion controller must satisfy after every event — the machine-checked
/// guarantees that make a *synthesised* (evolved) controller trustworthy regardless of its gains. The
/// loss clauses take the **FlightSize** the event reported (`loss_flight`), since the RFC 5681 loss
/// response is defined in terms of the bytes actually in flight, not the (possibly already-cut) `cwnd`:
///
/// 1. **Starvation-freedom** — `cwnd ≥ MSS`: the window never collapses below one segment (a controller
///    that drove `cwnd` to 0 would wedge the connection).
/// 2. **Loss never inflates the window past the pipe** — a loss sets `cwnd ≤ max(FlightSize, 2·MSS)`. A
///    correct response *cuts* the in-flight bytes (`cwnd ← FlightSize · β`, `β < 1`, RFC 5681 uses
///    `β = ½`) with the `2·MSS` floor; it must never set `cwnd` *above* what was outstanding. This is
///    exactly the clause an over-aggressive gain breaks: `md_loss > 1` makes `cwnd = FlightSize · md_loss`
///    exceed `FlightSize`. (Note `FlightSize` can exceed `cwnd_before`, so this is *not* "no growth on
///    loss" — a flight-based cut may legitimately raise a previously-collapsed `cwnd`; what it bounds is
///    inflation past the real pipe.)
/// 3. **ECN-monotonicity** — an ECN-marked round never grows `cwnd` (it cuts or holds).
/// 4. **Clean-ACK monotonicity** — a clean ACK of new data never shrinks `cwnd`.
/// 5. **`ssthresh` floor on loss** — after a loss, `ssthresh ≥ 2·MSS` (RFC 5681).
fn cc_safety_invariants(
    ev: CcEvent,
    cwnd_before: u32,
    cwnd: u32,
    ssthresh: u32,
    mss: u32,
    loss_flight: Option<u32>,
) -> Result<(), String> {
    if cwnd < mss {
        return Err(format!("cwnd {cwnd} fell below one MSS {mss}"));
    }
    if let Some(flight) = loss_flight {
        if cwnd > flight.max(2 * mss) {
            return Err(format!("{CLAUSE_LOSS_INFLATED} above the FlightSize: cwnd {cwnd} > max(flight {flight}, 2·MSS {})", 2 * mss));
        }
        if ssthresh < 2 * mss {
            return Err(format!("ssthresh {ssthresh} below the 2·MSS floor {} after loss", 2 * mss));
        }
    }
    if matches!(ev, CcEvent::Ecn(..)) && cwnd > cwnd_before {
        return Err(format!("an {CLAUSE_ECN_GREW}: {cwnd_before} -> {cwnd}"));
    }
    if matches!(ev, CcEvent::Ack(a) if a > 0) && cwnd < cwnd_before {
        return Err(format!("a {CLAUSE_ACK_SHRANK}: {cwnd_before} -> {cwnd}"));
    }
    Ok(())
}

/// A predicate the controller sweep evaluates after every event. The production checker passes
/// [`cc_safety_invariants`]; the negative-control test passes a deliberately-false one to prove the
/// enumeration apparatus actually surfaces violations (the same teeth-check the scoreboard sweep has).
type CcInvariant = fn(CcEvent, u32, u32, u32, u32, Option<u32>) -> Result<(), String>;

/// Recursively enumerate every event sequence up to `depth` from the controller's current state,
/// evaluating `inv` after each event. The clone per branch makes it a tree walk over all reachable
/// controller states — exactly as [`explore`] does for the scoreboard.
fn explore_cc<C: CongestionControl + Clone>(alphabet: &[CcEvent], inv: CcInvariant, mss: u32, c: &C, depth: u32, report: &mut BmcReport) {
    if depth == 0 {
        return;
    }
    for &ev in alphabet {
        let mut next = c.clone();
        let cwnd_before = next.cwnd();
        let loss_flight = apply_cc(&mut next, ev, mss);
        report.check(inv(ev, cwnd_before, next.cwnd(), next.ssthresh(), mss, loss_flight));
        explore_cc(alphabet, inv, mss, &next, depth - 1, report);
    }
}

/// Drive `controller` through every event sequence up to `depth` over the bounded alphabet, evaluating
/// `inv` after each event. Factored out so the negative control can run the *same* enumeration with a
/// false invariant.
fn run_cc_sweep<C: CongestionControl + Clone>(controller: C, mss: u32, depth: u32, inv: CcInvariant) -> BmcReport {
    let alphabet = cc_alphabet(mss);
    let mut report = BmcReport::default();
    explore_cc(&alphabet, inv, mss, &controller, depth, &mut report);
    report
}

/// **Exhaustively** drive `controller` through every congestion-control event sequence up to `depth`
/// and confirm the [`cc_safety_invariants`] hold after every event — a finite *proof* that, over this
/// bounded neighbourhood, the controller stays inside the safety envelope no matter what the network
/// does. Because the engine is sans-IO, the code paths driven are exactly the live stack's. Returns the
/// case count and the first violation (a correct controller yields zero).
pub fn check_controller_safety<C: CongestionControl + Clone>(controller: C, mss: u32, depth: u32) -> BmcReport {
    run_cc_sweep(controller, mss, depth, cc_safety_invariants)
}

/// **Exhaustively** verify the safety envelope over a grid of the **sanitised** `Learned` genome space —
/// each of the five gains at its min / midpoint / max (`3⁵ = 243` genomes) — driving every one through
/// the bounded event sweep. The grid is not arbitrary: of the five envelope invariants, four hold
/// *structurally* for **any** genome (the cut operations floor at `MSS` / `2·MSS`, the additive step
/// floors at 1 byte, and the ECN cut is `clamp(…, 0, ecn_max)` so it can never be negative = growth);
/// only "loss never inflates past the FlightSize" depends on a gene — `cwnd = FlightSize · md_loss`, so
/// it needs `md_loss ≤ 1`, and the binding worst case is the **maximum** `md_loss = 0.95` the grid
/// includes (sanitisation clamps it there). So zero violations here is, together with that structural
/// argument, evidence that the *whole* sanitised genome box — everything the CEM search can synthesise —
/// is safe over this bound: the "evolve **and** prove" guarantee. Returns the aggregate case count and
/// the first violation, if any.
pub fn check_learned_genome_space(mss: u32, depth: u32) -> BmcReport {
    let grid = |lo: f64, hi: f64| [lo, (lo + hi) / 2.0, hi];
    let mut report = BmcReport::default();
    for &ai in &grid(0.05, 8.0) {
        for &md in &grid(0.1, 0.95) {
            for &ea in &grid(0.0, 2.0) {
                for &eb in &grid(-1.0, 2.0) {
                    for &em in &grid(0.05, 0.95) {
                        let p = LearnedParams { ai_gain: ai, md_loss: md, ecn_a: ea, ecn_b: eb, ecn_max: em };
                        let sub = check_controller_safety(Learned::with_params(mss as u16, p), mss, depth);
                        report.cases += sub.cases;
                        report.violations += sub.violations;
                        if report.first_violation.is_none() {
                            report.first_violation = sub.first_violation;
                        }
                    }
                }
            }
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::congestion::{initial_window, ControlProgram, Dctcp, Instr, Prague, Reno, Synth, SynthOp};

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

    /// A negative control proving the checker has teeth — and, crucially, exercising the **real**
    /// enumeration apparatus (`explore` → `inv` → report), not just the counter bookkeeping. It runs
    /// the same exhaustive sweep with a deliberately-false invariant ("the scoreboard must never hold a
    /// SACK run"); an `Update` op makes it false, so the sweep must surface violations with a repro. If
    /// the enumeration or wiring ever silently broke (e.g. `explore` stopped recursing, the alphabet
    /// emptied, or the real invariant always returned `Ok`), *this* test goes red — which the
    /// always-zero-violations positive sweeps could not catch on their own.
    #[test]
    #[cfg_attr(miri, ignore)] // drives the enumeration (~thousands of states) — too slow for Miri
    fn the_checker_catches_a_violation() {
        fn always_no_sack(sb: &Scoreboard, _: SeqNumber, _: SeqNumber, _: u32) -> Result<(), String> {
            match sb.highest_sacked_edge() {
                None => Ok(()),
                Some(e) => Err(format!("a SACK run exists (edge {})", e.raw())),
            }
        }
        let r = run_scoreboard_sweep(4, 2, 1, always_no_sack);
        assert!(r.cases > 1_000, "the sweep must actually run: {} cases", r.cases);
        assert!(r.violations > 0, "the real enumeration must flag the false invariant");
        assert!(r.first_violation.is_some(), "...and produce a repro");
        // Belt-and-braces: the *true* invariant over the very same sweep finds nothing.
        let real = run_scoreboard_sweep(4, 2, 1, scoreboard_invariants);
        assert_eq!(real.violations, 0, "the real invariant holds over the same states");
    }

    /// PROOF (bounded): each shipped controller — Reno, DCTCP, Prague, and the evolved `Learned` (baked
    /// genome) — stays inside the **safety envelope** (`cwnd ≥ MSS`, no growth on loss above the 2·MSS
    /// floor, ECN never grows the window, a clean ACK never shrinks it, `ssthresh ≥ 2·MSS` after loss)
    /// across *every* event sequence up to depth 4 over the bounded alphabet. Not a sample — a finite
    /// guarantee that no adversarial ordering of acks / marks / losses / RTT samples breaks the envelope.
    #[test]
    #[cfg_attr(miri, ignore)] // tens of thousands of states per controller — beyond Miri's budget
    fn controller_safety_holds_for_the_stock_controllers() {
        let mss = 1000u32;
        let runs = [
            ("reno", check_controller_safety(Reno::new(mss as u16), mss, 4)),
            ("dctcp", check_controller_safety(Dctcp::new(mss as u16), mss, 4)),
            ("prague", check_controller_safety(Prague::new(mss as u16), mss, 4)),
            ("learned(baked)", check_controller_safety(Learned::with_params(mss as u16, LearnedParams::BAKED), mss, 4)),
            ("synth(baked)", check_controller_safety(Synth::with_program(mss as u16, ControlProgram::BAKED_SYNTH), mss, 4)),
        ];
        for (name, report) in runs {
            assert!(report.cases > 10_000, "{name}: the sweep must be substantial: {} cases", report.cases);
            assert_eq!(report.violations, 0, "{name} broke the safety envelope; first repro: {:?}", report.first_violation);
        }
    }

    /// PROOF (bounded), the headline **"evolve AND prove"** result: the *entire sanitised genome space*
    /// the CEM search can ever synthesise — every one of the 243 genomes at the gene min/mid/max — stays
    /// inside the safety envelope across every event sequence up to depth 3. Because the synthesiser
    /// clamps every gene into exactly these ranges (`LearnedParams::sanitized`), this is a finite proof
    /// that **synthesis is confined to a verified-safe region**: a learned controller that is, by
    /// construction, machine-checked never to starve a flow, grow its window on congestion, or shrink it
    /// on success — the safety guarantee learned/RL controllers are usually unable to offer.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn learned_genome_space_is_provably_safe() {
        let r = check_learned_genome_space(1000, 3);
        assert!(r.cases > 500_000, "the genome-space sweep must be substantial: {} cases", r.cases);
        assert_eq!(r.violations, 0, "a sanitised genome broke the safety envelope; first repro: {:?}", r.first_violation);
    }

    /// The teeth, two ways. (a) An **unsanitised** pathological genome (`md_loss = 2.0`, which sets the
    /// loss window to `flight · 2 = 2·cwnd` — growth on loss) MUST violate the envelope, and the *same*
    /// genome through the sanitising constructor MUST be safe — proving the checker catches the real
    /// safety property *and* that `LearnedParams::sanitized` is load-bearing, not decorative. (b) A
    /// deliberately-false invariant over a stock controller surfaces violations, proving the enumeration
    /// actually drives the controller and reports (not just bookkeeping); the real envelope over the same
    /// states finds nothing.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn the_controller_checker_has_teeth_and_proves_sanitize_load_bearing() {
        let mss = 1000u32;
        // md_loss = 2.0 sets the loss window to FlightSize·2 > FlightSize — inflation past the pipe.
        let pathological = LearnedParams { ai_gain: 1.0, md_loss: 2.0, ecn_a: 0.5, ecn_b: 0.0, ecn_max: 0.5 };
        let unsafe_report = check_controller_safety(Learned::with_raw_params(mss as u16, pathological), mss, 3);
        assert!(unsafe_report.violations > 0, "an unsanitised md_loss=2 genome must inflate cwnd past the FlightSize on loss");
        assert!(
            unsafe_report.first_violation.as_deref().unwrap_or("").contains(CLAUSE_LOSS_INFLATED),
            "the violation is the loss-inflation one: {:?}",
            unsafe_report.first_violation
        );
        // The SAME genome, sanitised (the production path), is safe — sanitize() clamps md_loss ≤ 0.95.
        let safe_report = check_controller_safety(Learned::with_params(mss as u16, pathological), mss, 3);
        assert_eq!(safe_report.violations, 0, "sanitize() makes the genome safe: {:?}", safe_report.first_violation);

        // Apparatus teeth: a false invariant ("cwnd never exceeds the initial window") is surfaced by the
        // real enumeration on a stock controller (slow start grows past it).
        fn never_grows(_: CcEvent, _: u32, cwnd: u32, _: u32, mss: u32, _: Option<u32>) -> Result<(), String> {
            if cwnd > initial_window(mss) {
                Err(format!("cwnd {cwnd} exceeded the initial window"))
            } else {
                Ok(())
            }
        }
        let false_inv = run_cc_sweep(Reno::new(mss as u16), mss, 3, never_grows);
        assert!(false_inv.violations > 0, "the enumeration must surface the false invariant's violations");
        let real = run_cc_sweep(Reno::new(mss as u16), mss, 3, cc_safety_invariants);
        assert_eq!(real.violations, 0, "the real envelope holds over the same states");
    }

    /// Build a `Synth` sub-program that computes `first` in its first slot and carries the result to the
    /// output register (so the whole sub-program evaluates to `first`) — the rest of the law stays AIMD.
    fn sub_from(first: Instr) -> [Instr; ControlProgram::PROG_LEN] {
        let mut p = [Instr::new(SynthOp::Max, 0, 0); ControlProgram::PROG_LEN];
        p[0] = first;
        for (i, slot) in p.iter_mut().enumerate().skip(1) {
            let prev = (ControlProgram::REGS_IN + i - 1) as u8;
            *slot = Instr::new(SynthOp::Max, prev, prev);
        }
        p
    }

    /// **The synthesis-modulo-verification filter, proven to have teeth.** This is the heart of the GP
    /// synthesis: the bmc is used as a *hard reject* on a candidate control LAW, and it must (a) pass the
    /// AIMD seed unscathed, and (b) reject each of the three single-clause-unsafe laws — an increase that
    /// shrinks the window on a clean ACK, an ECN response that *grows* the window on a mark, and a loss
    /// response that inflates the window past the pipe — with exactly the matching envelope clause, even
    /// though every one of those laws is wired through the *unsanitised* `Synth` path. So the GP filter
    /// is not vacuous: it actually catches the unsafe majority a free search would produce, which is what
    /// makes "every survivor is machine-checked safe" a real guarantee and not a tautology.
    #[test]
    #[cfg_attr(miri, ignore)] // tens of thousands of states per law — beyond Miri's budget
    fn synth_safety_filter_accepts_aimd_and_rejects_unsafe_laws() {
        let mss = 1000u32;

        // (a) The AIMD seed is inside the envelope — the search's warm start is feasible.
        let safe = check_controller_safety(Synth::with_program(mss as u16, ControlProgram::AIMD), mss, 4);
        assert!(safe.cases > 10_000, "the sweep must be substantial: {} cases", safe.cases);
        assert_eq!(safe.violations, 0, "AIMD broke the envelope: {:?}", safe.first_violation);

        // (b1) An increase law `step = 0.5 − 1 = −0.5 seg/RTT` shrinks cwnd on a clean ACK (clause 4).
        let mut p = ControlProgram::AIMD;
        *p.sub_mut(0) = sub_from(Instr::new(SynthOp::Sub, 5, 6)); // r5(0.5) − r6(1) = −0.5
        let r = check_controller_safety(Synth::with_program(mss as u16, p), mss, 4);
        assert!(r.violations > 0, "a negative-increase law must violate the envelope");
        assert!(
            r.first_violation.as_deref().unwrap_or("").contains(CLAUSE_ACK_SHRANK),
            "the violation is the clean-ACK-shrink one: {:?}",
            r.first_violation
        );

        // (b2) An ECN law `cut = 0.5 − 1 = −0.5` *grows* cwnd on a CE mark (clause 3, ECN-monotonicity).
        let mut p = ControlProgram::AIMD;
        *p.sub_mut(2) = sub_from(Instr::new(SynthOp::Sub, 5, 6)); // negative cut
        let r = check_controller_safety(Synth::with_program(mss as u16, p), mss, 4);
        assert!(r.violations > 0, "a negative-cut ECN law must violate the envelope");
        assert!(
            r.first_violation.as_deref().unwrap_or("").contains(CLAUSE_ECN_GREW),
            "the violation is the ECN-growth one: {:?}",
            r.first_violation
        );

        // (b3) A loss law `cwnd = 2 · flight_seg` inflates the window past the pipe (clause 2).
        let mut p = ControlProgram::AIMD;
        *p.sub_mut(1) = sub_from(Instr::new(SynthOp::Mul, 1, 7)); // r1(flight) × r7(2)
        let r = check_controller_safety(Synth::with_program(mss as u16, p), mss, 4);
        assert!(r.violations > 0, "an inflating loss law must violate the envelope");
        assert!(
            r.first_violation.as_deref().unwrap_or("").contains(CLAUSE_LOSS_INFLATED),
            "the violation is the loss-inflation one: {:?}",
            r.first_violation
        );
    }
}
