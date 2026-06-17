//! Deterministic simulation testing (DST) — an in-process adversarial network for the stack.
//!
//! Because the engine is **sans-IO** (it reads no clock and performs no I/O — every input is an
//! explicit argument; see the crate docs), two whole [`Runtime`]s can be wired together through a
//! virtual link entirely in memory, with a **seeded** fault model — packet loss, duplication,
//! reordering (via jittered delay), and bit corruption — and driven by a deterministic
//! event-scheduler. The same seed reproduces a run *exactly*, so a failing seed **is** the bug
//! report: re-run it and it replays bit-for-bit. This is the [TigerBeetle]/[FoundationDB] style of
//! testing — millions of randomized adversarial scenarios with perfect reproducibility — applied to
//! a real TCP implementation, which production stacks can't do because they're entangled with the
//! kernel clock and NIC.
//!
//! What it checks (the invariants a correct stack must never violate, no matter the faults):
//! - **Byte integrity** — the receiver's stream equals the sender's, exactly, in order.
//! - **Eventual completion** — the transfer finishes within a generous step/time budget; a quiesced
//!   state with data still owed (no timers armed, nothing in flight) is a wedge.
//! - **No panic** — the engine survives arbitrary loss/reorder/duplication/corruption of its input.
//!
//! Everything here is **`std`-only and allocation-light**: the PRNG is a hand-rolled SplitMix64, the
//! link is plain `Vec`s, and there is no real clock — so the harness itself is `Miri`-clean and the
//! whole run is a pure function of `(seed, config)`.
//!
//! [TigerBeetle]: https://tigerbeetle.com/blog/2023-07-11-we-put-a-distributed-database-in-the-browser
//! [FoundationDB]: https://apple.github.io/foundationdb/testing.html

use std::cell::RefCell;
use std::rc::Rc;

use crate::congestion::CcKind;
use crate::iface::Endpoint;
use crate::runtime::{MockDevice, Runtime};
use crate::time::Instant;
use std::net::Ipv4Addr;

/// SplitMix64 — a tiny, fast, well-distributed deterministic PRNG (Vigna). Seeded once per scenario;
/// every fault decision draws from it, so the whole run is reproducible from the seed alone. Pure
/// integer arithmetic, so it is identical on every platform and clean under Miri.
#[derive(Clone)]
pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng { state: seed }
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// `true` with probability `ppm / 1_000_000` (parts per million — integer, so no float drift).
    #[inline]
    fn chance_ppm(&mut self, ppm: u32) -> bool {
        ppm != 0 && (self.next_u64() % 1_000_000) < ppm as u64
    }

    /// A value in `[0, n)`.
    #[inline]
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next_u64() % n
        }
    }
}

/// The fault model of the virtual link, per direction. All probabilities are parts-per-million.
#[derive(Clone, Copy, Debug)]
pub struct LinkConfig {
    /// Per-packet drop probability (ppm).
    pub loss_ppm: u32,
    /// Per-packet duplication probability (ppm) — a second copy is scheduled with its own delay.
    pub dup_ppm: u32,
    /// Per-packet bit-corruption probability (ppm) — flips one bit in the TCP region, which a
    /// correct stack must catch with the TCP checksum and never deliver to the application.
    pub corrupt_ppm: u32,
    /// Base one-way delay (µs); must be ≥ 1 so logical time strictly advances each event.
    pub min_delay_us: u64,
    /// Extra uniform `[0, jitter]` delay (µs). Non-zero jitter is what reorders packets in flight.
    pub jitter_us: u64,
}

impl LinkConfig {
    /// A perfect link: a fixed 5 ms one-way delay, no faults. The baseline.
    pub const PERFECT: LinkConfig = LinkConfig {
        loss_ppm: 0,
        dup_ppm: 0,
        corrupt_ppm: 0,
        min_delay_us: 5_000,
        jitter_us: 0,
    };

    /// A hostile-but-survivable link: `loss`% loss, 1% duplication, reordering jitter, ~10 ms RTT.
    /// A correct stack must still deliver every byte intact and terminate.
    pub fn lossy(loss_percent: u32) -> LinkConfig {
        LinkConfig {
            loss_ppm: loss_percent * 10_000,
            dup_ppm: 10_000,
            corrupt_ppm: 0,
            min_delay_us: 5_000,
            jitter_us: 4_000,
        }
    }
}

/// Which stack a frame is travelling toward.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Side {
    ToClient,
    ToServer,
}

/// A frame in flight on the virtual link, scheduled for delivery at `deliver_at`.
struct InFlight {
    deliver_at: Instant,
    side: Side,
    /// Monotonic enqueue counter — breaks ties so equal-delay frames deliver in send order
    /// (deterministic regardless of `Vec` layout).
    order: u64,
    frame: Vec<u8>,
}

/// The virtual link: a single seeded RNG and a queue of in-flight frames. Each direction applies the
/// same [`LinkConfig`]; faults are drawn from the RNG, so the entire path is reproducible.
struct Link {
    rng: Rng,
    cfg: LinkConfig,
    inflight: Vec<InFlight>,
    order: u64,
}

impl Link {
    fn new(seed: u64, cfg: LinkConfig) -> Self {
        Link { rng: Rng::new(seed), cfg, inflight: Vec::new(), order: 0 }
    }

    /// A frame left a stack at `now`, heading to `side`. Apply the fault model and (unless dropped)
    /// schedule it — plus a duplicate, if drawn.
    fn enqueue(&mut self, now: Instant, side: Side, frame: Vec<u8>) {
        if self.rng.chance_ppm(self.cfg.loss_ppm) {
            return; // dropped on the wire
        }
        let corrupt = self.rng.chance_ppm(self.cfg.corrupt_ppm);
        self.schedule(now, side, frame.clone(), corrupt);
        if self.rng.chance_ppm(self.cfg.dup_ppm) {
            // A duplicate with an independent delay (so it may arrive before or after the original).
            self.schedule(now, side, frame, false);
        }
    }

    fn schedule(&mut self, now: Instant, side: Side, mut frame: Vec<u8>, corrupt: bool) {
        if corrupt && frame.len() > 20 {
            // Flip one bit in the TCP region (offset ≥ 20, past the IPv4 header) so the TCP checksum
            // — which covers the TCP header, payload, and IP pseudo-header — must reject it.
            let off = 20 + self.rng.below((frame.len() - 20) as u64) as usize;
            frame[off] ^= 1 << (self.rng.below(8) as u8);
        }
        let delay = self.cfg.min_delay_us + self.rng.below(self.cfg.jitter_us + 1);
        let order = self.order;
        self.order += 1;
        self.inflight.push(InFlight { deliver_at: now.plus_micros(delay), side, order, frame });
    }

    /// The earliest scheduled delivery, if any (drives the event scheduler's clock).
    fn next_deliver_at(&self) -> Option<Instant> {
        self.inflight.iter().map(|f| f.deliver_at).min()
    }

    /// Inject every frame now due (`deliver_at ≤ now`) into its destination stack, in
    /// `(deliver_at, order)` order so delivery is deterministic.
    fn deliver_due(&mut self, now: Instant, client: &mut Runtime<MockDevice>, server: &mut Runtime<MockDevice>) {
        let mut due: Vec<InFlight> = Vec::new();
        let mut keep: Vec<InFlight> = Vec::new();
        for f in std::mem::take(&mut self.inflight) {
            if f.deliver_at <= now {
                due.push(f);
            } else {
                keep.push(f);
            }
        }
        self.inflight = keep;
        due.sort_by_key(|f| (f.deliver_at, f.order));
        for f in due {
            match f.side {
                Side::ToClient => client.device_mut().inject(f.frame),
                Side::ToServer => server.device_mut().inject(f.frame),
            }
        }
    }
}

/// One scenario to simulate: a seed, the link's fault model, how many bytes to transfer, and which
/// congestion controller both stacks run. Deterministic — `run` is a pure function of this.
#[derive(Clone, Copy, Debug)]
pub struct Scenario {
    pub seed: u64,
    pub link: LinkConfig,
    pub bytes: usize,
    pub cc: CcKind,
}

/// The result of a simulated transfer. `Completed` is the only non-buggy outcome for a survivable
/// link; the others are findings (and the `seed` that produced them replays exactly).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// Every byte arrived, in order, intact — after `steps` events and `sim_time_us` of sim time.
    Completed { steps: u64, sim_time_us: u64 },
    /// Bytes arrived but the stream is wrong — a data-integrity bug (the stack delivered corrupt or
    /// reordered data to the application).
    IntegrityViolation { received: usize },
    /// The simulation quiesced (no timers armed, nothing in flight) with data still owed — a wedge.
    Stuck { steps: u64, received: usize },
    /// The step/time budget was exhausted before completion — a livelock, or a pathological link.
    Timeout { steps: u64, received: usize },
}

impl Outcome {
    pub fn is_completed(&self) -> bool {
        matches!(self, Outcome::Completed { .. })
    }
}

const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const MAX_STEPS: u64 = 2_000_000;
const MAX_SIM_US: u64 = 600_000_000; // 600 s of simulated time

/// The deterministic payload of `n` bytes a scenario transfers (a function of `n` only, so the
/// integrity oracle is fixed; the seed varies the *link*, not the data).
fn payload_of(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect()
}

fn secret_from(seed: u64, salt: u64) -> [u8; 16] {
    let a = seed.to_le_bytes();
    let b = seed.wrapping_add(salt).to_le_bytes();
    let mut s = [0u8; 16];
    s[..8].copy_from_slice(&a);
    s[8..].copy_from_slice(&b);
    s
}

/// Run one scenario to completion (or to a finding). **Deterministic**: the same [`Scenario`]
/// always returns the same [`Outcome`], so a failing seed is a complete, replayable repro.
pub fn run(scn: &Scenario) -> Outcome {
    let server_ep = Endpoint::new(SERVER_IP, 8080);

    let mut server = Runtime::new(MockDevice::new(), server_ep, secret_from(scn.seed, 0xA5A5));
    let mut client = Runtime::new(MockDevice::new(), Endpoint::new(CLIENT_IP, 40_000), secret_from(scn.seed, 0x5A5A));
    server.set_congestion_control(scn.cc);
    client.set_congestion_control(scn.cc);

    let payload: Rc<Vec<u8>> = Rc::new(payload_of(scn.bytes));
    let received: Rc<RefCell<Vec<u8>>> = Rc::new(RefCell::new(Vec::with_capacity(scn.bytes)));

    // Server: accept one connection and drain it into `received`. Errors (e.g. a peer RST) just end
    // the read loop — a correct stack must never *panic*, which is itself one of the invariants.
    let listener = server.listener();
    let rv = received.clone();
    server.spawn(async move {
        let stream = listener.accept().await;
        let mut buf = [0u8; 16 * 1024];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => rv.borrow_mut().extend_from_slice(&buf[..n]),
            }
        }
    });

    // Client: dial the server and stream the payload. A connect failure (extreme loss exhausting the
    // SYN retries) just ends the task — the scenario then never completes and surfaces as a Timeout,
    // which the caller chooses survivable link parameters to avoid.
    let connector = client.connector();
    let to_send = payload.clone();
    client.spawn(async move {
        let stream = match connector.connect(server_ep).await {
            Ok(s) => s,
            Err(_) => return,
        };
        let _ = stream.write_all(&to_send).await;
        stream.close();
    });

    let mut link = Link::new(scn.seed, scn.link);
    let mut now = Instant::from_micros(0);
    let mut steps: u64 = 0;

    loop {
        // 1. Deliver everything the link has made due, then let both stacks process (timers,
        //    ingress, tasks) and emit their egress at this instant.
        link.deliver_due(now, &mut client, &mut server);
        client.turn(now).expect("mock device never errors");
        server.turn(now).expect("mock device never errors");

        // 2. Put the egress on the wire, subject to the fault model.
        for f in client.device_mut().take_outbound() {
            link.enqueue(now, Side::ToServer, f);
        }
        for f in server.device_mut().take_outbound() {
            link.enqueue(now, Side::ToClient, f);
        }

        // 3. Done the instant the whole payload has arrived — check integrity then.
        let got = received.borrow().len();
        if got >= scn.bytes {
            return if *received.borrow() == *payload {
                Outcome::Completed { steps, sim_time_us: now.micros() }
            } else {
                Outcome::IntegrityViolation { received: got }
            };
        }

        // 4. Budget guard — a livelock or pathological link, not a hang.
        steps += 1;
        if steps > MAX_STEPS || now.micros() > MAX_SIM_US {
            return Outcome::Timeout { steps, received: got };
        }

        // 5. Advance logical time to the next event: the earliest of either stack's next timer and
        //    the link's next delivery. None of those means the system has quiesced with data still
        //    owed — a wedge (e.g. data outstanding but no retransmit timer armed).
        let next = [client.poll_at(), server.poll_at(), link.next_deliver_at()]
            .into_iter()
            .flatten()
            .min();
        match next {
            Some(t) if t > now => now = t,
            // Defensive: a same-instant event would spin; nudge time forward so the budget still
            // bounds the run. (Timers fire on `turn`, link delays are ≥ 1 µs, so this is unreached.)
            Some(_) => now = now.plus_micros(1),
            None => return Outcome::Stuck { steps, received: got },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The headline DST property: across a wide spread of seeds and a hostile link (loss +
    /// duplication + reordering), the stack delivers **every byte intact and terminates, every
    /// time**. This is the test that exercises the reliability machinery — retransmission, SACK
    /// recovery, out-of-order reassembly, and the ack-clocked go-back-N drain — under adversarial
    /// conditions no hand-written test would think to construct.
    #[test]
    #[cfg_attr(miri, ignore)] // hundreds of full transfers through two stacks — far too slow for Miri
    fn dst_integrity_holds_across_many_seeds() {
        for cc in [CcKind::Reno, CcKind::Cubic, CcKind::Bbr] {
            for loss in [1u32, 5, 10] {
                for seed in 0..120u64 {
                    let scn = Scenario { seed, link: LinkConfig::lossy(loss), bytes: 40_000, cc };
                    let outcome = run(&scn);
                    assert!(
                        outcome.is_completed(),
                        "DST finding — replay with this exact scenario: {scn:?} -> {outcome:?}"
                    );
                }
            }
        }
    }

    /// Determinism / replay: the same seed reproduces the same outcome bit-for-bit. This is the
    /// property that makes a failing seed a complete bug report.
    #[test]
    #[cfg_attr(miri, ignore)] // three full 24 KB transfers — too slow for Miri (perfect_link covers it)
    fn dst_is_deterministic_replay() {
        let scn = Scenario { seed: 0xDEADBEEF, link: LinkConfig::lossy(8), bytes: 24_000, cc: CcKind::Cubic };
        let a = run(&scn);
        let b = run(&scn);
        assert!(a.is_completed(), "{a:?}");
        assert_eq!(a, b, "the same seed must replay to an identical outcome");
        // A different seed exercises a different fault sequence (so the suite isn't testing one path).
        let other = run(&Scenario { seed: 0xDEADBEEE, ..scn });
        assert!(other.is_completed(), "{other:?}");
    }

    /// The harness has teeth on *corruption* too: with a bit-corrupting link, the TCP checksum must
    /// reject every mangled segment, so the application still receives the exact payload (corruption
    /// degrades to loss, never to a silent integrity violation). A regression that trusted the wire
    /// would surface here immediately.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn dst_corruption_is_caught_by_the_checksum() {
        let link = LinkConfig { corrupt_ppm: 80_000, ..LinkConfig::lossy(2) };
        for seed in 0..40u64 {
            let scn = Scenario { seed, link, bytes: 20_000, cc: CcKind::Reno };
            let outcome = run(&scn);
            assert!(
                outcome.is_completed(),
                "corruption must be caught by the checksum, not delivered: {scn:?} -> {outcome:?}"
            );
        }
    }

    /// A perfect link still works (sanity: the scheduler/link don't themselves break a clean path),
    /// and a small transfer completes quickly — light enough to run under Miri for memory-safety.
    #[test]
    fn dst_perfect_link_completes() {
        let scn = Scenario { seed: 1, link: LinkConfig::PERFECT, bytes: 4_000, cc: CcKind::Reno };
        assert!(run(&scn).is_completed());
    }

    /// Heavy loss must still *terminate with integrity* — no wedge, no timeout. This is precisely
    /// the regime the ack-clocked go-back-N drain exists for; before that fix a Swiss-cheese window
    /// could collapse into one-segment-per-RTO here.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn dst_heavy_loss_still_terminates() {
        for seed in 0..30u64 {
            let scn = Scenario { seed, link: LinkConfig::lossy(20), bytes: 16_000, cc: CcKind::Bbr };
            let outcome = run(&scn);
            assert!(outcome.is_completed(), "heavy loss must not wedge: {scn:?} -> {outcome:?}");
        }
    }
}
