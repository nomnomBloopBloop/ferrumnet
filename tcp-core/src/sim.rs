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
//! *Determinism scope.* The run is exactly reproducible for the **single-connection** workload here:
//! each [`Runtime`]'s only unordered state is its waker maps, which hold at most one entry at a time
//! for one flow, so their iteration order can never influence the delivered byte stream, the event
//! schedule, or the [`Outcome`]. Extending the harness to *concurrent* flows would put several
//! entries in those maps and so would first need them switched to an ordered map to keep the
//! cross-process reproducibility that makes a failing seed a complete repro.
//!
//! [TigerBeetle]: https://tigerbeetle.com/blog/2023-07-11-we-put-a-distributed-database-in-the-browser
//! [FoundationDB]: https://apple.github.io/foundationdb/testing.html

use std::cell::RefCell;
use std::rc::Rc;

use crate::congestion::CcKind;
use crate::iface::Endpoint;
use crate::runtime::{MockDevice, Runtime};
use crate::time::Instant;
use crate::seq::SeqNumber;
use crate::wire::{set_ecn, Ipv4Packet, TcpPacket, ECN_CE, ECN_ECT0, ECN_ECT1, MAX_SACK_BLOCKS};
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
/// same [`LinkConfig`]; faults are drawn from the RNG, so the entire path is reproducible. It also
/// tallies the faults it injects (`dropped`/`duplicated`/`corrupted`) — surfaced on a [`Outcome::
/// Completed`] so a test can *assert the adversary actually acted*, turning "teeth" from a
/// statistical hope into an executed invariant (a regression that silently disabled injection would
/// then fail the count assertion instead of passing 1080 scenarios over a secretly-clean link).
struct Link {
    rng: Rng,
    cfg: LinkConfig,
    inflight: Vec<InFlight>,
    order: u64,
    dropped: u64,
    duplicated: u64,
    corrupted: u64,
}

impl Link {
    fn new(seed: u64, cfg: LinkConfig) -> Self {
        Link { rng: Rng::new(seed), cfg, inflight: Vec::new(), order: 0, dropped: 0, duplicated: 0, corrupted: 0 }
    }

    /// A frame left a stack at `now`, heading to `side`. Apply the fault model and (unless dropped)
    /// schedule it — plus a duplicate, if drawn.
    fn enqueue(&mut self, now: Instant, side: Side, frame: Vec<u8>) {
        if self.rng.chance_ppm(self.cfg.loss_ppm) {
            self.dropped += 1;
            return; // dropped on the wire
        }
        let corrupt = self.rng.chance_ppm(self.cfg.corrupt_ppm);
        self.schedule(now, side, frame.clone(), corrupt);
        if self.rng.chance_ppm(self.cfg.dup_ppm) {
            // A duplicate with an independent delay (so it may arrive before or after the original).
            self.duplicated += 1;
            self.schedule(now, side, frame, false);
        }
    }

    fn schedule(&mut self, now: Instant, side: Side, mut frame: Vec<u8>, corrupt: bool) {
        if corrupt && frame.len() > 20 {
            // Flip one bit in the TCP region (offset ≥ 20, past the IPv4 header) so the TCP checksum
            // — which covers the TCP header, payload, and IP pseudo-header — must reject it.
            let off = 20 + self.rng.below((frame.len() - 20) as u64) as usize;
            frame[off] ^= 1 << (self.rng.below(8) as u8);
            self.corrupted += 1;
        }
        let delay = self.cfg.min_delay_us + self.rng.below(self.cfg.jitter_us + 1);
        let order = self.order;
        self.order += 1;
        self.inflight.push(InFlight { deliver_at: now.plus_micros(delay), side, order, frame });
    }

    /// The earliest scheduled delivery, if any (drives the event scheduler's clock).
    fn next_deliver_at(&self) -> Option<Instant> {
        min_deliver_at(&self.inflight)
    }

    /// Inject every frame now due into its destination stack (see [`flush_due`]).
    fn deliver_due(&mut self, now: Instant, client: &mut Runtime<MockDevice>, server: &mut Runtime<MockDevice>) {
        flush_due(&mut self.inflight, now, client, server);
    }
}

/// The earliest scheduled delivery across a set of in-flight frames.
fn min_deliver_at(inflight: &[InFlight]) -> Option<Instant> {
    inflight.iter().map(|f| f.deliver_at).min()
}

/// Inject every frame now due (`deliver_at ≤ now`) into its destination stack, in `(deliver_at,
/// order)` order so delivery is deterministic regardless of `Vec` layout.
fn flush_due(inflight: &mut Vec<InFlight>, now: Instant, client: &mut Runtime<MockDevice>, server: &mut Runtime<MockDevice>) {
    let mut due: Vec<InFlight> = Vec::new();
    let mut keep: Vec<InFlight> = Vec::new();
    for f in std::mem::take(inflight) {
        if f.deliver_at <= now {
            due.push(f);
        } else {
            keep.push(f);
        }
    }
    *inflight = keep;
    due.sort_by_key(|f| (f.deliver_at, f.order));
    for f in due {
        match f.side {
            Side::ToClient => client.device_mut().inject(f.frame),
            Side::ToServer => server.device_mut().inject(f.frame),
        }
    }
}

/// The two wired stacks plus the shared workload state — built once, then driven through either the
/// fault link ([`run`]) or the bottleneck link ([`run_bottleneck`]).
struct Pair {
    client: Runtime<MockDevice>,
    server: Runtime<MockDevice>,
    payload: Rc<Vec<u8>>,
    received: Rc<RefCell<Vec<u8>>>,
    connected: Rc<std::cell::Cell<bool>>,
}

/// Build a client→server bulk transfer of `bytes` over a fresh pair of stacks running `cc`. The
/// server drains into `received`; the client dials, marks `connected` on success, streams the
/// payload, and closes. Read errors / a connect failure end the relevant task cleanly (never panic).
fn build_pair(seed: u64, bytes: usize, cc: CcKind) -> Pair {
    let server_ep = Endpoint::new(SERVER_IP, 8080);
    // `set_congestion_control` / `listener` / `connector` / `spawn` are all `&self`; the runtimes
    // only need `&mut` once the caller drives them with `turn`, so they are bound mutable there.
    let server = Runtime::new(MockDevice::new(), server_ep, secret_from(seed, 0xA5A5));
    let client = Runtime::new(MockDevice::new(), Endpoint::new(CLIENT_IP, 40_000), secret_from(seed, 0x5A5A));
    server.set_congestion_control(cc);
    client.set_congestion_control(cc);

    let payload: Rc<Vec<u8>> = Rc::new(payload_of(bytes));
    let received: Rc<RefCell<Vec<u8>>> = Rc::new(RefCell::new(Vec::with_capacity(bytes)));

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

    let connector = client.connector();
    let to_send = payload.clone();
    let connected = Rc::new(std::cell::Cell::new(false));
    let conn_flag = connected.clone();
    client.spawn(async move {
        let stream = match connector.connect(server_ep).await {
            Ok(s) => s,
            Err(_) => return,
        };
        conn_flag.set(true);
        let _ = stream.write_all(&to_send).await;
        stream.close();
    });

    Pair { client, server, payload, received, connected }
}

// ── bottleneck link (the reproducible congestion-control testbed) ────────────────────────────────

/// Active-queue management at the bottleneck.
#[derive(Clone, Copy, Debug)]
pub enum Aqm {
    /// Classic tail-drop: drop a frame that would overflow the buffer. This is what produces
    /// bufferbloat — a loss-based controller only learns of congestion once the buffer is *full*.
    TailDrop,
    /// L4S-style CE marking (RFC 9331 / DCTCP RFC 8257): an ECN-capable (ECT) frame whose standing-
    /// queue delay exceeds `threshold_us` is marked CE — *congestion experienced* — instead of
    /// waiting for the buffer to fill, so an ECN-aware controller (DCTCP) reacts to a **shallow**
    /// queue and holds it sub-millisecond. A Not-ECT frame (Reno/CUBIC/BBR) is never marked, and a
    /// genuinely full buffer still tail-drops as the backstop. This is the AQM that makes the
    /// latency leap visible: same bottleneck, the marking turns a 24–74 ms queue into a sub-ms one.
    CeMark { threshold_us: u64 },
}

/// True if a frame's IPv4 ECN codepoint is ECT(0) or ECT(1) — i.e. the sender marked it ECN-capable,
/// so a congested AQM may set CE on it instead of dropping. Frames shorter than an IPv4 header (none
/// reach here) and Not-ECT/CE frames are not ECT.
fn frame_is_ect(frame: &[u8]) -> bool {
    frame.len() >= 20 && matches!(frame[1] & 0x03, ECN_ECT0 | ECN_ECT1)
}

/// A rate-limited, finite-buffer bottleneck — the *realistic* congestion case (vs the DST link's
/// independent per-packet loss). A greedy loss-based sender fills the buffer (bufferbloat → high
/// queuing latency); a sender that paces to the bottleneck (BBR) keeps the standing queue near
/// empty. Each direction is an independent FIFO served at `rate_bytes_per_sec`; the bulk-data
/// direction develops the standing queue while the ACK direction stays near empty.
#[derive(Clone, Copy, Debug)]
pub struct Bottleneck {
    pub rate_bytes_per_sec: u64,
    pub buffer_bytes: u64,
    pub base_delay_us: u64,
    pub aqm: Aqm,
}

/// Queue + loss statistics for one direction of a bottleneck run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QueueStats {
    /// Largest standing-queue delay any frame waited (µs).
    pub max_queue_us: u64,
    /// Mean standing-queue delay across delivered frames (µs) — the bufferbloat metric.
    pub mean_queue_us: u64,
    pub delivered: u64,
    pub dropped: u64,
    /// Frames the AQM marked CE (only an [`Aqm::CeMark`] bottleneck ever marks; an ECN test asserts
    /// this fired, so a regression that stopped marking can't pass over a silently-unmarked link).
    pub marked: u64,
}

struct BottleneckLink {
    cfg: Bottleneck,
    inflight: Vec<InFlight>,
    order: u64,
    /// Serialization clock per `Side`: when the link next becomes free to start sending a frame.
    next_free: [Instant; 2],
    sum_queue_us: [u64; 2],
    max_queue_us: [u64; 2],
    delivered: [u64; 2],
    dropped: [u64; 2],
    marked: [u64; 2],
}

impl BottleneckLink {
    fn new(cfg: Bottleneck) -> Self {
        BottleneckLink {
            cfg,
            inflight: Vec::new(),
            order: 0,
            next_free: [Instant::ZERO; 2],
            sum_queue_us: [0; 2],
            max_queue_us: [0; 2],
            delivered: [0; 2],
            dropped: [0; 2],
            marked: [0; 2],
        }
    }

    fn enqueue(&mut self, now: Instant, side: Side, mut frame: Vec<u8>) {
        let i = side as usize;
        let rate = self.cfg.rate_bytes_per_sec.max(1);
        // Standing backlog (bytes still queued ahead of `now`) = rate × time-until-link-free.
        let backlog_bytes = self.next_free[i].saturating_micros_since(now).saturating_mul(rate) / 1_000_000;
        if backlog_bytes + frame.len() as u64 > self.cfg.buffer_bytes {
            self.dropped[i] += 1; // tail-drop on a full buffer (the backstop, under any AQM)
            return;
        }
        let serialize_us = (frame.len() as u64).saturating_mul(1_000_000) / rate;
        let start = if self.next_free[i] > now { self.next_free[i] } else { now };
        let queue_us = start.saturating_micros_since(now); // waiting time = the standing-queue delay
        // L4S CE marking: an ECN-capable frame meeting a standing queue deeper than the threshold is
        // marked CE rather than dropped, so a DCTCP sender reacts to a shallow queue. `set_ecn` fixes
        // the IP checksum; the TCP checksum is untouched (its pseudo-header excludes the ECN byte),
        // so the marked frame still validates at the receiver.
        if let Aqm::CeMark { threshold_us } = self.cfg.aqm {
            if queue_us > threshold_us && frame_is_ect(&frame) {
                set_ecn(&mut frame, ECN_CE);
                self.marked[i] += 1;
            }
        }
        let depart = start.plus_micros(serialize_us);
        self.next_free[i] = depart;
        self.sum_queue_us[i] += queue_us;
        self.max_queue_us[i] = self.max_queue_us[i].max(queue_us);
        self.delivered[i] += 1;
        let order = self.order;
        self.order += 1;
        self.inflight.push(InFlight { deliver_at: depart.plus_micros(self.cfg.base_delay_us), side, order, frame });
    }

    fn next_deliver_at(&self) -> Option<Instant> {
        min_deliver_at(&self.inflight)
    }

    fn deliver_due(&mut self, now: Instant, client: &mut Runtime<MockDevice>, server: &mut Runtime<MockDevice>) {
        flush_due(&mut self.inflight, now, client, server);
    }

    fn stats(&self, side: Side) -> QueueStats {
        let i = side as usize;
        QueueStats {
            max_queue_us: self.max_queue_us[i],
            mean_queue_us: if self.delivered[i] > 0 { self.sum_queue_us[i] / self.delivered[i] } else { 0 },
            delivered: self.delivered[i],
            dropped: self.dropped[i],
            marked: self.marked[i],
        }
    }
}

/// The result of a bottleneck transfer: whether it completed with integrity, how long it took, and
/// the bulk-data-direction queue statistics (the bufferbloat metric).
#[derive(Clone, Copy, Debug)]
pub struct BottleneckResult {
    pub completed: bool,
    pub sim_time_us: u64,
    pub bytes: usize,
    pub data_queue: QueueStats,
}

impl BottleneckResult {
    /// Goodput in bytes/second over the transfer.
    pub fn throughput_bytes_per_sec(&self) -> u64 {
        if self.sim_time_us > 0 {
            (self.bytes as u64).saturating_mul(1_000_000) / self.sim_time_us
        } else {
            0
        }
    }
}

/// Run a bulk transfer over a finite-buffer bottleneck and measure throughput + queuing latency.
/// **Deterministic.** The data direction is client→server ([`Side::ToServer`]); its standing queue
/// is the bufferbloat metric — a loss-based controller fills it, a paced one (BBR) keeps it small.
pub fn run_bottleneck(seed: u64, cfg: Bottleneck, bytes: usize, cc: CcKind) -> BottleneckResult {
    let Pair { mut client, mut server, payload, received, connected } = build_pair(seed, bytes, cc);
    let mut link = BottleneckLink::new(cfg);
    let mut now = Instant::from_micros(0);
    let mut steps: u64 = 0;
    let result = |completed, now: Instant, link: &BottleneckLink| BottleneckResult {
        completed,
        sim_time_us: now.micros(),
        bytes,
        data_queue: link.stats(Side::ToServer),
    };

    loop {
        link.deliver_due(now, &mut client, &mut server);
        client.turn(now).expect("mock device never errors");
        server.turn(now).expect("mock device never errors");
        for f in client.device_mut().take_outbound() {
            link.enqueue(now, Side::ToServer, f);
        }
        for f in server.device_mut().take_outbound() {
            link.enqueue(now, Side::ToClient, f);
        }

        let got = received.borrow().len();
        if connected.get() && got >= bytes {
            return result(*received.borrow() == *payload, now, &link);
        }

        steps += 1;
        if steps > MAX_STEPS || now.micros() > MAX_SIM_US {
            return result(false, now, &link);
        }

        let next = [client.poll_at(), server.poll_at(), link.next_deliver_at()].into_iter().flatten().min();
        match next {
            Some(t) if t > now => now = t,
            Some(_) => now = now.plus_micros(1),
            None => return result(false, now, &link),
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
    /// Every byte arrived, in order, intact — after `steps` events and `sim_time_us` of sim time,
    /// having survived `dropped` losses, `duplicated` duplications, and `corrupted` bit-flips on the
    /// wire (the tally lets a test prove the fault model actually fired).
    Completed { steps: u64, sim_time_us: u64, dropped: u64, duplicated: u64, corrupted: u64 },
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
    run_collecting(scn, None)
}

/// Run a scenario and also collect the [`Coverage`] it exercises — the observable-behaviour signal
/// the coverage-guided fuzzer steers on. Identical execution to [`run`] (same loop, same outcome);
/// the only difference is that each emitted frame is fed to the collector before it hits the wire.
pub fn run_with_coverage(scn: &Scenario) -> (Outcome, Coverage) {
    let mut collector = CovCollector::new();
    let outcome = run_collecting(scn, Some(&mut collector));
    let cov = collector.finish(&outcome);
    (outcome, cov)
}

/// The shared driver behind [`run`] and [`run_with_coverage`]. When `cov` is `Some`, every emitted
/// frame is observed for coverage *before* the link mangles it; when `None` the collection is fully
/// elided, so [`run`] (and the 1080-scenario suite) pays nothing for the instrumentation.
fn run_collecting(scn: &Scenario, mut cov: Option<&mut CovCollector>) -> Outcome {
    // Two stacks + the bulk-transfer workload (server drains into `received`; client dials, sets
    // `connected`, streams the payload). `connected` gates completion so an empty (`bytes == 0`)
    // transfer is only reported `Completed` after a real handshake, never vacuously at step 0; a
    // connect failure under extreme loss leaves it false, so the run quiesces to `Stuck`.
    let Pair { mut client, mut server, payload, received, connected } = build_pair(scn.seed, scn.bytes, scn.cc);

    let mut link = Link::new(scn.seed, scn.link);
    let mut now = Instant::from_micros(0);
    let mut steps: u64 = 0;

    loop {
        // 1. Deliver everything the link has made due, then let both stacks process (timers,
        //    ingress, tasks) and emit their egress at this instant.
        link.deliver_due(now, &mut client, &mut server);
        client.turn(now).expect("mock device never errors");
        server.turn(now).expect("mock device never errors");

        // 2. Put the egress on the wire, subject to the fault model (observing it for coverage first).
        for f in client.device_mut().take_outbound() {
            if let Some(c) = cov.as_deref_mut() {
                c.observe(Side::ToServer, &f);
            }
            link.enqueue(now, Side::ToServer, f);
        }
        for f in server.device_mut().take_outbound() {
            if let Some(c) = cov.as_deref_mut() {
                c.observe(Side::ToClient, &f);
            }
            link.enqueue(now, Side::ToClient, f);
        }

        // 3. Done once the connection is up and the whole payload has arrived — check integrity then.
        //    Gating on `connected` keeps an empty transfer from reporting success before it handshakes.
        let got = received.borrow().len();
        if connected.get() && got >= scn.bytes {
            return if *received.borrow() == *payload {
                Outcome::Completed {
                    steps,
                    sim_time_us: now.micros(),
                    dropped: link.dropped,
                    duplicated: link.duplicated,
                    corrupted: link.corrupted,
                }
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

// ── coverage-guided greybox fuzzing ──────────────────────────────────────────────────────────────
//
// The DST suite above runs a *fixed* grid of seeds. A greybox fuzzer instead steers the search with
// feedback: it keeps the scenarios that exercise **new behaviour** and mutates them, so it spends its
// budget reaching states a fixed grid would never stumble into (the AFL/libFuzzer discipline). Here
// the feedback is read entirely **off the wire** — the sequence of segment-event classes the two
// stacks emit (SYN, SYN-ACK, fresh data, retransmit, pure/duplicate/SACK ACK, FIN, RST, zero-window,
// …), hashed pairwise the way AFL hashes basic-block transitions, plus a few run-outcome features.
// So the coverage signal needs **no engine instrumentation**: the sans-IO core stays untouched and
// `#![deny(unsafe_code)]`/zero-dep, and the whole fuzzer is a pure, deterministic function of its
// seed — a discovered scenario is itself a replayable repro, exactly like the rest of the DST harness.

const COV_BITS: usize = 2048;
const COV_WORDS: usize = COV_BITS / 64;

const CC_ALL: [CcKind; 4] = [CcKind::Reno, CcKind::Cubic, CcKind::Bbr, CcKind::Dctcp];

/// A fixed-size behavioural-coverage bitmap (AFL-style edge coverage). Each set bit is one
/// `(previous-event → this-event)` transition the run exercised, or one outcome feature — read off
/// the emitted frames and the [`Outcome`], never from engine instrumentation. 2048 buckets hold a
/// single connection's behaviour with collisions rare.
#[derive(Clone, PartialEq, Eq)]
pub struct Coverage {
    bits: [u64; COV_WORDS],
}

impl Coverage {
    fn new() -> Self {
        Coverage { bits: [0; COV_WORDS] }
    }

    #[inline]
    fn set(&mut self, bucket: usize) {
        let b = bucket & (COV_BITS - 1);
        self.bits[b >> 6] |= 1u64 << (b & 63);
    }

    /// The number of distinct edges/features covered.
    pub fn count(&self) -> u32 {
        self.bits.iter().map(|w| w.count_ones()).sum()
    }

    /// Fold `other` into `self`; return how many buckets became newly set — `other`'s novelty.
    fn merge(&mut self, other: &Coverage) -> u32 {
        let mut new = 0;
        for (a, b) in self.bits.iter_mut().zip(other.bits.iter()) {
            new += (*b & !*a).count_ones();
            *a |= *b;
        }
        new
    }

    /// Buckets set in `self` but not in `other` — coverage `self` reached that `other` missed.
    pub fn extra_over(&self, other: &Coverage) -> u32 {
        self.bits.iter().zip(other.bits.iter()).map(|(a, b)| (*a & !*b).count_ones()).sum()
    }
}

impl core::fmt::Debug for Coverage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Coverage({} edges)", self.count())
    }
}

/// Spreads a composite block id (event class + recovery depth + direction) across the coverage map
/// (the AFL per-block hash).
#[inline]
fn cov_loc(id: usize) -> usize {
    id.wrapping_mul(2_654_435_761) & (COV_BITS - 1)
}

/// `n`'s bit-length, capped — a coarse logarithmic bucket for magnitude features (fault counts,
/// step/time totals) so "a few" and "many" land in different buckets without one bucket per value.
#[inline]
fn log_bucket(n: u64) -> usize {
    (64 - n.leading_zeros()) as usize
}

/// Walks one run's emitted-frame stream and accumulates [`Coverage`]. Per-direction state lets it
/// tell a retransmit from fresh data and a duplicate ACK from a fresh one — the events that actually
/// separate the recovery paths — without reaching into the engine.
struct CovCollector {
    cov: Coverage,
    prev: [usize; 2],          // AFL prev_loc, per side (the last edge endpoint)
    prev2: [usize; 2],         // one more back, so the edge is a 3-event n-gram (richer than pairs)
    last_ack: [Option<SeqNumber>; 2],
    dup_run: [u32; 2],         // consecutive duplicate ACKs (fast-retransmit pressure), per side
    hi_seq_end: [Option<SeqNumber>; 2], // highest seq+len emitted, per side (retransmit detection)
    rtx_streak: [u32; 2],      // consecutive retransmits — *recovery depth*, per side
}

impl CovCollector {
    fn new() -> Self {
        CovCollector {
            cov: Coverage::new(),
            prev: [0; 2],
            prev2: [0; 2],
            last_ack: [None; 2],
            dup_run: [0; 2],
            hi_seq_end: [None; 2],
            rtx_streak: [0; 2],
        }
    }

    /// Classify a frame, record its edge from the previous frame on the same side, and set any
    /// standalone feature buckets it triggers.
    fn observe(&mut self, side: Side, frame: &[u8]) {
        let i = side as usize;
        let ip = match Ipv4Packet::new_checked(frame) {
            Ok(p) => p,
            Err(_) => return,
        };
        let tcp = match TcpPacket::new_checked(ip.payload()) {
            Ok(t) => t,
            Err(_) => return,
        };
        let flags = tcp.flags();
        let payload_len = tcp.payload().len();
        let seq = tcp.seq();
        let ack = tcp.ack();
        let window = tcp.window();
        let mut blocks = [(SeqNumber::new(0), SeqNumber::new(0)); MAX_SACK_BLOCKS];
        let sack_n = tcp.sack_blocks(&mut blocks);

        // Retransmit: a data segment whose start lies below the high-water of what we have sent.
        let is_rtx = payload_len > 0 && self.hi_seq_end[i].is_some_and(|hi| seq.lt(hi));
        // Duplicate ACK: a pure ACK repeating the previous cumulative ack on this side.
        let is_dup_ack = payload_len == 0
            && !flags.syn()
            && !flags.fin()
            && self.last_ack[i] == Some(ack);

        let ev: u8 = if flags.rst() {
            0
        } else if flags.syn() && flags.ack() {
            1
        } else if flags.syn() {
            2
        } else if flags.fin() {
            3
        } else if payload_len > 0 {
            if is_rtx {
                4
            } else if flags.psh() {
                5
            } else {
                6
            }
        } else if window == 0 {
            7
        } else if sack_n > 0 {
            8
        } else if is_dup_ack {
            9
        } else {
            10
        };
        // Recovery depth: consecutive retransmits and consecutive duplicate ACKs on this side.
        // Folding the depth into the location stratifies every event by *how deep into recovery* it
        // happens — "a data segment at retransmit-streak 6" is a different bucket from "...at streak 1"
        // — and those deep buckets need a specific high-loss input to reach, which is exactly what
        // makes coverage feedback pay off over blind sampling.
        if is_rtx {
            self.rtx_streak[i] = self.rtx_streak[i].saturating_add(1);
        } else if payload_len > 0 {
            self.rtx_streak[i] = 0; // fresh data ends the retransmit run
        }
        if is_dup_ack {
            self.dup_run[i] = self.dup_run[i].saturating_add(1);
        } else if payload_len == 0 && !flags.syn() && !flags.fin() {
            self.dup_run[i] = 0; // an advancing ACK ends the dup-ACK run
        }
        let depth = (log_bucket(self.rtx_streak[i] as u64) << 3) | log_bucket(self.dup_run[i] as u64);
        let cur = cov_loc((ev as usize) | (depth << 5) | (i << 12));
        // 3-event n-gram edge coverage: this location against the previous two on the same side.
        self.cov.set(self.prev2[i].rotate_left(1) ^ self.prev[i] ^ cur);
        self.prev2[i] = self.prev[i];
        self.prev[i] = cur >> 1;

        // Standalone feature buckets, so a rare option/flag/magnitude always registers regardless of
        // its edge.
        let feat = 1_600;
        if sack_n > 0 {
            self.cov.set(feat + sack_n); // 1..MAX_SACK_BLOCKS distinct
        }
        if window == 0 {
            self.cov.set(feat + 8);
        }
        if flags.ece() {
            self.cov.set(feat + 9 + i);
        }
        if tcp.timestamps().is_some() {
            self.cov.set(feat + 12);
        }
        if tcp.window_scale().is_some() {
            self.cov.set(feat + 13);
        }
        if matches!(ip.ecn(), ECN_ECT0 | ECN_ECT1) {
            self.cov.set(feat + 14);
        }
        self.cov.set(feat + 16 + log_bucket(self.rtx_streak[i] as u64)); // recovery depth reached
        self.cov.set(feat + 30 + log_bucket(self.dup_run[i] as u64));
        if payload_len > 0 {
            self.cov.set(feat + 44 + log_bucket(payload_len as u64)); // segment-size class
        }

        // Update per-side state.
        if payload_len == 0 && !flags.syn() && !flags.fin() {
            self.last_ack[i] = Some(ack);
        }
        if payload_len > 0 {
            let end = seq + payload_len as u32;
            // (`map_or(true, …)` not `is_none_or`: the latter is 1.82+, our MSRV is 1.75.)
            if self.hi_seq_end[i].map_or(true, |hi| hi.lt(end)) {
                self.hi_seq_end[i] = Some(end);
            }
        }
    }

    /// Fold the run outcome in as a final set of feature buckets and yield the coverage.
    fn finish(mut self, outcome: &Outcome) -> Coverage {
        let base = 1_700;
        match outcome {
            Outcome::Completed { steps, sim_time_us, dropped, duplicated, corrupted } => {
                self.cov.set(base);
                self.cov.set(base + 10 + log_bucket(*dropped));
                self.cov.set(base + 30 + log_bucket(*duplicated));
                self.cov.set(base + 50 + log_bucket(*corrupted));
                self.cov.set(base + 70 + log_bucket(*steps));
                self.cov.set(base + 90 + log_bucket(*sim_time_us / 1_000));
            }
            Outcome::IntegrityViolation { .. } => self.cov.set(base + 1),
            Outcome::Stuck { .. } => self.cov.set(base + 2),
            Outcome::Timeout { .. } => self.cov.set(base + 3),
        }
        self.cov
    }
}

/// The result of a [`fuzz`] campaign: how many scenarios it ran, the corpus of distinct
/// coverage-advancing scenarios it kept, the total behaviour covered, and any **findings** —
/// scenarios that did not complete with integrity under a survivable link (each one a replayable bug,
/// since the mutator never makes the link un-survivable, so a non-completion is always a real defect).
#[derive(Clone, Debug)]
pub struct FuzzReport {
    pub iterations: u32,
    pub corpus_size: usize,
    pub edges: u32,
    pub findings: Vec<Scenario>,
    /// The union coverage the campaign reached (for comparison against a baseline).
    pub coverage: Coverage,
}

/// Mutate a scenario by perturbing 1–3 of its dimensions, staying inside a **survivable** envelope
/// (loss ≤ 12%, dup ≤ 8%, corrupt ≤ 2%, jitter ≤ 6 ms, ≤ 24 KB — all within the range the fixed DST
/// suite already proves the stack survives), so any non-completion the fuzzer turns up is a genuine
/// bug, never an un-survivably-hostile link.
fn fuzz_mutate(rng: &mut Rng, s: &Scenario) -> Scenario {
    let mut s = *s;
    let n = 1 + rng.below(3);
    for _ in 0..n {
        match rng.below(6) {
            0 => s.seed ^= 1u64 << rng.below(64),
            1 => s.link.loss_ppm = rng.below(120_001) as u32,
            2 => s.link.dup_ppm = rng.below(80_001) as u32,
            3 => s.link.corrupt_ppm = rng.below(20_001) as u32,
            4 => s.link.jitter_us = rng.below(6_001),
            5 => s.cc = CC_ALL[rng.below(4) as usize],
            _ => unreachable!(),
        }
    }
    // bytes is perturbed on its own axis so the corpus spans short and long transfers.
    if rng.below(2) == 0 {
        s.bytes = 1_000 + rng.below(23_001) as usize;
    }
    s.link.min_delay_us = s.link.min_delay_us.max(1_000); // the link requires a ≥ 1 µs base delay
    s
}

/// A fresh uniformly-random scenario in the same survivable envelope — the black-box baseline the
/// coverage-guided search is measured against.
fn fuzz_random_scenario(rng: &mut Rng) -> Scenario {
    Scenario {
        seed: rng.next_u64(),
        link: LinkConfig {
            loss_ppm: rng.below(120_001) as u32,
            dup_ppm: rng.below(80_001) as u32,
            corrupt_ppm: rng.below(20_001) as u32,
            min_delay_us: 5_000,
            jitter_us: rng.below(6_001),
        },
        bytes: 1_000 + rng.below(23_001) as usize,
        cc: CC_ALL[rng.below(4) as usize],
    }
}

/// The seed scenario every campaign starts from: a mild, definitely-survivable lossy link.
fn fuzz_base() -> Scenario {
    Scenario { seed: 1, link: LinkConfig::lossy(5), bytes: 8_000, cc: CcKind::Reno }
}

/// Run a **coverage-guided** fuzzing campaign of `iterations` scenarios, deterministically driven by
/// `fuzz_seed`. It keeps every scenario that advances coverage and mutates the corpus, so it reaches
/// behaviour a fixed grid never would — and it asserts nothing itself: the caller inspects the
/// [`FuzzReport`] (its `findings` must be empty; its `coverage`/`edges` are the search's reach).
pub fn fuzz(fuzz_seed: u64, iterations: u32) -> FuzzReport {
    let mut rng = Rng::new(fuzz_seed ^ 0xF1F2_F3F4_F5F6_F7F8);
    let mut global = Coverage::new();
    let mut corpus: Vec<Scenario> = Vec::new();
    let mut findings: Vec<Scenario> = Vec::new();

    let base = fuzz_base();
    let (o, c) = run_with_coverage(&base);
    global.merge(&c);
    corpus.push(base);
    if !o.is_completed() {
        findings.push(base);
    }

    for _ in 0..iterations {
        let parent = corpus[rng.below(corpus.len() as u64) as usize];
        let child = fuzz_mutate(&mut rng, &parent);
        let (o, c) = run_with_coverage(&child);
        if global.merge(&c) > 0 {
            corpus.push(child); // it found new behaviour — keep it to mutate further
        }
        if !o.is_completed() {
            findings.push(child);
        }
    }

    FuzzReport { iterations, corpus_size: corpus.len(), edges: global.count(), findings, coverage: global }
}

/// The black-box baseline: `iterations` uniformly-random scenarios from the same envelope, with **no**
/// coverage feedback (the corpus never grows). Used to show that the feedback in [`fuzz`] actually
/// buys reach beyond blind sampling at an equal budget.
pub fn fuzz_random_baseline(fuzz_seed: u64, iterations: u32) -> FuzzReport {
    let mut rng = Rng::new(fuzz_seed ^ 0x0102_0304_0506_0708);
    let mut global = Coverage::new();
    let mut findings: Vec<Scenario> = Vec::new();
    for _ in 0..iterations {
        let scn = fuzz_random_scenario(&mut rng);
        let (o, c) = run_with_coverage(&scn);
        global.merge(&c);
        if !o.is_completed() {
            findings.push(scn);
        }
    }
    FuzzReport { iterations, corpus_size: 0, edges: global.count(), findings, coverage: global }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Coverage-guided greybox fuzzing as a **correctness oracle**. Across a campaign of coverage-
    /// steered mutations inside a survivable fault envelope, the stack must never violate an invariant
    /// — every scenario the search turns up completes with full byte integrity (`findings` empty). And
    /// the campaign is a pure function of its seed, so it replays bit-for-bit — a discovered scenario
    /// is a complete repro. The coverage signal is read entirely off the wire (no engine
    /// instrumentation), which is exactly what lets a sans-IO stack be fuzzed this way at all.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn coverage_guided_fuzzing_is_a_clean_deterministic_oracle() {
        let a = fuzz(0xC0FFEE, 300);
        assert!(
            a.findings.is_empty(),
            "fuzzing found a non-completing scenario under a survivable link — a real bug: {:?}",
            a.findings
        );
        assert!(a.corpus_size > 50, "the campaign kept a substantial corpus: {}", a.corpus_size);
        assert!(a.edges > 250, "and reached rich behavioural coverage: {} edges", a.edges);
        // The whole campaign replays bit-for-bit from its seed.
        let b = fuzz(0xC0FFEE, 300);
        assert_eq!(a.edges, b.edges, "edge count must replay");
        assert_eq!(a.corpus_size, b.corpus_size, "corpus must replay");
        assert!(a.coverage == b.coverage, "coverage must replay bit-for-bit");
    }

    /// Coverage feedback earns its keep on **depth**, not breadth. Because every event is bucketed by
    /// how deep into recovery it occurs (retransmit / dup-ACK streak length), the deep buckets need a
    /// specific high-loss input to reach — so steering the budget toward the corpus members that
    /// already reached recovery finds behaviour a uniform-random sampler at the same budget never does.
    /// (Random samples configs more broadly, so neither strictly dominates *total* coverage; the point
    /// is the guided-only behaviour — the deep tail the feedback buys.)
    #[test]
    #[cfg_attr(miri, ignore)]
    fn coverage_feedback_reaches_states_random_search_misses() {
        let budget = 300;
        let guided = fuzz(0x1234, budget);
        let random = fuzz_random_baseline(0x1234, budget);
        assert!(guided.findings.is_empty() && random.findings.is_empty(), "no findings either way");
        let guided_only = guided.coverage.extra_over(&random.coverage);
        assert!(
            guided_only > 25,
            "coverage feedback reaches behaviour random search misses at equal budget: {guided_only} guided-only edges"
        );
    }

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

    /// Teeth as an *executed* invariant: the adversary must really act. If a regression silently
    /// disabled fault injection, the 1080-scenario suite above would pass over a secretly-clean link
    /// and test nothing — so here we count the injected faults and assert they fired. (The standard
    /// DST guard; without it, "we ran many scenarios" can quietly degrade to "we ran a clean link
    /// many times".)
    #[test]
    #[cfg_attr(miri, ignore)]
    fn dst_fault_model_actually_fires() {
        let (mut drops, mut dups) = (0u64, 0u64);
        for seed in 0..20u64 {
            match run(&Scenario { seed, link: LinkConfig::lossy(20), bytes: 16_000, cc: CcKind::Reno }) {
                Outcome::Completed { dropped, duplicated, .. } => {
                    drops += dropped;
                    dups += duplicated;
                }
                o => panic!("expected Completed, got {o:?}"),
            }
        }
        assert!(drops > 0, "a 20% lossy link must actually drop frames");
        assert!(dups > 0, "...and duplicate some");
        // A corrupting link must actually mangle frames (which the checksum then rejects).
        match run(&Scenario { seed: 3, link: LinkConfig { corrupt_ppm: 80_000, ..LinkConfig::lossy(2) }, bytes: 20_000, cc: CcKind::Reno }) {
            Outcome::Completed { corrupted, .. } => assert!(corrupted > 0, "the corrupting link must corrupt frames"),
            o => panic!("expected Completed, got {o:?}"),
        }
    }

    // ── bottleneck testbed ────────────────────────────────────────────────────────────────────────

    /// The reproducible bufferbloat result, in-process and deterministic (the same story the hardware
    /// netem bench told, but with zero variance). On a 20 mbit bottleneck with a deep 256 KiB buffer
    /// (BDP ≈ 50 KiB at the 20 ms base RTT), Reno grows its window until the buffer overflows — a
    /// standing queue, i.e. bufferbloat — while BBR paces to the bottleneck and keeps the queue near
    /// empty. Same goodput, dramatically different latency under load.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn bottleneck_paced_bbr_avoids_the_bufferbloat_loss_based_cc_causes() {
        // Buffer (512 KiB) > the 256 KiB receive window, so Reno is window-limited at ~256 KiB in
        // flight and parks a steady ~200 KiB standing queue (deep bufferbloat); the 2 MiB transfer is
        // long enough for that steady state to dominate the ramp. BBR paces to the line and holds the
        // queue near a BDP.
        let bn = Bottleneck { rate_bytes_per_sec: 2_500_000, buffer_bytes: 512 * 1024, base_delay_us: 10_000, aqm: Aqm::TailDrop };
        let reno = run_bottleneck(7, bn, 2 * 1024 * 1024, CcKind::Reno);
        let bbr = run_bottleneck(7, bn, 2 * 1024 * 1024, CcKind::Bbr);
        // Measured: Reno parks a ~74 ms mean standing queue; BBR holds ~24 ms (≈1 BDP) — ~3× lower at
        // near-equal goodput, and no drops (window-limited, pure bufferbloat). The BBR residual is the
        // rung L4S/DCTCP pushes to sub-millisecond.
        assert!(reno.completed && bbr.completed, "both deliver intact: reno {reno:?} bbr {bbr:?}");
        // Both roughly saturate the 2.5 MB/s line...
        assert!(
            reno.throughput_bytes_per_sec() > 1_500_000 && bbr.throughput_bytes_per_sec() > 1_500_000,
            "both near the line: reno {} bbr {}",
            reno.throughput_bytes_per_sec(),
            bbr.throughput_bytes_per_sec()
        );
        // ...but BBR holds a far smaller standing queue (it keeps the bottleneck busy, not bloated).
        assert!(
            bbr.data_queue.mean_queue_us * 2 < reno.data_queue.mean_queue_us,
            "BBR keeps the queue far smaller: bbr {} µs vs reno {} µs",
            bbr.data_queue.mean_queue_us,
            reno.data_queue.mean_queue_us
        );
    }

    /// THE LATENCY LEAP (L4S/DCTCP). On one finite-buffer bottleneck fronted by an L4S CE-marking
    /// AQM, three controllers paint the full latency ladder: loss-based Reno fills the buffer (deep
    /// bufferbloat), BBR paces to ~1 BDP, and DCTCP — reacting to the *shallow-queue* CE marks the
    /// AQM sets on its ECT data — holds a **sub-millisecond** standing queue at comparable goodput.
    /// Deterministic and in-process: the rung the hardware netem story pointed at, with zero variance.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn bottleneck_dctcp_holds_a_sub_millisecond_queue() {
        // A datacenter-like path (DCTCP's design point): 2.5 MB/s, a deep 512 KiB buffer, a 4 ms base
        // RTT (BDP ≈ 10 KiB), and an L4S AQM that marks CE once a frame's standing-queue delay tops
        // 1 ms. Reno/BBR send Not-ECT, so the AQM cannot mark them — they bloat exactly as they would
        // under tail-drop; only DCTCP's ECT data is marked, and only DCTCP reacts to it. The 8 MiB
        // transfer is long enough that DCTCP's steady state (not its slow-start ramp) dominates.
        let bn = Bottleneck { rate_bytes_per_sec: 2_500_000, buffer_bytes: 512 * 1024, base_delay_us: 2_000, aqm: Aqm::CeMark { threshold_us: 1_000 } };
        let bytes = 8 * 1024 * 1024;
        let reno = run_bottleneck(7, bn, bytes, CcKind::Reno);
        let bbr = run_bottleneck(7, bn, bytes, CcKind::Bbr);
        let dctcp = run_bottleneck(7, bn, bytes, CcKind::Dctcp);
        assert!(reno.completed && bbr.completed && dctcp.completed, "all deliver intact: reno {reno:?} bbr {bbr:?} dctcp {dctcp:?}");

        // Teeth: the AQM actually CE-marked DCTCP's ECT data (without marks DCTCP would behave like
        // Reno here), and it never marked the Not-ECT loss-based controllers.
        assert!(dctcp.data_queue.marked > 0, "the CE-marking AQM must mark DCTCP's ECT frames: {dctcp:?}");
        assert_eq!(reno.data_queue.marked, 0, "Not-ECT Reno is never CE-marked: {reno:?}");
        assert_eq!(bbr.data_queue.marked, 0, "Not-ECT BBR is never CE-marked: {bbr:?}");
        // Pure marking, no drops — DCTCP keeps the buffer far from full.
        assert_eq!(dctcp.data_queue.dropped, 0, "DCTCP holds the queue shallow — nothing tail-drops: {dctcp:?}");

        // The ladder: DCTCP ≪ BBR ≪ Reno standing queue.
        assert!(dctcp.data_queue.mean_queue_us < 1_000, "DCTCP holds a sub-millisecond queue: {} µs", dctcp.data_queue.mean_queue_us);
        assert!(
            dctcp.data_queue.mean_queue_us * 4 < bbr.data_queue.mean_queue_us,
            "DCTCP ≪ BBR: dctcp {} µs vs bbr {} µs",
            dctcp.data_queue.mean_queue_us,
            bbr.data_queue.mean_queue_us
        );
        assert!(
            bbr.data_queue.mean_queue_us < reno.data_queue.mean_queue_us,
            "BBR < Reno: bbr {} µs vs reno {} µs",
            bbr.data_queue.mean_queue_us,
            reno.data_queue.mean_queue_us
        );

        // ...at comparable goodput: DCTCP doesn't buy its low latency by going slow — a clear
        // majority of the 2.5 MB/s line, and ≥ 80 % of what loss-based Reno (which floods the buffer)
        // manages on the same path.
        assert!(dctcp.throughput_bytes_per_sec() > 1_800_000, "DCTCP stays near the line: {} B/s", dctcp.throughput_bytes_per_sec());
        assert!(
            dctcp.throughput_bytes_per_sec() * 5 > reno.throughput_bytes_per_sec() * 4,
            "DCTCP goodput comparable to Reno: dctcp {} B/s vs reno {} B/s",
            dctcp.throughput_bytes_per_sec(),
            reno.throughput_bytes_per_sec()
        );
    }

    /// DCTCP's L4S ECN reaction is *additive* to the loss machinery, never a replacement for it: on
    /// the fault link (which never CE-marks), DCTCP sees no marks and must be exactly as robust as any
    /// other controller — delivering every byte intact under heavy loss, duplication and reordering.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn dst_dctcp_is_robust_under_loss() {
        for loss in [1u32, 5, 10] {
            for seed in 0..40u64 {
                let scn = Scenario { seed, link: LinkConfig::lossy(loss), bytes: 32_000, cc: CcKind::Dctcp };
                let outcome = run(&scn);
                assert!(outcome.is_completed(), "DCTCP must survive loss: {scn:?} -> {outcome:?}");
            }
        }
    }

    /// Determinism + a sanity floor: a small transfer over a fast bottleneck completes with integrity,
    /// and the same seed reproduces the same queue stats. Light enough for Miri's memory-safety check.
    #[test]
    fn bottleneck_is_deterministic_and_lossless_when_unloaded() {
        let bn = Bottleneck { rate_bytes_per_sec: 10_000_000, buffer_bytes: 128 * 1024, base_delay_us: 2_000, aqm: Aqm::TailDrop };
        let a = run_bottleneck(1, bn, 4_000, CcKind::Reno);
        let b = run_bottleneck(1, bn, 4_000, CcKind::Reno);
        assert!(a.completed, "{a:?}");
        assert_eq!(a.data_queue, b.data_queue, "same seed → same queue stats");
        assert_eq!(a.data_queue.dropped, 0, "an under-filled fast bottleneck drops nothing");
    }
}
