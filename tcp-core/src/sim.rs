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

// ── dual-queue L4S bottleneck (the coexistence testbed) ──────────────────────────────────────────

/// A **dual-queue** L4S bottleneck — the structure of RFC 9332's dualPI2. One shared link rate is
/// served by a fair (per-class round-robin) scheduler across **two class queues**: an **L4S** queue
/// for ECN-capable (ECT) traffic, kept shallow and CE-marked the instant its sojourn crosses a
/// sub-millisecond threshold, and a **Classic** queue for Not-ECT traffic, given a deep buffer that
/// tail-drops (the only signal a loss-based sender understands). Classification is by the IP ECN
/// field, exactly as L4S specifies (RFC 9331): a scalable sender (Prague) marks its data ECT and
/// lands in the low-latency queue; a classic sender (Reno) is Not-ECT and lands in the deep queue.
///
/// This **isolates** the two: the classic flow can bloat its *own* deep queue without inflating the
/// L4S flow's latency — the headline result a single shared FIFO cannot give (there one greedy classic
/// flow's bloat is everyone's latency). The two flows also **coexist** — both complete, neither is
/// starved. The per-class round-robin scheduler keeps either class from monopolising the link, but it
/// does **not** by itself equalise *throughput*: a scalable L4S flow keeps its queue near-empty, so the
/// L4S class is often idle and the scheduler hands that slack to the classic flow — the exact split
/// therefore depends on the buffer/threshold balance (in the demo the classic flow finishes *faster*).
/// Robust throughput *fairness* across RTT and config is precisely what dualPI2's *coupled* PI-controller
/// marking law (`p_L ≈ √p_C`) adds, and is the documented refinement deferred here; this models the
/// dual-queue structure (two class queues, per-class native marking — shallow-step for L4S, tail-drop
/// for Classic — and a fair scheduler) and demonstrates the **latency isolation + coexistence** half.
#[derive(Clone, Copy, Debug)]
pub struct DualQueue {
    pub rate_bytes_per_sec: u64,
    pub base_delay_us: u64,
    /// CE-mark an L4S frame once its queue sojourn exceeds this (shallow → sub-ms L4S latency).
    pub l4s_threshold_us: u64,
    /// Classic-queue buffer: a frame that would overflow it is tail-dropped — the loss signal a
    /// classic loss-based controller needs to find its operating point.
    pub classic_buffer_bytes: u64,
    /// L4S-queue buffer: a backstop only. A scalable controller keeps this queue near-empty, so it
    /// tail-drops only if marking somehow fails to restrain the flow.
    pub l4s_buffer_bytes: u64,
}

/// Per-flow result of a [`run_dualqueue`] coexistence run.
#[derive(Clone, Copy, Debug)]
pub struct FlowResult {
    pub completed: bool,
    pub bytes: usize,
    pub sim_time_us: u64,
    /// Mean standing-queue delay this flow's data saw at the bottleneck (µs).
    pub mean_queue_us: u64,
    pub max_queue_us: u64,
    pub marked: u64,
    pub dropped: u64,
}

impl FlowResult {
    pub fn throughput_bytes_per_sec(&self) -> u64 {
        if self.sim_time_us > 0 {
            (self.bytes as u64).saturating_mul(1_000_000) / self.sim_time_us
        } else {
            0
        }
    }
}

/// A frame waiting in a class queue for the link to serve it.
struct DqQueued {
    arrival: Instant,
    flow: usize,
    len: u64,
    frame: Vec<u8>,
}

/// A frame past the bottleneck, propagating to its destination stack.
struct DqFlight {
    deliver_at: Instant,
    flow: usize,
    side: Side,
    order: u64,
    frame: Vec<u8>,
}

/// The dual-queue link. Stats arrays are indexed by **flow** (`[0]` = flow 0 / the scalable L4S sender,
/// `[1]` = flow 1 / the classic sender), so each flow's queue / mark / drop stats are attributed
/// exactly to that flow — even though a sender's occasional Not-ECT control frame (SYN / handshake ACK /
/// FIN) is classified into the *other* class's queue (per-packet ECN classification is the correct L4S
/// behaviour; only the *bookkeeping* is by flow). The L4S/Classic *queues* themselves stay ECN-classified.
struct DualQueueLink {
    cfg: DualQueue,
    l4s: std::collections::VecDeque<DqQueued>,
    classic: std::collections::VecDeque<DqQueued>,
    l4s_bytes: u64,
    classic_bytes: u64,
    /// When the shared link finishes serialising the frame it is currently sending.
    link_free_at: Instant,
    /// Round-robin pointer: when both class queues are backlogged, serve L4S iff this is true, then
    /// flip — so the link alternates between the classes and neither monopolises it. (This does *not*
    /// by itself equalise throughput — a scalable flow leaves slack the classic flow takes; see
    /// [`DualQueue`].)
    serve_l4s_next: bool,
    flight: Vec<DqFlight>,
    order: u64,
    sum_queue_us: [u64; 2],
    max_queue_us: [u64; 2],
    delivered: [u64; 2],
    marked: [u64; 2],
    dropped: [u64; 2],
}

impl DualQueueLink {
    fn new(cfg: DualQueue) -> Self {
        DualQueueLink {
            cfg,
            l4s: std::collections::VecDeque::new(),
            classic: std::collections::VecDeque::new(),
            l4s_bytes: 0,
            classic_bytes: 0,
            link_free_at: Instant::ZERO,
            serve_l4s_next: true,
            flight: Vec::new(),
            order: 0,
            sum_queue_us: [0; 2],
            max_queue_us: [0; 2],
            delivered: [0; 2],
            marked: [0; 2],
            dropped: [0; 2],
        }
    }

    /// A client→server data frame arrived at the bottleneck: classify by IP ECN (ECT → L4S queue,
    /// else → Classic queue) and enqueue, or tail-drop if that class's buffer is full.
    fn enqueue_data(&mut self, now: Instant, flow: usize, frame: Vec<u8>) {
        let len = frame.len() as u64;
        if frame_is_ect(&frame) {
            if self.l4s_bytes + len > self.cfg.l4s_buffer_bytes {
                self.dropped[flow] += 1; // a drop is charged to the flow that sent the frame
                return;
            }
            self.l4s_bytes += len;
            self.l4s.push_back(DqQueued { arrival: now, flow, len, frame });
        } else {
            if self.classic_bytes + len > self.cfg.classic_buffer_bytes {
                self.dropped[flow] += 1;
                return;
            }
            self.classic_bytes += len;
            self.classic.push_back(DqQueued { arrival: now, flow, len, frame });
        }
    }

    /// A server→client frame (an ACK): the reverse path is not the bottleneck, so it skips the queues
    /// and just takes the propagation delay.
    fn enqueue_ack(&mut self, now: Instant, flow: usize, frame: Vec<u8>) {
        let order = self.order;
        self.order += 1;
        self.flight.push(DqFlight {
            deliver_at: now.plus_micros(self.cfg.base_delay_us),
            flow,
            side: Side::ToClient,
            order,
            frame,
        });
    }

    /// Serialise queued frames the shared link can *start* by `now`, scheduling each onward. The link
    /// serves one frame at a time at the configured rate; while it is free and a class queue has a
    /// frame, the round-robin scheduler picks the next class and serialises its head frame.
    fn service(&mut self, now: Instant) {
        let rate = self.cfg.rate_bytes_per_sec.max(1);
        while self.link_free_at <= now {
            let serve_l4s = match (self.l4s.is_empty(), self.classic.is_empty()) {
                (true, true) => break,        // nothing queued
                (false, true) => true,        // only L4S backlogged
                (true, false) => false,       // only Classic backlogged
                (false, false) => self.serve_l4s_next, // both: alternate
            };
            let f = if serve_l4s {
                self.serve_l4s_next = false;
                self.l4s_bytes -= self.l4s.front().unwrap().len;
                self.l4s.pop_front().unwrap()
            } else {
                self.serve_l4s_next = true;
                self.classic_bytes -= self.classic.front().unwrap().len;
                self.classic.pop_front().unwrap()
            };
            // The link starts serialising when it is free *and* the frame has arrived.
            let start = if self.link_free_at > f.arrival { self.link_free_at } else { f.arrival };
            let queue_us = start.saturating_micros_since(f.arrival);
            let serialize_us = f.len.saturating_mul(1_000_000) / rate;
            self.link_free_at = start.plus_micros(serialize_us);

            let mut frame = f.frame;
            // L4S CE marking: an ECT frame whose shallow-queue sojourn tops the threshold is marked CE
            // rather than dropped — the same mechanism as `Aqm::CeMark`, applied to the L4S class only.
            if serve_l4s && queue_us > self.cfg.l4s_threshold_us && frame_is_ect(&frame) {
                set_ecn(&mut frame, ECN_CE);
                self.marked[f.flow] += 1;
            }
            // Stats by flow (the frame's sender), so the per-flow attribution is exact.
            self.sum_queue_us[f.flow] += queue_us;
            self.max_queue_us[f.flow] = self.max_queue_us[f.flow].max(queue_us);
            self.delivered[f.flow] += 1;
            let order = self.order;
            self.order += 1;
            self.flight.push(DqFlight {
                deliver_at: self.link_free_at.plus_micros(self.cfg.base_delay_us),
                flow: f.flow,
                side: Side::ToServer,
                order,
                frame,
            });
        }
    }

    /// The next time the link has work: when it next frees to serve a queued frame, or the earliest
    /// in-flight delivery.
    fn next_event_at(&self) -> Option<Instant> {
        let mut t = self.flight.iter().map(|f| f.deliver_at).min();
        if !self.l4s.is_empty() || !self.classic.is_empty() {
            t = Some(match t {
                Some(t) => t.min(self.link_free_at),
                None => self.link_free_at,
            });
        }
        t
    }

    /// Inject every in-flight frame now due into its destination flow's client/server stack, in
    /// `(deliver_at, order)` order for determinism.
    fn deliver_due(&mut self, now: Instant, flows: &mut [Pair]) {
        let mut due: Vec<DqFlight> = Vec::new();
        let mut keep: Vec<DqFlight> = Vec::new();
        for f in std::mem::take(&mut self.flight) {
            if f.deliver_at <= now {
                due.push(f);
            } else {
                keep.push(f);
            }
        }
        self.flight = keep;
        due.sort_by_key(|f| (f.deliver_at, f.order));
        for f in due {
            match f.side {
                Side::ToServer => flows[f.flow].server.device_mut().inject(f.frame),
                Side::ToClient => flows[f.flow].client.device_mut().inject(f.frame),
            }
        }
    }

    fn flow_result(&self, flow: usize, completed: bool, bytes: usize, sim_time_us: u64) -> FlowResult {
        FlowResult {
            completed,
            bytes,
            sim_time_us,
            mean_queue_us: if self.delivered[flow] > 0 { self.sum_queue_us[flow] / self.delivered[flow] } else { 0 },
            max_queue_us: self.max_queue_us[flow],
            marked: self.marked[flow],
            dropped: self.dropped[flow],
        }
    }
}

/// A flow's [`FlowResult`], built honestly: `completed` is whether *this* flow delivered every byte
/// intact (`received == payload`), independent of whether the other flow finished — and `sim_time_us`
/// is the flow's own completion time when it finished, else the elapsed budget.
fn flow_outcome(link: &DualQueueLink, flow: usize, pair: &Pair, done_at: Option<u64>, now: Instant) -> FlowResult {
    let intact = *pair.received.borrow() == *pair.payload;
    link.flow_result(flow, intact, pair.received.borrow().len(), done_at.unwrap_or(now.micros()))
}

/// Run two bulk transfers sharing one [`DualQueue`] bottleneck and return a per-flow result. Flow 0
/// runs `l4s_cc` (a scalable, ECT-marking controller — its data lands in the shallow L4S queue);
/// flow 1 runs `classic_cc` (a loss-based, Not-ECT controller — its data lands in the deep Classic
/// queue). Deterministic: each flow is an independent pair of single-connection runtimes, and the
/// scheduler/propagation are ordered by explicit counters, so the run is a pure function of the
/// inputs. Stats are attributed per **flow** (flow 0 / flow 1), not per class, so they are exact even
/// for a sender's Not-ECT control frames (see [`DualQueueLink`]).
pub fn run_dualqueue(seed: u64, cfg: DualQueue, bytes: usize, l4s_cc: CcKind, classic_cc: CcKind) -> (FlowResult, FlowResult) {
    let mut flows = vec![
        build_pair(seed, bytes, l4s_cc),
        build_pair(seed.wrapping_add(0x9E37_79B9), bytes, classic_cc),
    ];
    let mut link = DualQueueLink::new(cfg);
    let mut now = Instant::from_micros(0);
    let mut steps: u64 = 0;
    // Per-flow completion sim-time (µs), recorded the step each flow's transfer first finishes — so a
    // starved flow's longer time yields a lower throughput (the fairness metric is genuine, not the
    // global end time both would share).
    let mut done_at: [Option<u64>; 2] = [None; 2];

    loop {
        link.service(now);
        link.deliver_due(now, &mut flows);
        for p in &mut flows {
            p.client.turn(now).expect("mock device never errors");
            p.server.turn(now).expect("mock device never errors");
        }
        // Client→server data through the dual queue; server→client ACKs on the reverse path.
        for (i, p) in flows.iter_mut().enumerate() {
            let out_c: Vec<Vec<u8>> = p.client.device_mut().take_outbound();
            for f in out_c {
                link.enqueue_data(now, i, f);
            }
            let out_s: Vec<Vec<u8>> = p.server.device_mut().take_outbound();
            for f in out_s {
                link.enqueue_ack(now, i, f);
            }
        }
        // Serialise anything just enqueued that the link can already start, so progress never stalls.
        link.service(now);

        for i in 0..flows.len() {
            if done_at[i].is_none() && flows[i].connected.get() && flows[i].received.borrow().len() >= bytes {
                done_at[i] = Some(now.micros());
            }
        }
        if done_at.iter().all(|d| d.is_some()) {
            return (flow_outcome(&link, 0, &flows[0], done_at[0], now), flow_outcome(&link, 1, &flows[1], done_at[1], now));
        }

        steps += 1;
        if steps > MAX_STEPS || now.micros() > MAX_SIM_US {
            // Budget exhausted: report each flow's *own* status — a flow that finished intact before
            // its peer wedged is still `completed`, not failed.
            return (flow_outcome(&link, 0, &flows[0], done_at[0], now), flow_outcome(&link, 1, &flows[1], done_at[1], now));
        }

        let mut next = link.next_event_at();
        for p in &flows {
            next = [next, p.client.poll_at(), p.server.poll_at()].into_iter().flatten().min();
        }
        match next {
            Some(t) if t > now => now = t,
            Some(_) => now = now.plus_micros(1),
            None => {
                return (flow_outcome(&link, 0, &flows[0], done_at[0], now), flow_outcome(&link, 1, &flows[1], done_at[1], now));
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
        // — which multiplies the distinct event *sequences* the coverage map distinguishes. (A blind
        // sampler reaches the same recovery *depths*; what coverage feedback adds is reaching more of
        // the depth-stratified event sequences *within* recovery — see the feedback test below.)
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

/// Mutate a scenario by perturbing 1–3 of its dimensions, staying inside a **survivable** envelope:
/// loss ≤ 12%, dup ≤ 8%, corrupt ≤ 2%, jitter ≤ 6 ms, ≤ 24 KB. Each cap sits at or below a point the
/// fixed DST suite already exercises on *that* axis (loss 12% < its 20% heavy-loss test; corrupt 2% <
/// its 8% corruption test; dup/jitter at the grid's levels), and the four-way worst corner was
/// re-confirmed survivable directly. So the link stays survivable and any non-completion the fuzzer
/// turns up is a genuine bug, never an un-survivably-hostile link.
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

/// Run a **coverage-guided** fuzzing campaign that evaluates exactly `iterations` scenarios,
/// deterministically driven by `fuzz_seed`. The first scenario is a mild fixed base; each subsequent
/// one is a mutation of a corpus member, and the corpus grows with every scenario that advances
/// coverage — so the search steers toward new behaviour a fixed grid never would. It asserts nothing
/// itself: the caller inspects the [`FuzzReport`] (its `findings` must be empty; its `coverage`/
/// `edges` are the search's reach). The `iterations` evaluation count matches
/// [`fuzz_random_baseline`] exactly, so the two are an equal-budget comparison.
pub fn fuzz(fuzz_seed: u64, iterations: u32) -> FuzzReport {
    let mut rng = Rng::new(fuzz_seed ^ 0xF1F2_F3F4_F5F6_F7F8);
    let mut global = Coverage::new();
    let mut corpus: Vec<Scenario> = Vec::new();
    let mut findings: Vec<Scenario> = Vec::new();

    for _ in 0..iterations {
        // The first scenario seeds the corpus from a fixed base; the rest mutate a corpus member.
        let scn = if corpus.is_empty() {
            fuzz_base()
        } else {
            let idx = rng.below(corpus.len() as u64) as usize;
            fuzz_mutate(&mut rng, &corpus[idx])
        };
        let (o, c) = run_with_coverage(&scn);
        if global.merge(&c) > 0 {
            corpus.push(scn); // it found new behaviour — keep it to mutate further
        }
        if !o.is_completed() {
            findings.push(scn);
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

// ── evolved congestion control (CEM trainer) ─────────────────────────────────────────────────────
//
// The deterministic bottleneck sim is a microsecond-fast, perfectly-reproducible environment — which
// makes it a *training ground* for a learned controller. The cross-entropy method (CEM) searches the
// [`LearnedParams`] genome to maximise a latency-vs-throughput fitness, evaluating each candidate
// through the very same `run_bottleneck` path the real stack uses. Everything is std-only: the
// Gaussian samples come from a sum-of-twelve-uniforms central-limit draw (no Box-Muller `ln`/`sqrt`/
// `cos`), and the one square root the covariance update needs is hand-rolled Newton — so the optimiser
// is zero-dependency and free of transcendental intrinsics, exactly like the controllers it tunes.

use crate::congestion::{set_learned_override, set_program_override, ControlProgram, Instr, LearnedParams, SynthOp, Synth};

const GENOME: usize = 5;

fn genome_to_vec(p: LearnedParams) -> [f64; GENOME] {
    [p.ai_gain, p.md_loss, p.ecn_a, p.ecn_b, p.ecn_max]
}

fn vec_to_genome(v: [f64; GENOME]) -> LearnedParams {
    LearnedParams { ai_gain: v[0], md_loss: v[1], ecn_a: v[2], ecn_b: v[3], ecn_max: v[4] }
}

/// Newton's-method square root — no `f64::sqrt` intrinsic, matching the project's no-transcendental
/// rule (the same discipline as CUBIC's hand-rolled cube root). Returns 0 for non-positive input.
fn sqrt_newton(a: f64) -> f64 {
    if a <= 0.0 {
        return 0.0;
    }
    let mut x = if a > 1.0 { a } else { 1.0 };
    for _ in 0..40 {
        x = 0.5 * (x + a / x);
    }
    x
}

/// A standard-normal sample as the sum of twelve uniforms minus six (central-limit theorem: mean 0,
/// variance 1). No transcendental functions — unlike Box-Muller — so it stays zero-dependency and
/// deterministic on every platform.
fn gaussian01(rng: &mut Rng) -> f64 {
    let mut s = 0.0;
    for _ in 0..12 {
        s += rng.next_u64() as f64 / u64::MAX as f64;
    }
    s - 6.0
}

/// One training/evaluation scenario for the fitness: a bottleneck, the transfer size, and the seed.
#[derive(Clone, Copy, Debug)]
pub struct TrainScenario {
    pub bn: Bottleneck,
    pub bytes: usize,
    pub seed: u64,
}

/// The latency-throughput fitness of a genome over `scenarios`: reward goodput (as a fraction of line
/// rate), penalise the mean standing queue (per millisecond), and heavily penalise a transfer that
/// fails to complete with integrity. Higher is better. Each scenario runs the genome through the real
/// `run_bottleneck` path (installed via the training override), so the fitness is exactly the
/// behaviour the shipped controller would exhibit.
pub fn frontier_fitness(p: LearnedParams, scenarios: &[TrainScenario]) -> f64 {
    set_learned_override(Some(p));
    let mut total = 0.0;
    for s in scenarios {
        let r = run_bottleneck(s.seed, s.bn, s.bytes, CcKind::Learned);
        let line = s.bn.rate_bytes_per_sec.max(1) as f64;
        let goodput = r.throughput_bytes_per_sec() as f64 / line;
        let q_ms = r.data_queue.mean_queue_us as f64 / 1_000.0;
        // Maximise goodput subject to a *sub-millisecond* queue: a standing queue up to 1 ms is
        // "free" (that is the L4S target), and only the excess beyond it is penalised — so the search
        // spends the latency budget it is allowed on throughput instead of crushing the queue to zero
        // at a throughput cost (which is the trap DCTCP's fixed aggressive response falls into here).
        let queue_excess = (q_ms - 1.0).max(0.0);
        let complete = if r.completed { 0.0 } else { -5.0 };
        total += goodput - 0.4 * queue_excess + complete;
    }
    set_learned_override(None);
    total / scenarios.len().max(1) as f64
}

/// Evolve a [`LearnedParams`] genome on `train` with the **cross-entropy method**: keep a per-gene
/// Gaussian, sample a population each generation, evaluate the fitness, and refit the Gaussian to the
/// top `elite_frac`. Deterministic in `seed`. Returns the best genome seen and its fitness.
pub fn evolve(train: &[TrainScenario], generations: u32, pop: usize, elite_frac: f64, seed: u64) -> (LearnedParams, f64) {
    evolve_from(LearnedParams::DEFAULT, generations, pop, elite_frac, seed, |p| frontier_fitness(p, train))
}

/// The CEM engine behind [`evolve`], generalised over the **initial mean genome** and an arbitrary
/// **fitness** (higher is better). `evolve` passes `LearnedParams::DEFAULT` + [`frontier_fitness`]
/// (so it is byte-for-byte unchanged); co-evolution ([`coevolve`]) passes the previous champion as a
/// warm start and a *robust* worst-case-over-an-adversarial-archive fitness. Deterministic in `seed`.
fn evolve_from(
    init: LearnedParams,
    generations: u32,
    pop: usize,
    elite_frac: f64,
    seed: u64,
    mut fitness: impl FnMut(LearnedParams) -> f64,
) -> (LearnedParams, f64) {
    let mut rng = Rng::new(seed ^ 0xE70E_77E5_0E77_E50E);
    let mut mean = genome_to_vec(init);
    // Initial per-gene exploration spread, and a floor so the Gaussian can't collapse prematurely.
    let mut std = [1.0_f64, 0.2, 0.6, 0.5, 0.25];
    let floor = [0.05_f64, 0.02, 0.05, 0.05, 0.03];

    let mut best = init;
    let mut best_fit = fitness(best);
    let n_elite = ((pop as f64 * elite_frac).ceil() as usize).clamp(1, pop.max(1));

    for _ in 0..generations {
        let mut scored: Vec<([f64; GENOME], f64)> = Vec::with_capacity(pop);
        for _ in 0..pop {
            let mut cand = mean;
            for j in 0..GENOME {
                cand[j] += std[j] * gaussian01(&mut rng);
            }
            let p = vec_to_genome(cand).sanitized();
            let fit = fitness(p);
            if fit > best_fit {
                best_fit = fit;
                best = p;
            }
            scored.push((genome_to_vec(p), fit));
        }
        // Rank by fitness (desc) and refit the Gaussian to the elite (mean + per-gene std).
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        for j in 0..GENOME {
            let m = scored[..n_elite].iter().map(|(c, _)| c[j]).sum::<f64>() / n_elite as f64;
            let var = scored[..n_elite].iter().map(|(c, _)| (c[j] - m) * (c[j] - m)).sum::<f64>() / n_elite as f64;
            mean[j] = m;
            std[j] = sqrt_newton(var).max(floor[j]);
        }
    }
    (best, best_fit)
}

// ── adversarial worst-case discovery (the network as the optimiser) ──────────────────────────────
//
// The coverage fuzzer above steers toward *new behaviour*; the CEM trainer steers a *controller*
// toward low latency. This third search inverts the trainer: it steers the **network** toward the
// trace that maximally *hurts* a fixed controller. The same deterministic sim that lets us fuzz for
// correctness and evolve a controller lets us *minimax* for robustness — search the space of network
// conditions for the one that drives a chosen cost (the standing queue, or the throughput shortfall)
// as high as it goes. Because the run is a pure function of the trace, a found worst case is a
// concrete, re-runnable artefact: "the trace that bloats BBR," replayable bit-for-bit, not a
// statistical anecdote. This is the verifier-in-the-loop / CEGIS discipline pointed at congestion
// control — and the natural escalation of the synthesise-and-verify loop the project already has.
//
// The searchable trace is a **capacity trajectory**: the bottleneck's service rate follows a
// schedule of per-slice multipliers (percent of a base rate), cycled over the whole transfer.
// Capacity variation, *not* loss, is the lever (independent loss only triggers the loss response;
// a capacity change bloats a queue), and which trace is worst depends on the objective:
//   - For the **standing-queue** objective the search converges on a *sustained throttle* — a low
//     near-constant rate — because mean sojourn is maximised by the slowest drain (every byte waits
//     longer in a slow-emptying queue), compounded on a short transfer by the controller overshooting
//     a link slower than its start-up probe expects. It is a worse *operating point*, not a timing
//     trick: the winning trace is roughly flat-but-low.
//   - For the **throughput** objective the search finds a genuinely *time-varying* trace — bandwidth
//     moving underneath a windowed-max rate estimator (BBR remembers a stale max for ~10 RTTs, so a
//     spike that primes the estimate high followed by a crash drives it into a deep queue). This is
//     the real timing pathology, and it is BBR-specific (see `adversary_worst_case_report`).
// The envelope is **bounded** — the rate never falls below a floor — so the *link* is always capable
// of delivering the transfer. Two distinct non-completions can therefore occur, which the single
// `completed` flag must not be allowed to conflate: a byte-integrity failure would be a real **stack
// bug** (the fuzzer's oracle, and it never happens here), whereas a budget *timeout* under the
// throughput objective is the adversary driving a controller into a near-livelock — a **controller**
// finding, not a stack bug (the same trace completes fine under a loss-based controller).

/// Slices in an adversarial capacity schedule. The schedule is *cycled* over the whole transfer, so a
/// short fixed-size genome shapes an arbitrarily long run; 16 gives the search enough degrees of
/// freedom to place a drop within a controller's probe cycle without an unwieldy search space.
const ADV_SLICES: usize = 16;
/// Per-slice capacity multiplier bounds, in **percent of the base rate**. The floor keeps the *link*
/// always able to deliver the transfer (capacity never collapses to nothing); the ceiling above 100
/// lets the adversary build both bandwidth *drops* and *spikes* — a spike that primes a windowed-max
/// rate estimator high followed by a crash is the worst pattern for an estimator-paced controller
/// (the throughput objective), while the standing-queue objective drives toward the floor instead.
const ADV_MIN_PCT: u16 = 30;
const ADV_MAX_PCT: u16 = 150;
/// Fixed run seed for every adversarial evaluation: the bottleneck is deterministic and carries no
/// fault RNG, so an evaluation is a pure function of `(env, trace, cc)`. Fixing the seed pins the
/// only incidental input (the ISN secrets), making the cost depend on the *trace* alone — exactly
/// what a cost-maximising search needs.
const ADV_RUN_SEED: u64 = 0xADAC_5EED_ADAC_5EED;

/// The fixed bottleneck envelope the adversary searches *within*: the base line rate it scales, the
/// buffer depth, the one-way propagation delay, how long each schedule slice lasts, and the AQM. The
/// adversary may only reshape the capacity *trajectory* (the [`AdvTrace`]); everything here is held
/// constant, so guided and random searches draw from the same space and compare apples to apples.
#[derive(Clone, Copy, Debug)]
pub struct AdvEnv {
    pub base_rate_bytes_per_sec: u64,
    pub buffer_bytes: u64,
    pub base_delay_us: u64,
    /// How long each of the [`ADV_SLICES`] schedule entries holds before the next (µs).
    pub slice_us: u64,
    pub aqm: Aqm,
}

/// A searchable **capacity trace**: per-slice rate multipliers (percent of the env's base rate),
/// cycled over the transfer. This is the network condition the adversary optimises; a found trace
/// replays bit-for-bit through [`run_adversarial`], so it is a complete, re-runnable repro.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AdvTrace {
    schedule: [u16; ADV_SLICES],
}

impl AdvTrace {
    /// The unstressed reference: a constant base rate (every slice 100 %) — i.e. the ordinary
    /// fixed-rate bottleneck, the controller's steady operating point with no adversary acting.
    pub const FLAT: AdvTrace = AdvTrace { schedule: [100; ADV_SLICES] };

    /// The **discovered worst case** — a concrete, named, re-runnable artefact. This is the genuinely
    /// time-varying capacity trace that `adversary_search(Bbr, ThroughputShortfall, 1 MiB, 160, 0xCAFE)`
    /// finds (reproduced in the ignored `adversary_worst_case_report`): on it BBR's goodput collapses
    /// while a loss-based controller is unaffected. Baked here, exactly as the evolved controller's
    /// genome is baked, so a fast test can exercise the headline without re-running the search.
    pub const KNOWN_BBR_BREAKER: AdvTrace =
        AdvTrace { schedule: [33, 33, 33, 94, 33, 105, 33, 33, 30, 42, 70, 33, 33, 33, 33, 33] };

    /// The raw per-slice multipliers (percent of base), for inspection / a repro.
    pub fn schedule(&self) -> &[u16] {
        &self.schedule
    }

    /// True if any slice departs from the flat base — i.e. the adversary moved the capacity off the
    /// constant base line (throttled below it and/or spiked above it). A teeth check that the search
    /// returned something other than the flat reference; note it does **not** imply *time variation*
    /// within the trace (a sustained throttle, the mean-queue winner, is uniform-but-below-base — use
    /// [`AdvTrace::time_varies`] when the claim is specifically about a moving bottleneck).
    pub fn is_varying(&self) -> bool {
        self.schedule.iter().any(|&p| p != 100)
    }

    /// True if the trace's rate genuinely **changes over time** (its slices are not all equal) — the
    /// property that distinguishes a timing/shape pathology from a flat throttle.
    pub fn time_varies(&self) -> bool {
        self.schedule.iter().min() != self.schedule.iter().max()
    }

    /// The link's service rate (bytes/sec) at time `t`: the base rate scaled by the schedule slice
    /// `t` falls in (the schedule cycles every `ADV_SLICES · slice_us`). Floored at 1 B/s so logical
    /// time always advances.
    fn rate_at(&self, env: &AdvEnv, t: Instant) -> u64 {
        let slice = (t.micros() / env.slice_us.max(1)) as usize % ADV_SLICES;
        (env.base_rate_bytes_per_sec.saturating_mul(self.schedule[slice] as u64) / 100).max(1)
    }
}

impl core::fmt::Debug for AdvTrace {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "AdvTrace({:?}%)", self.schedule)
    }
}

/// A data frame waiting in the bottleneck's single FIFO for the link to serialise it.
struct AdvQueued {
    arrival: Instant,
    len: u64,
    frame: Vec<u8>,
}

/// The adversarial bottleneck link: one finite FIFO on the data direction served at a **time-varying**
/// rate (the [`AdvTrace`]), with the reverse (ACK) direction taking only propagation delay (it is not
/// the bottleneck). Structurally this is [`BottleneckLink`] generalised to a rate that changes over
/// time — modelled with an explicit byte FIFO (like the dual-queue link) so the varying rate is exact
/// per frame rather than inferred from a single constant.
struct AdvLink {
    env: AdvEnv,
    trace: AdvTrace,
    queue: std::collections::VecDeque<AdvQueued>,
    queued_bytes: u64,
    /// When the shared link finishes serialising the frame it is currently sending.
    link_free_at: Instant,
    /// Frames past the bottleneck, propagating to their destination stack (both directions).
    inflight: Vec<InFlight>,
    order: u64,
    sum_queue_us: u64,
    max_queue_us: u64,
    delivered: u64,
    dropped: u64,
    marked: u64,
}

impl AdvLink {
    fn new(env: AdvEnv, trace: AdvTrace) -> Self {
        AdvLink {
            env,
            trace,
            queue: std::collections::VecDeque::new(),
            queued_bytes: 0,
            link_free_at: Instant::ZERO,
            inflight: Vec::new(),
            order: 0,
            sum_queue_us: 0,
            max_queue_us: 0,
            delivered: 0,
            dropped: 0,
            marked: 0,
        }
    }

    /// A client→server data frame reached the bottleneck: enqueue it, or tail-drop if the buffer is
    /// full (the backstop under any AQM).
    fn enqueue_data(&mut self, now: Instant, frame: Vec<u8>) {
        let len = frame.len() as u64;
        if self.queued_bytes + len > self.env.buffer_bytes {
            self.dropped += 1;
            return;
        }
        self.queued_bytes += len;
        self.queue.push_back(AdvQueued { arrival: now, len, frame });
    }

    /// A server→client frame (an ACK): the reverse path is not the bottleneck, so it skips the queue
    /// and just takes the propagation delay.
    fn enqueue_ack(&mut self, now: Instant, frame: Vec<u8>) {
        let order = self.order;
        self.order += 1;
        self.inflight.push(InFlight {
            deliver_at: now.plus_micros(self.env.base_delay_us),
            side: Side::ToClient,
            order,
            frame,
        });
    }

    /// Serialise every queued frame the link can *start* by `now`, at the capacity in force when each
    /// frame's serialisation begins, scheduling each onward after the propagation delay.
    fn service(&mut self, now: Instant) {
        while self.link_free_at <= now {
            let Some(head) = self.queue.front() else { break };
            // The link starts serialising when it is free *and* the frame has arrived.
            let start = if self.link_free_at > head.arrival { self.link_free_at } else { head.arrival };
            let queue_us = start.saturating_micros_since(head.arrival); // sojourn = standing-queue delay
            let rate = self.trace.rate_at(&self.env, start); // the capacity at the instant service starts
            let f = self.queue.pop_front().unwrap();
            self.queued_bytes -= f.len;
            let serialize_us = f.len.saturating_mul(1_000_000) / rate;
            self.link_free_at = start.plus_micros(serialize_us);

            let mut frame = f.frame;
            // L4S CE marking (same mechanism as `Aqm::CeMark`): an ECT frame whose sojourn tops the
            // threshold is marked CE rather than dropped, so an ECN-aware controller can react to it.
            if let Aqm::CeMark { threshold_us } = self.env.aqm {
                if queue_us > threshold_us && frame_is_ect(&frame) {
                    set_ecn(&mut frame, ECN_CE);
                    self.marked += 1;
                }
            }
            self.sum_queue_us += queue_us;
            self.max_queue_us = self.max_queue_us.max(queue_us);
            self.delivered += 1;
            let order = self.order;
            self.order += 1;
            self.inflight.push(InFlight {
                deliver_at: self.link_free_at.plus_micros(self.env.base_delay_us),
                side: Side::ToServer,
                order,
                frame,
            });
        }
    }

    /// The next time the link has work: when it next frees to serve a queued frame, or the earliest
    /// in-flight delivery.
    fn next_event_at(&self) -> Option<Instant> {
        let mut t = min_deliver_at(&self.inflight);
        if !self.queue.is_empty() {
            t = Some(match t {
                Some(t) => t.min(self.link_free_at),
                None => self.link_free_at,
            });
        }
        t
    }

    fn deliver_due(&mut self, now: Instant, client: &mut Runtime<MockDevice>, server: &mut Runtime<MockDevice>) {
        flush_due(&mut self.inflight, now, client, server);
    }

    fn mean_queue_us(&self) -> u64 {
        if self.delivered > 0 {
            self.sum_queue_us / self.delivered
        } else {
            0
        }
    }
}

/// The result of an adversarial bottleneck run — the cost signals a search maximises.
#[derive(Clone, Copy, Debug)]
pub struct AdvResult {
    /// `true` only if the transfer delivered every requested byte intact. `false` is **either** a
    /// byte-integrity failure (a stack bug — never seen) **or**, under the throughput objective, a
    /// budget timeout (the controller crawled past the step/time budget without finishing — a
    /// controller-collapse finding, not a stack bug; the data still delivered is `delivered_bytes`).
    pub completed: bool,
    pub sim_time_us: u64,
    /// Bytes requested (the transfer size).
    pub bytes: usize,
    /// Bytes actually delivered to the receiver by the time the run ended (= `bytes` on completion;
    /// less on a timeout). Goodput is computed from this, so it is honest on a non-completing run.
    pub delivered_bytes: usize,
    /// Mean standing-queue delay on the data direction (µs) — the bufferbloat cost.
    pub mean_queue_us: u64,
    pub max_queue_us: u64,
    pub dropped: u64,
    pub marked: u64,
}

impl AdvResult {
    /// Goodput in bytes/second: **delivered** bytes over the elapsed time (so a transfer that timed
    /// out part-way reports the goodput it actually achieved, not the requested rate).
    pub fn throughput_bytes_per_sec(&self) -> u64 {
        if self.sim_time_us > 0 {
            (self.delivered_bytes as u64).saturating_mul(1_000_000) / self.sim_time_us
        } else {
            0
        }
    }
}

/// Run a bulk transfer over the adversarial, **time-varying** bottleneck described by `(env, trace)`
/// and measure the cost signals. **Deterministic**: a pure function of `(env, trace, bytes, cc)` (the
/// run seed is fixed), so a given trace always yields the same [`AdvResult`] — a found worst case
/// replays bit-for-bit.
pub fn run_adversarial(env: AdvEnv, trace: AdvTrace, bytes: usize, cc: CcKind) -> AdvResult {
    let Pair { mut client, mut server, payload, received, connected } = build_pair(ADV_RUN_SEED, bytes, cc);
    let mut link = AdvLink::new(env, trace);
    let mut now = Instant::from_micros(0);
    let mut steps: u64 = 0;
    let result = |completed, now: Instant, delivered: usize, link: &AdvLink| AdvResult {
        completed,
        sim_time_us: now.micros(),
        bytes,
        delivered_bytes: delivered,
        mean_queue_us: link.mean_queue_us(),
        max_queue_us: link.max_queue_us,
        dropped: link.dropped,
        marked: link.marked,
    };

    loop {
        link.service(now);
        link.deliver_due(now, &mut client, &mut server);
        client.turn(now).expect("mock device never errors");
        server.turn(now).expect("mock device never errors");
        for f in client.device_mut().take_outbound() {
            link.enqueue_data(now, f);
        }
        for f in server.device_mut().take_outbound() {
            link.enqueue_ack(now, f);
        }
        // Serialise anything just enqueued the link can already start, so progress never stalls.
        link.service(now);

        let got = received.borrow().len();
        if connected.get() && got >= bytes {
            return result(*received.borrow() == *payload, now, got, &link);
        }

        steps += 1;
        if steps > MAX_STEPS || now.micros() > MAX_SIM_US {
            return result(false, now, got, &link);
        }

        let next = [client.poll_at(), server.poll_at(), link.next_event_at()].into_iter().flatten().min();
        match next {
            Some(t) if t > now => now = t,
            Some(_) => now = now.plus_micros(1),
            None => return result(false, now, received.borrow().len(), &link),
        }
    }
}

/// What the adversary maximises against a controller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdvObjective {
    /// The mean standing-queue delay (µs) — drive the bufferbloat as high as it goes. The search
    /// converges on a *sustained throttle* (a low near-constant rate), since mean sojourn is maximised
    /// by the slowest drain — a worse operating point, not a timing trick.
    MeanQueueUs,
    /// The worst single-frame standing-queue delay (µs) — the latency-spike cost.
    MaxQueueUs,
    /// The throughput *shortfall* below the base line rate (B/s): `base_rate − achieved goodput`, so a
    /// higher cost is a slower transfer. This objective finds genuinely *time-varying* traces (a
    /// windowed-max rate estimator's blind spot) and can drive a controller into a near-livelock —
    /// goodput here is the honest delivered-bytes goodput, so a stalled transfer scores a real shortfall.
    ThroughputShortfall,
    /// A combined **latency-throughput frontier penalty** (×1000, so it stays integer): the throughput
    /// shortfall *as a fraction of the line* plus the standing queue's excess over 1 ms (the same hinge
    /// the CEM fitness uses), plus a large penalty for not completing. This is the objective the
    /// co-evolution game ([`coevolve`]) is played on — the adversary maximises it, the controller
    /// minimises its worst case — so neither side can win degenerately (the adversary can't just lower
    /// the average bandwidth without the controller being able to answer, and the controller can't kill
    /// the queue by tanking throughput, because both are in the one cost).
    FrontierPenalty,
}

/// The scalar cost of a run under `obj` (higher is worse for the controller).
fn adv_single_cost(obj: AdvObjective, env: &AdvEnv, r: &AdvResult) -> u64 {
    match obj {
        AdvObjective::MeanQueueUs => r.mean_queue_us,
        AdvObjective::MaxQueueUs => r.max_queue_us,
        AdvObjective::ThroughputShortfall => {
            env.base_rate_bytes_per_sec.saturating_sub(r.throughput_bytes_per_sec())
        }
        AdvObjective::FrontierPenalty => {
            let line = env.base_rate_bytes_per_sec.max(1) as f64;
            let goodput_frac = r.throughput_bytes_per_sec() as f64 / line;
            let q_ms = r.mean_queue_us as f64 / 1_000.0;
            let mut penalty = (1.0 - goodput_frac).max(0.0) + 0.4 * (q_ms - 1.0).max(0.0);
            if !r.completed {
                penalty += 5.0;
            }
            (penalty * 1_000.0) as u64
        }
    }
}

/// A uniformly-random per-slice multiplier in `[ADV_MIN_PCT, ADV_MAX_PCT]`.
fn adv_rand_pct(rng: &mut Rng) -> u16 {
    ADV_MIN_PCT + rng.below((ADV_MAX_PCT - ADV_MIN_PCT + 1) as u64) as u16
}

/// A fresh uniformly-random capacity trace — the black-box baseline the guided search is measured
/// against (same envelope, same per-slice distribution).
fn adv_random_trace(rng: &mut Rng) -> AdvTrace {
    let mut schedule = [100u16; ADV_SLICES];
    for v in schedule.iter_mut() {
        *v = adv_rand_pct(rng);
    }
    AdvTrace { schedule }
}

/// Mutate a trace toward (hopefully) higher cost. The mix is weighted toward **block** mutations (a
/// contiguous run set to one level — a sustained drop or spike), because the mean-queue cost responds
/// to a *sustained* capacity change far more than to a single isolated slice; **point** mutations
/// (retarget 1–3 slices) and a local **nudge** (shift one slice by a small step) add coarse breadth
/// and fine timing. The block run wraps, matching how the schedule itself cycles.
fn adv_mutate(rng: &mut Rng, parent: &AdvTrace) -> AdvTrace {
    let mut t = *parent;
    match rng.below(20) {
        // ~45 %: block mutation (the move that actually shifts a *sustained* queue).
        0..=8 => {
            let start = rng.below(ADV_SLICES as u64) as usize;
            let len = 1 + rng.below(ADV_SLICES as u64);
            let level = adv_rand_pct(rng);
            for k in 0..len as usize {
                t.schedule[(start + k) % ADV_SLICES] = level;
            }
        }
        // ~30 %: point mutation of 1–3 slices.
        9..=14 => {
            let n = 1 + rng.below(3);
            for _ in 0..n {
                let i = rng.below(ADV_SLICES as u64) as usize;
                t.schedule[i] = adv_rand_pct(rng);
            }
        }
        // ~25 %: local nudge of one slice (fine timing/depth search).
        _ => {
            let i = rng.below(ADV_SLICES as u64) as usize;
            let step = 10 + rng.below(30) as u16;
            t.schedule[i] = if rng.below(2) == 0 {
                t.schedule[i].saturating_sub(step).max(ADV_MIN_PCT)
            } else {
                (t.schedule[i] + step).min(ADV_MAX_PCT)
            };
        }
    }
    t
}

/// One kept trace in the elite corpus.
struct AdvElite {
    trace: AdvTrace,
    cost: u64,
}

/// Hill-climbing adversarial search. Keeps a small **elite corpus** of the highest-cost traces seen
/// and, each iteration, mutates one of them (with an occasional random restart for basin diversity),
/// retaining any trace that beats the weakest elite — a steady-state evolutionary maximiser. The
/// first evaluation is the flat reference, so its cost is returned as `flat_cost`. Runs exactly
/// `iterations` evaluations (so it is an *equal-budget* comparison against
/// [`adversary_random_baseline`] — though note ~1/4 of those evaluations are random immigrants, i.e.
/// the same blind sampling, so the guidance's edge comes from the mutation/tournament fraction and is
/// modest in this low-dimensional schedule space; its surer value is the single refined, reproducible
/// worst case it returns). Deterministic in `seed`. `eval` returns `(cost, completed)`.
///
/// Returns `(best_trace, best_cost, best_completed, flat_cost, corpus_len)`. `iterations` must be ≥ 1
/// (else `flat_cost` is never measured and stays 0); callers pass a real budget.
fn maximize_cost<F: FnMut(&AdvTrace) -> (u64, bool)>(
    iterations: u32,
    seed: u64,
    mut eval: F,
) -> (AdvTrace, u64, bool, u64, usize) {
    debug_assert!(iterations >= 1, "the search needs at least one evaluation (the flat reference)");
    const CORPUS_MAX: usize = 16;
    let mut rng = Rng::new(seed ^ 0xAD7E_5A12_3456_789A);
    let mut corpus: Vec<AdvElite> = Vec::new(); // kept sorted by cost, descending
    let mut best = AdvTrace::FLAT;
    let mut best_cost = 0u64;
    let mut best_completed = true;
    let mut flat_cost = 0u64;

    for it in 0..iterations {
        let trace = if corpus.is_empty() {
            AdvTrace::FLAT // the unstressed reference seeds the corpus
        } else if rng.below(4) == 0 {
            adv_random_trace(&mut rng) // a random immigrant — broad exploration each round
        } else {
            // Tournament-of-three over the elite corpus, then mutate the winner: biased toward the
            // best trace seen (strong exploitation) without collapsing onto it (the loser draws keep
            // diversity), so the climb refines the genuinely-worst basin instead of a random one.
            let mut parent = &corpus[rng.below(corpus.len() as u64) as usize];
            for _ in 0..2 {
                let other = &corpus[rng.below(corpus.len() as u64) as usize];
                if other.cost > parent.cost {
                    parent = other;
                }
            }
            adv_mutate(&mut rng, &parent.trace)
        };
        let (cost, completed) = eval(&trace);
        if it == 0 {
            flat_cost = cost;
        }
        if cost > best_cost {
            best = trace;
            best_cost = cost;
            best_completed = completed;
        }
        // Elitism: keep the top CORPUS_MAX traces (by cost) to mutate further.
        if corpus.len() < CORPUS_MAX || cost > corpus.last().map_or(0, |e| e.cost) {
            let pos = corpus.iter().position(|e| e.cost < cost).unwrap_or(corpus.len());
            corpus.insert(pos, AdvElite { trace, cost });
            corpus.truncate(CORPUS_MAX);
        }
    }
    (best, best_cost, best_completed, flat_cost, corpus.len())
}

/// The result of an [`adversary_search`] campaign: the worst-case trace it found (replayable), that
/// trace's cost and whether it still completed with integrity, the flat-path reference cost (the
/// steady, no-adversary baseline), and how large an elite corpus the search kept.
#[derive(Clone, Copy, Debug)]
pub struct AdvReport {
    pub iterations: u32,
    pub objective: AdvObjective,
    pub cc: CcKind,
    pub best_trace: AdvTrace,
    pub best_cost: u64,
    pub best_completed: bool,
    pub corpus_size: usize,
    /// The cost of the flat (constant base-rate) path — the controller's steady, unstressed reference
    /// with no adversary acting. (The *average under random variation* is the random baseline's mean,
    /// not this; this is the no-variation operating point.)
    pub flat_cost: u64,
}

/// Search for the capacity trace that maximises `objective` against controller `cc` on bottleneck
/// `env`, over `iterations` evaluations, deterministically driven by `seed`. The returned
/// [`AdvReport::best_trace`] is the worst case found, replayable bit-for-bit through
/// [`run_adversarial`].
pub fn adversary_search(
    cc: CcKind,
    objective: AdvObjective,
    env: AdvEnv,
    bytes: usize,
    iterations: u32,
    seed: u64,
) -> AdvReport {
    let (best_trace, best_cost, best_completed, flat_cost, corpus_size) = maximize_cost(iterations, seed, |t| {
        let r = run_adversarial(env, *t, bytes, cc);
        (adv_single_cost(objective, &env, &r), r.completed)
    });
    AdvReport { iterations, objective, cc, best_trace, best_cost, best_completed, corpus_size, flat_cost }
}

/// The black-box baseline: `iterations` uniformly-random traces from the *same* envelope, with no
/// cost feedback. Reports the **mean** cost (the controller's average case under random capacity
/// variation) and the **max** (what blind sampling alone turns up) — so a guided campaign that beats
/// the mean and meets-or-beats the max has demonstrably found structure, not luck, at equal budget.
#[derive(Clone, Copy, Debug)]
pub struct AdvBaseline {
    pub iterations: u32,
    pub mean_cost: u64,
    pub max_cost: u64,
    /// Whether every random trace completed with integrity (survivability across the envelope).
    pub all_completed: bool,
}

/// Evaluate `iterations` uniformly-random traces against `cc` on `env` (see [`AdvBaseline`]).
pub fn adversary_random_baseline(
    cc: CcKind,
    objective: AdvObjective,
    env: AdvEnv,
    bytes: usize,
    iterations: u32,
    seed: u64,
) -> AdvBaseline {
    let mut rng = Rng::new(seed ^ 0x0BAD_C0DE_0BAD_C0DE);
    let mut sum: u128 = 0;
    let mut max_cost = 0u64;
    let mut all_completed = true;
    for _ in 0..iterations {
        let t = adv_random_trace(&mut rng);
        let r = run_adversarial(env, t, bytes, cc);
        let c = adv_single_cost(objective, &env, &r);
        sum += c as u128;
        max_cost = max_cost.max(c);
        all_completed &= r.completed;
    }
    AdvBaseline {
        iterations,
        mean_cost: (sum / iterations.max(1) as u128) as u64,
        max_cost,
        all_completed,
    }
}

// ── co-evolution: synthesise a controller robust to its own worst case (CEGIS for CC) ─────────────
//
// The three searches above are now wired into one loop. The CEM *synthesises* a controller, the
// adversary finds the *counterexample* (the capacity trace that hurts it most), that trace joins a
// growing **archive**, and the CEM re-synthesises against the whole archive — minimising the controller's
// *worst case* over every attack found so far, not its average. It is the counterexample-guided
// inductive-synthesis (CEGIS) loop, minimax / GAN-like, applied to congestion control on the real stack
// engine: the network attacks, the synthesiser defends, and (separately, via `bmc`) the survivor is
// machine-checked safe. Both sides play the one [`AdvObjective::FrontierPenalty`] cost, so it is a true
// zero-sum game on the latency-throughput frontier — the controller cannot cheat by tanking throughput to
// flatten the queue, and the adversary cannot win by merely lowering the mean bandwidth. The output is a
// controller the search *optimises* to be hard to break — verified empirically on a held-out attack, not
// guaranteed — that is **safe by construction** (every genome is sanitised into the bounded-proven M19
// envelope); the archive is the concrete record of exactly which attacks it withstands. Std-only, replayable.

/// The outcome of a [`coevolve`] run: the robust champion genome, how it was reached, and the
/// per-round trace of the adversary's best attack (which should plateau/shrink as the controller
/// closes its gaps — the convergence signal).
#[derive(Clone, Debug)]
pub struct CoevolveReport {
    /// The synthesised robust controller (sanitised — inside the safe genome envelope).
    pub genome: LearnedParams,
    /// How many adversarial traces ended up in the archive (the flat seed + each counterexample).
    pub archive_size: usize,
    /// Rounds actually run (fewer than requested if the adversary stopped finding new counterexamples).
    pub rounds: u32,
    /// The adversary's best [`AdvObjective::FrontierPenalty`] against each round's champion, in order.
    pub worst_cost_per_round: Vec<u64>,
}

/// The worst (max) frontier penalty a genome suffers across `archive` — assumes the [`Learned`]
/// override is already set to that genome.
fn worst_over_archive(env: AdvEnv, bytes: usize, archive: &[AdvTrace]) -> u64 {
    archive
        .iter()
        .map(|t| adv_single_cost(AdvObjective::FrontierPenalty, &env, &run_adversarial(env, *t, bytes, CcKind::Learned)))
        .max()
        .unwrap_or(0)
}

/// **Co-evolve a controller against an adversary that attacks it** (the CEGIS / minimax loop). Each
/// round: (1) the CEM re-synthesises the [`Learned`] genome to minimise its *worst-case* frontier
/// penalty over the current adversarial archive (warm-started from the previous champion); (2) the
/// adversary searches for the capacity trace that maximally hurts the new champion; (3) if that trace
/// is materially worse than anything in the archive, it is added (a fresh counterexample) — otherwise
/// the adversary has stopped finding new attacks and the loop converges early. Deterministic in `seed`.
/// Returns the report and the final archive (the certificate of attacks the genome withstands).
#[allow(clippy::too_many_arguments)]
pub fn coevolve(
    env: AdvEnv,
    bytes: usize,
    rounds: u32,
    generations: u32,
    pop: usize,
    elite_frac: f64,
    adv_iters: u32,
    seed: u64,
) -> (CoevolveReport, Vec<AdvTrace>) {
    let mut archive: Vec<AdvTrace> = vec![AdvTrace::FLAT];
    let mut champion = LearnedParams::DEFAULT;
    let mut worst_cost_per_round: Vec<u64> = Vec::new();
    let mut rounds_run = 0u32;

    for r in 0..rounds {
        rounds_run = r + 1;
        // (1) Re-synthesise: minimise the worst-case frontier penalty over the archive (so the fitness
        // the CEM *maximises* is its negation). Warm-start from the current champion.
        let arch = archive.clone();
        let (g, _) = evolve_from(champion, generations, pop, elite_frac, seed.wrapping_add((r as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)), |p| {
            set_learned_override(Some(p));
            let worst = worst_over_archive(env, bytes, &arch);
            set_learned_override(None);
            -(worst as f64)
        });
        champion = g;

        // (2) Attack the new champion.
        set_learned_override(Some(champion));
        let attack = adversary_search(CcKind::Learned, AdvObjective::FrontierPenalty, env, bytes, adv_iters, seed.wrapping_add((r as u64).wrapping_mul(0x1234_5678_9ABC_DEF1)).wrapping_add(1));
        let archive_worst = worst_over_archive(env, bytes, &archive);
        set_learned_override(None);
        worst_cost_per_round.push(attack.best_cost);

        // (3) Keep the counterexample only if it materially beats the champion's archive worst case
        // (>10% worse) — otherwise the adversary has run out of new attacks and we have converged.
        if attack.best_cost > archive_worst + archive_worst / 10 {
            archive.push(attack.best_trace);
        } else {
            break;
        }
    }

    let report = CoevolveReport {
        genome: champion.sanitized(),
        archive_size: archive.len(),
        rounds: rounds_run,
        worst_cost_per_round,
    };
    (report, archive)
}

/// The worst frontier penalty a fresh adversarial search can inflict on `genome` (pass `None` for the
/// baked genome) on `env` — the **held-out** robustness measure (a brand-new attack, not one the
/// genome trained against), so it is an honest comparison between controllers.
pub fn worst_under_fresh_attack(genome: Option<LearnedParams>, env: AdvEnv, bytes: usize, adv_iters: u32, seed: u64) -> u64 {
    set_learned_override(genome);
    let attack = adversary_search(CcKind::Learned, AdvObjective::FrontierPenalty, env, bytes, adv_iters, seed);
    set_learned_override(None);
    attack.best_cost
}

// ── the adversary as a prover: a bounded performance certificate ──────────────────────────────────
//
// The adversary above *samples* the trace space for a bad case; the bmc *exhausts* an op-sequence space
// to prove a safety invariant. This fuses the two: **exhaust a bounded slice of the capacity-trace space
// and take the worst, turning the adversary into a prover.** The envelope is every `n_slices`-periodic
// schedule over `n_levels` evenly-spaced capacity levels (tiled across the 16-slice trace); the returned
// bound is the MAX of a chosen cost (mean or max standing queue) over *all* of them — a sound worst-case
// **performance** bound *for that discretised, periodic envelope*, the model-checking discipline applied to
// performance, not just safety. It is a *bounded* certificate (over the discretised, periodic envelope),
// exactly as the safety bmc is bounded (small depth/window). Two things give it teeth beyond "we tried a
// lot of traces". First, it **discriminates** controllers — a robust controller's certified worst-case
// queue is far below a fragile one's. Second, along the **`n_slices` (period) axis** the envelopes are
// *nested* — for `n_slices` a divisor of 16 a period-2 pattern *is* a period-4 pattern, so
// envelope(2) ⊆ envelope(4) ⊆ envelope(8) and the bound is monotone non-decreasing — so when it stops
// growing (as it does for controllers whose worst case is a low-period structural pattern, e.g. the
// minimum-rate floor for AIMD/ECN controllers) that is a *real* convergence, not luck. (The `n_levels`
// axis does NOT generally nest — `{30,90,150}` is not a subset of `{30,70,110,150}` — so we vary only
// `n_slices` for the convergence argument.) For a controller whose worst case is a *timing* pattern (BBR),
// the bound is still growing at the checked granularities, so there it is an exhaustive *lower* bound that
// nonetheless beats the sampling adversary. Crucially the certificate is sound only **over its discretised
// periodic envelope**: extending it to a continuum bound would need a monotonicity/Lipschitz argument that
// is *not* proven here — that is the open ceiling.

/// A certified worst-case standing-queue bound from exhausting a discretised capacity-trace envelope.
#[derive(Clone, Copy, Debug)]
pub struct PerfCertificate {
    /// The max over the envelope of the chosen `objective` (mean or max standing queue, µs) — a sound
    /// upper bound on that cost for every trace **in the discretised periodic envelope**.
    pub bound_us: u64,
    /// The envelope trace that attains the bound (always a member of the envelope; replayable bit-for-bit
    /// through [`run_adversarial`]).
    pub worst_trace: AdvTrace,
    /// How many traces were actually exhausted (counted, not inferred — `n_levels ^ n_slices`).
    pub traces_checked: u64,
    pub n_slices: usize,
    pub n_levels: usize,
}

/// The `k`-th of `n_levels` capacity levels, evenly spaced across `[ADV_MIN_PCT, ADV_MAX_PCT]` (percent
/// of the base rate). `n_levels == 1` collapses to the floor. Note the level sets nest (a coarser grid ⊆ a
/// finer one) only when `(coarse-1) | (fine-1)` — e.g. 3 → 5, not 3 → 4 — so the convergence argument
/// varies `n_slices`, not `n_levels`.
fn adv_level(k: usize, n_levels: usize) -> u16 {
    if n_levels <= 1 {
        return ADV_MIN_PCT;
    }
    let span = (ADV_MAX_PCT - ADV_MIN_PCT) as usize;
    ADV_MIN_PCT + (span * k / (n_levels - 1)) as u16
}

/// **Certify a worst-case `objective` bound** for `cc` over the bounded capacity-trace envelope: every
/// `n_slices`-periodic schedule over `n_levels` evenly-spaced capacity levels, tiled across the 16-slice
/// trace (the tiling is exactly `n_slices`-periodic when `n_slices` divides 16 — use 2/4/8, the values the
/// nested-envelope convergence argument relies on). **Exhaustive** — `bound_us` is a sound upper bound on
/// the cost for *any* trace **in that envelope** (not the continuum). Deterministic. For the [`Learned`]
/// controller, install the genome with [`set_learned_override`] first. Cost is `n_levels ^ n_slices`
/// transfers (panics if that overflows `u64` — keep the envelope small; it is a *bounded* certificate).
///
/// Note on what the bound means per objective. For [`AdvObjective::MeanQueueUs`] the worst-case trace is —
/// *empirically, over this envelope* — the minimum-rate one; we do **not** prove that mean queue is monotone
/// in capacity for an adaptive controller, so this is an exhaustive observation, not a structural theorem.
/// The certificate earns its keep on objectives whose worst case is a genuine **timing** pattern — e.g.
/// [`AdvObjective::MaxQueueUs`], where a capacity spike primes the window before a crash — which the
/// minimum-rate trace does not capture.
pub fn certify_worst(cc: CcKind, env: AdvEnv, bytes: usize, n_slices: usize, n_levels: usize, objective: AdvObjective) -> PerfCertificate {
    let n_slices = n_slices.clamp(1, ADV_SLICES);
    let n_levels = n_levels.max(1);
    // Reject an unrepresentable envelope loudly rather than silently truncating an "exhaustive" sweep.
    let total = (n_levels as u64)
        .checked_pow(n_slices as u32)
        .expect("envelope too large to exhaust — keep n_levels^n_slices within u64");
    // Seed the witness with the all-floor trace (idx 0) — always a member of the envelope, so a returned
    // `worst_trace` is a genuine envelope member even if every cost is 0.
    let mut worst_trace = AdvTrace { schedule: [ADV_MIN_PCT; ADV_SLICES] };
    let mut bound_us = 0u64;
    let mut checked = 0u64;
    for idx in 0..total {
        // Decode idx into an n_slices-digit base-n_levels pattern, then tile it across the 16 slices.
        let mut schedule = [100u16; ADV_SLICES];
        let mut pattern = [ADV_MIN_PCT; ADV_SLICES];
        let mut x = idx;
        for p in pattern.iter_mut().take(n_slices) {
            *p = adv_level((x % n_levels as u64) as usize, n_levels);
            x /= n_levels as u64;
        }
        for (i, s) in schedule.iter_mut().enumerate() {
            *s = pattern[i % n_slices];
        }
        let trace = AdvTrace { schedule };
        let cost = adv_single_cost(objective, &env, &run_adversarial(env, trace, bytes, cc));
        if cost > bound_us {
            bound_us = cost;
            worst_trace = trace;
        }
        checked += 1;
    }
    PerfCertificate { bound_us, worst_trace, traces_checked: checked, n_slices, n_levels }
}

// ── verified GP synthesis of the control law (synthesis modulo verification) ───────────────────────
//
// Everything above tunes KNOWN structure. The CEM trainer (`evolve`) moves five gains of a hand-written
// AIMD skeleton; co-evolution makes those gains robust; the adversary/certificate measure a *fixed*
// controller. This last search changes the kind of thing being searched: the control **law** itself, as
// a program. The genome is a `ControlProgram` — three tiny SSA register machines (increase / loss / ecn,
// see `crate::congestion`) — and a genetic search (point mutation + sub-program crossover) explores the
// space of laws. The novelty is the **filter**: before a candidate is ever scored on the network, it is
// driven through the bounded safety checker (`crate::bmc::check_controller_safety`); a program that can
// break the safety envelope on *any* event sequence in the bounded neighbourhood is rejected outright,
// never scored. So the search is confined, by a machine-checked proof, to provably-safe laws — "synthesis
// modulo verification". The fitness of a survivor is the same latency-throughput frontier the CEM trainer
// optimises (`synth_frontier_fitness`), so a discovered law is directly comparable to the hand-tuned and
// gene-tuned controllers on the held-out bottlenecks. The seed is `ControlProgram::AIMD` (≡ DCTCP), which
// is safe and decent, so the search always has a feasible warm start and the central question is sharp:
// does it *move away* from AIMD to a better safe law, or does it stay — "AIMD is a fixed point the search
// keeps returning to" (a heuristic-search observation, not a proof of optimality)?

/// Fitness sentinel for a program the safety filter rejected: below any real frontier fitness (which is a
/// goodput-minus-queue score in roughly `[-5, 1]`), so a rejected law can never be selected.
const SYNTH_REJECT: f64 = -1.0e18;

/// The latency-throughput fitness of a synthesised `prog` over `scenarios` — the same hinge fitness as
/// [`frontier_fitness`] (reward goodput as a fraction of line rate, penalise only the standing queue
/// beyond a 1 ms L4S budget, heavily penalise a non-completing transfer), but run through the [`Synth`]
/// controller (installed via [`set_program_override`]) so it is directly comparable to the gene-tuned
/// [`crate::congestion::Learned`] frontier. Higher is better.
pub fn synth_frontier_fitness(prog: ControlProgram, scenarios: &[TrainScenario]) -> f64 {
    set_program_override(Some(prog));
    let mut total = 0.0;
    for s in scenarios {
        let r = run_bottleneck(s.seed, s.bn, s.bytes, CcKind::Synth);
        let line = s.bn.rate_bytes_per_sec.max(1) as f64;
        let goodput = r.throughput_bytes_per_sec() as f64 / line;
        let q_ms = r.data_queue.mean_queue_us as f64 / 1_000.0;
        let queue_excess = (q_ms - 1.0).max(0.0);
        let complete = if r.completed { 0.0 } else { -5.0 };
        total += goodput - 0.4 * queue_excess + complete;
    }
    set_program_override(None);
    total / scenarios.len().max(1) as f64
}

/// One point mutation repeated `n` times: pick a sub-program, an instruction slot, and one field (op /
/// operand a / operand b) and reroll it. A rerolled operand is drawn in the valid SSA range for its slot
/// (`[0, REGS_IN + slot)`), so a mutation never creates a forward reference. Returns the mutated program.
fn synth_mutate(rng: &mut Rng, mut prog: ControlProgram, n: usize) -> ControlProgram {
    for _ in 0..n.max(1) {
        let which = rng.below(ControlProgram::SUBS as u64) as usize;
        let slot = rng.below(ControlProgram::PROG_LEN as u64) as usize;
        let field = rng.below(3);
        let max_operand = (ControlProgram::REGS_IN + slot) as u64; // valid earlier registers
        let sub = prog.sub_mut(which);
        let cur = sub[slot];
        sub[slot] = match field {
            0 => Instr::new(SynthOp::ALL[rng.below(SynthOp::ALL.len() as u64) as usize], cur.a, cur.b),
            1 => Instr::new(cur.op, rng.below(max_operand) as u8, cur.b),
            _ => Instr::new(cur.op, cur.a, rng.below(max_operand) as u8),
        };
    }
    prog
}

/// Sub-program-level crossover: the child takes each of the three response laws (increase / loss / ecn)
/// from one parent or the other, uniformly — so the search can recombine, e.g., one parent's loss
/// response with another's ECN response.
fn synth_crossover(rng: &mut Rng, a: ControlProgram, b: ControlProgram) -> ControlProgram {
    let mut child = a;
    for which in 0..ControlProgram::SUBS {
        if rng.below(2) == 1 {
            *child.sub_mut(which) = *b.sub(which);
        }
    }
    child
}

/// What a control-law search found.
#[derive(Clone, Copy, Debug)]
pub struct SynthReport {
    /// The best **safe** program found (its safety is re-confirmable with `check_controller_safety`).
    pub best: ControlProgram,
    /// Its frontier fitness (the same scale as [`synth_frontier_fitness`]).
    pub best_fit: f64,
    /// The fitness of the [`ControlProgram::AIMD`] seed on the same training set — the "did it beat the
    /// hand-written law?" reference.
    pub seed_fit: f64,
    /// How many candidate programs the bmc safety filter rejected over the whole run (the filter's work).
    pub rejected: u64,
    /// How many distinct candidates were evaluated (mutated/crossed children, excluding carried elites).
    pub evaluated: u64,
}

/// **Synthesise a congestion-control law** by genetic search under the bmc safety filter. Starting from
/// the safe [`ControlProgram::AIMD`] seed, each generation keeps the top `elite` by fitness and breeds the
/// rest by crossover + mutation; **every** candidate is first run through
/// [`crate::bmc::check_controller_safety`] at depth `bmc_depth`, and one with any violation is rejected
/// (fitness [`SYNTH_REJECT`]) before it is ever scored on the network — so the returned `best` is, by a
/// bounded machine-checked proof, inside the safety envelope. Scoring is [`synth_frontier_fitness`] on
/// `train`. Deterministic in `seed`. This is the heavy search; the fast machinery test uses a small budget.
pub fn evolve_control_law(
    train: &[TrainScenario],
    generations: u32,
    pop: usize,
    elite: usize,
    mss: u16,
    bmc_depth: u32,
    seed: u64,
) -> SynthReport {
    let mut rng = Rng::new(seed ^ 0x5717_C0DE_5717_C0DE);
    let mut rejected = 0u64;
    let mut evaluated = 0u64;
    // The verified filter, then the network score — cheap rejects never pay for an expensive sim.
    let eval = |prog: ControlProgram, rejected: &mut u64, evaluated: &mut u64| -> f64 {
        *evaluated += 1;
        let report = crate::bmc::check_controller_safety(Synth::with_program(mss, prog), mss as u32, bmc_depth);
        if report.violations > 0 {
            *rejected += 1;
            return SYNTH_REJECT;
        }
        synth_frontier_fitness(prog, train)
    };

    let seed_fit = eval(ControlProgram::AIMD, &mut rejected, &mut evaluated);
    let mut population: Vec<(ControlProgram, f64)> = vec![(ControlProgram::AIMD, seed_fit)];
    while population.len() < pop.max(1) {
        let muts = 1 + rng.below(3) as usize;
        let child = synth_mutate(&mut rng, ControlProgram::AIMD, muts);
        let fit = eval(child, &mut rejected, &mut evaluated);
        population.push((child, fit));
    }
    let mut best = population[0];
    for &cand in &population {
        if cand.1 > best.1 {
            best = cand;
        }
    }

    let n_elite = elite.clamp(1, pop.max(1));
    for _ in 0..generations {
        population.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        let elites: Vec<ControlProgram> = population[..n_elite.min(population.len())].iter().map(|&(p, _)| p).collect();
        let mut next: Vec<(ControlProgram, f64)> = population[..n_elite.min(population.len())].to_vec();
        while next.len() < pop.max(1) {
            let pa = elites[rng.below(elites.len() as u64) as usize];
            let pb = elites[rng.below(elites.len() as u64) as usize];
            let crossed = synth_crossover(&mut rng, pa, pb);
            let muts = 1 + rng.below(3) as usize;
            let child = synth_mutate(&mut rng, crossed, muts);
            let fit = eval(child, &mut rejected, &mut evaluated);
            if fit > best.1 {
                best = (child, fit);
            }
            next.push((child, fit));
        }
        population = next;
    }

    SynthReport { best: best.0, best_fit: best.1, seed_fit, rejected, evaluated }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cemark_bn(rate: u64, base_us: u64, thr: u64) -> Bottleneck {
        Bottleneck { rate_bytes_per_sec: rate, buffer_bytes: 512 * 1024, base_delay_us: base_us, aqm: Aqm::CeMark { threshold_us: thr } }
    }

    fn train_set() -> Vec<TrainScenario> {
        // A spread of CE-marking bottlenecks: varied rate, base RTT, and marking threshold.
        [
            (2_500_000u64, 2_000u64, 1_000u64),
            (5_000_000, 1_000, 800),
            (1_250_000, 4_000, 1_500),
            (4_000_000, 1_500, 900),
            (1_800_000, 3_000, 1_200),
        ]
        .iter()
        .map(|&(r, b, t)| TrainScenario { bn: cemark_bn(r, b, t), bytes: 1024 * 1024, seed: 7 })
        .collect()
    }

    fn heldout_set() -> Vec<TrainScenario> {
        // UNSEEN bottlenecks — different rate/RTT/threshold than the training set.
        [
            (3_500_000u64, 1_700u64, 1_100u64),
            (2_000_000, 2_500, 700),
            (6_000_000, 800, 1_000),
            (1_000_000, 5_000, 1_400),
        ]
        .iter()
        .map(|&(r, b, t)| TrainScenario { bn: cemark_bn(r, b, t), bytes: 1024 * 1024, seed: 11 })
        .collect()
    }

    fn frontier_of(cc: CcKind, params: Option<LearnedParams>, set: &[TrainScenario]) -> (f64, f64) {
        set_learned_override(params);
        let (mut g, mut q) = (0.0, 0.0);
        for s in set {
            let r = run_bottleneck(s.seed, s.bn, s.bytes, cc);
            g += r.throughput_bytes_per_sec() as f64 / s.bn.rate_bytes_per_sec as f64;
            q += r.data_queue.mean_queue_us as f64;
        }
        set_learned_override(None);
        (g / set.len() as f64, q / set.len() as f64)
    }

    /// The (goodput, mean-queue) frontier of a synthesised law over `set` — the caller installs the
    /// program with [`set_program_override`] first (mirroring how `frontier_of` takes a `LearnedParams`).
    fn synth_frontier_of(set: &[TrainScenario]) -> (f64, f64) {
        let (mut g, mut q) = (0.0, 0.0);
        for s in set {
            let r = run_bottleneck(s.seed, s.bn, s.bytes, CcKind::Synth);
            g += r.throughput_bytes_per_sec() as f64 / s.bn.rate_bytes_per_sec as f64;
            q += r.data_queue.mean_queue_us as f64;
        }
        (g / set.len() as f64, q / set.len() as f64)
    }

    /// Reproduce the baked genome from scratch and print the full frontier (ignored — the evolution
    /// runs hundreds of sims). `evolve(&train_set(), 30, 28, 0.25, 12345)` is exactly what produced
    /// [`LearnedParams::BAKED`]; `learned-baked` and `learned-best` should land the same frontier.
    #[test]
    #[ignore]
    fn evolve_feasibility() {
        let train = train_set();
        let (best, fit) = evolve(&train, 30, 28, 0.25, 12345);
        eprintln!("EVOLVED genome {best:?}  train-fitness {fit:.3}");
        let test = heldout_set();
        for &(name, cc, params) in &[("reno", CcKind::Reno, None), ("bbr", CcKind::Bbr, None), ("dctcp", CcKind::Dctcp, None), ("learned-baked", CcKind::Learned, None), ("learned-best", CcKind::Learned, Some(best))] {
            let (g, q) = frontier_of(cc, params, &test);
            eprintln!("  {name:>14}: goodput {g:.2}x line | mean queue {q:.0} us");
        }
    }

    /// THE EVOLVED CONTROLLER (zero ML deps). On **held-out** CE-marking bottlenecks it never trained
    /// on, the baked `Learned` genome lands a distinctly better low-latency frontier point than the
    /// hand-tuned controllers: it recovers a large slice of the throughput DCTCP's fixed aggressive
    /// response throws away, while holding a queue an order of magnitude below BBR's and ~100× below
    /// Reno's. Deterministic — the genome is a constant, the scenarios fixed.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn learned_controller_beats_dctcp_on_the_held_out_frontier() {
        let test = heldout_set();
        let (_, reno_q) = frontier_of(CcKind::Reno, None, &test);
        let (_, bbr_q) = frontier_of(CcKind::Bbr, None, &test);
        let (dctcp_g, _) = frontier_of(CcKind::Dctcp, None, &test);
        let (learned_g, learned_q) = frontier_of(CcKind::Learned, None, &test); // baked genome

        // It recovers materially more throughput than DCTCP (the other low-latency controller)...
        assert!(
            learned_g > dctcp_g * 1.15,
            "learned recovers throughput DCTCP sacrifices: learned {learned_g:.2}x vs dctcp {dctcp_g:.2}x"
        );
        // ...while still holding a low (≈ sub-ms-class) standing queue — far below BBR and Reno.
        assert!(learned_q < 2_000.0, "learned holds a low queue: {learned_q:.0} us");
        assert!(learned_q * 3.0 < bbr_q, "learned ≪ BBR queue: {learned_q:.0} us vs {bbr_q:.0} us");
        assert!(learned_q * 10.0 < reno_q, "learned ≪ Reno queue: {learned_q:.0} us vs {reno_q:.0} us");
        // sanity: the bufferbloat ladder still holds for the hand-tuned controllers.
        assert!(bbr_q < reno_q, "bbr {bbr_q:.0} < reno {reno_q:.0}");
    }

    /// The CEM trainer is a working optimizer: a short campaign improves the fitness over the default
    /// genome and yields a sanitized, finite-fitness result. Small budget + a two-bottleneck training
    /// set keeps it quick; the full reproduction lives in the ignored `evolve_feasibility`.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn cem_trainer_improves_over_the_default_genome() {
        let train = vec![
            TrainScenario { bn: cemark_bn(2_500_000, 2_000, 1_000), bytes: 1024 * 1024, seed: 7 },
            TrainScenario { bn: cemark_bn(1_800_000, 3_000, 1_200), bytes: 1024 * 1024, seed: 7 },
        ];
        let default_fit = frontier_fitness(LearnedParams::DEFAULT, &train);
        let (best, best_fit) = evolve(&train, 6, 6, 0.34, 4242);
        assert!(best_fit.is_finite(), "fitness must be finite");
        assert!(best_fit > default_fit, "evolution must improve on the default: {best_fit:.3} vs {default_fit:.3}");
        // the returned genome is within the controller's valid envelope (sanitized).
        assert_eq!(best, best.sanitized(), "the best genome is sanitized");
    }

    /// **The GP-synthesis machinery, end to end (fast).** A short control-law search must: (1) actually
    /// engage the verifier — a free GP over the program space proposes unsafe laws, so the bmc filter
    /// rejects a positive number of them; (2) return a real, scored law (not a reject sentinel) whose
    /// fitness is the run-wide maximum over every evaluated candidate including the AIMD seed, hence never
    /// below it; and (3) yield a winner that **generalises past the filter's bound** — the search filters
    /// at depth 4, and we re-certify the winner at a strictly *deeper* depth 5, so this is a genuine
    /// (non-tautological) generalisation check, not a replay of the selecting check. This is the
    /// deterministic CI proof that "synthesis modulo verification" works; the full search that asks whether
    /// it finds a *new* law lives in the ignored `synth_control_law_derisk`.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn synth_search_finds_a_safe_law_no_worse_than_aimd() {
        let train = vec![
            TrainScenario { bn: cemark_bn(2_500_000, 2_000, 1_000), bytes: 1024 * 1024, seed: 7 },
            TrainScenario { bn: cemark_bn(1_800_000, 3_000, 1_200), bytes: 1024 * 1024, seed: 7 },
        ];
        let r = evolve_control_law(&train, 5, 8, 3, 1460, 4, 0x5A5A_1234);
        assert!(r.rejected > 0, "the bmc filter rejected nothing — it is not engaged: {r:?}");
        assert!(r.evaluated > 8, "the generation loop must actually run (more than one population): {r:?}");
        assert!(
            r.best_fit.is_finite() && r.best_fit > SYNTH_REJECT / 2.0,
            "best must be a real, scored law (not a reject sentinel): {r:?}"
        );
        // best is the run-wide max over all evaluated candidates (the seed included), so it is never below it.
        assert!(r.best_fit >= r.seed_fit - 1e-9, "the returned best is never below the AIMD seed it warm-starts from: {r:?}");
        // Re-certify at depth 5 — strictly deeper than the depth-4 filter that selected it, so a winner that
        // happened to be safe only up to depth 4 would be caught here. (NOT a replay of the selecting check.)
        let safety = crate::bmc::check_controller_safety(Synth::with_program(1460, r.best), 1460, 5);
        assert_eq!(
            safety.violations, 0,
            "the synthesised winner stays safe one bound deeper than the filter: {:?}",
            safety.first_violation
        );
    }

    /// The control-law search is a **pure function of its seed**: two runs with the same arguments return
    /// the identical genome and fitness, bit-for-bit. This is the determinism the de-risk's reproducibility
    /// rests on (it is what let the Windows-discovered `BAKED_SYNTH` reappear unchanged on the Linux VPS);
    /// the cross-*platform* bit-identity is an observation, this in-process replay is the CI-enforced part.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn synth_search_is_deterministic_in_its_seed() {
        let train = vec![TrainScenario { bn: cemark_bn(2_500_000, 2_000, 1_000), bytes: 256 * 1024, seed: 7 }];
        let a = evolve_control_law(&train, 2, 4, 2, 1460, 3, 0xD37E_8717);
        let b = evolve_control_law(&train, 2, 4, 2, 1460, 3, 0xD37E_8717);
        assert_eq!(a.best, b.best, "same seed must yield the identical genome");
        assert_eq!(a.best_fit.to_bits(), b.best_fit.to_bits(), "...and the identical fitness, bit-for-bit");
        assert_eq!(a.rejected, b.rejected, "...and the identical filter-rejection count");
    }

    /// **The synthesised law, headline result (fast — uses the baked discovery, no search).** Stated
    /// precisely, because the win is metric-specific and NOT a Pareto win. The law the GP found under the
    /// bmc filter ([`ControlProgram::BAKED_SYNTH`]) is, on the **held-out** bottlenecks: (1) machine-checked
    /// safe at depth 4; (2) the top of the **latency-throughput hinge fitness it was bred for** (goodput
    /// minus a queue penalty past a 1 ms L4S budget) over *every hand-tuned* controller — but this is
    /// because the loss-based controllers bury themselves in ~90 ms of standing queue: on **raw goodput**
    /// synth *loses* to Reno/CUBIC/BBR and only out-goodputs DCTCP/Prague (so it Pareto-dominates none — it
    /// trades goodput for a far lower queue); and (3) it loses to the *gene-tuned* `Learned` on **both**
    /// axes. That gap is the de-risk's honest verdict made machine-checked: the discrete grammar rediscovers
    /// DCTCP's `α/2` ECN response and cannot reach `Learned`'s finer `≈ α·0.185` gain — program-GP wins on
    /// *structure* + *safety-by-construction*, loses to continuous gene-tuning on fine constants.
    /// Deterministic (a baked genome, fixed scenarios).
    #[test]
    #[cfg_attr(miri, ignore)]
    fn synthesised_law_tops_the_queue_penalised_fitness_not_raw_goodput() {
        use crate::congestion::ControlProgram;
        let test = heldout_set();
        // The exact hinge fitness the search optimises (see `synth_frontier_fitness`): goodput, minus
        // 0.4 per ms of standing queue beyond a 1 ms L4S budget. This is the axis synth wins on.
        let hinge = |g: f64, q_us: f64| g - 0.4 * (q_us / 1_000.0 - 1.0).max(0.0);

        // (1) verified safe — the synthesis guarantee, on the shipped depth-4 bound.
        let safety = crate::bmc::check_controller_safety(Synth::with_program(1460, ControlProgram::BAKED_SYNTH), 1460, 4);
        assert_eq!(safety.violations, 0, "the synthesised law must be machine-checked safe: {:?}", safety.first_violation);

        set_program_override(Some(ControlProgram::BAKED_SYNTH));
        let (synth_g, synth_q) = synth_frontier_of(&test);
        set_program_override(None);
        let synth_h = hinge(synth_g, synth_q);

        // (2) under the hinge fitness it was bred for, synth tops *every hand-tuned* controller — but only
        // because the loss-based ones drown in standing queue; assert the ranking AND the mechanism.
        let (reno_g, reno_q) = frontier_of(CcKind::Reno, None, &test);
        for &(name, cc) in &[("reno", CcKind::Reno), ("cubic", CcKind::Cubic), ("bbr", CcKind::Bbr), ("dctcp", CcKind::Dctcp), ("prague", CcKind::Prague)] {
            let (g, q) = frontier_of(cc, None, &test);
            assert!(synth_h > hinge(g, q), "synth tops the hinge fitness vs {name}: {synth_h:.2} vs {:.2}", hinge(g, q));
        }

        // (2b) HONESTLY: on raw goodput synth is NOT the best — it loses to the loss-based controllers and
        // only out-goodputs DCTCP/Prague, buying that with a far lower queue (it Pareto-dominates none).
        assert!(synth_g < reno_g, "synth LOSES raw goodput to loss-based Reno (the honest caveat): {synth_g:.2}x vs {reno_g:.2}x");
        let (dctcp_g, _) = frontier_of(CcKind::Dctcp, None, &test);
        assert!(synth_g > dctcp_g * 1.05, "...but out-goodputs DCTCP at a sub-ms queue: {synth_g:.2}x vs {dctcp_g:.2}x");
        assert!(synth_q < 2_000.0 && synth_q * 10.0 < reno_q, "synth holds a sub-ms-class queue ≪ Reno's: {synth_q:.0} us vs {reno_q:.0} us");

        // (3) and it loses to the gene-tuned Learned on BOTH axes — the characterised constant-resolution gap.
        let (learned_g, learned_q) = frontier_of(CcKind::Learned, None, &test);
        assert!(synth_g < learned_g, "synth loses goodput to the gene-tuner Learned (expected): {synth_g:.2}x vs {learned_g:.2}x");
        assert!(synth_h < hinge(learned_g, learned_q), "...and loses to Learned on the hinge too: {synth_h:.2} vs {:.2}", hinge(learned_g, learned_q));
    }

    /// **The de-risk (ignored — runs the full search over hundreds of sims).** Synthesise a control law
    /// from scratch under the bmc filter, decompile it to readable expressions, re-certify it safe at
    /// depth 4, and print its held-out frontier against every hand-tuned and gene-tuned controller. The
    /// headline question this answers: does GP discover a stable *new* safe law that beats the others, or
    /// rediscover AIMD (a sharp result either way)? Run with `cargo test -p tcp-core synth_control_law_derisk -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn synth_control_law_derisk() {
        let train = train_set();
        let r = evolve_control_law(&train, 24, 28, 7, 1460, 4, 0x00C0_FFEE_5717);
        let (inc, md, ecn) = crate::congestion::synth_describe(&r.best);
        eprintln!("SYNTHESISED control law  (train-fitness {:.3}, AIMD-seed {:.3})", r.best_fit, r.seed_fit);
        eprintln!("  evaluated {} candidates; bmc rejected {} as unsafe", r.evaluated, r.rejected);
        eprintln!("  increase: step (seg/RTT) = {inc}");
        eprintln!("  loss:     cwnd (seg)     = {md}");
        eprintln!("  ecn:      cut            = {ecn}");
        eprintln!("  genome = {:?}", r.best);
        let safety = crate::bmc::check_controller_safety(Synth::with_program(1460, r.best), 1460, 4);
        eprintln!("  bmc(depth 4): {} cases, {} violations", safety.cases, safety.violations);

        let test = heldout_set();
        set_program_override(Some(r.best));
        let (sg, sq) = synth_frontier_of(&test);
        set_program_override(None);
        eprintln!("HELD-OUT frontier (unseen bottlenecks):");
        eprintln!("  {:>14}: goodput {sg:.2}x line | mean queue {sq:.0} us", "synth");
        for &(name, cc) in &[
            ("reno", CcKind::Reno),
            ("cubic", CcKind::Cubic),
            ("bbr", CcKind::Bbr),
            ("dctcp", CcKind::Dctcp),
            ("prague", CcKind::Prague),
            ("learned-baked", CcKind::Learned),
        ] {
            let (g, q) = frontier_of(cc, None, &test);
            eprintln!("  {name:>14}: goodput {g:.2}x line | mean queue {q:.0} us");
        }
    }

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

    /// Coverage feedback earns its keep on the **depth-stratified event sequences** within recovery,
    /// not on breadth. Every event is bucketed by how deep into recovery it occurs (retransmit /
    /// dup-ACK streak length), so the coverage map distinguishes a large space of recovery sequences;
    /// steering the budget toward the corpus members already in recovery reaches more of those
    /// sequences than a uniform-random sampler does at the same budget. (Random reaches the same
    /// recovery *depths* and samples configs more broadly, so neither strictly dominates *total*
    /// coverage — the point is the guided-only behaviour, the sequence tail the feedback buys.)
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

    /// TCP Prague (the L4S scalable controller) on the same CE-marking bottleneck: its ECN reaction is
    /// DCTCP's, so it likewise holds a **sub-millisecond** standing queue where loss-based Reno bloats —
    /// end-to-end proof the scalable controller works over the real stack, not just the unit tests.
    /// Prague's distinguishing RTT-independence is exercised by the controller unit tests and the
    /// dual-queue coexistence demo; on this single short-RTT flow it simply rides the shallow CE marks.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn bottleneck_prague_holds_a_sub_millisecond_queue() {
        let bn = Bottleneck { rate_bytes_per_sec: 2_500_000, buffer_bytes: 512 * 1024, base_delay_us: 2_000, aqm: Aqm::CeMark { threshold_us: 1_000 } };
        let bytes = 8 * 1024 * 1024;
        let reno = run_bottleneck(7, bn, bytes, CcKind::Reno);
        let prague = run_bottleneck(7, bn, bytes, CcKind::Prague);
        assert!(reno.completed && prague.completed, "both deliver intact: reno {reno:?} prague {prague:?}");
        // Teeth: the AQM CE-marked Prague's ECT data (without marks it would behave like Reno), and the
        // shallow queue it holds never fills the buffer (pure marking, no tail-drop).
        assert!(prague.data_queue.marked > 0, "the CE-marking AQM must mark Prague's ECT data: {prague:?}");
        assert_eq!(prague.data_queue.dropped, 0, "Prague holds the queue shallow — nothing tail-drops: {prague:?}");
        assert!(prague.data_queue.mean_queue_us < 1_000, "Prague holds a sub-millisecond queue: {} µs", prague.data_queue.mean_queue_us);
        assert!(
            prague.data_queue.mean_queue_us * 10 < reno.data_queue.mean_queue_us,
            "Prague ≪ Reno standing queue: prague {} µs vs reno {} µs",
            prague.data_queue.mean_queue_us,
            reno.data_queue.mean_queue_us
        );
    }

    /// L4S coexistence on a **dual-queue** bottleneck: a Prague (L4S, ECT) flow and a Reno (classic,
    /// Not-ECT) flow share one link, classified by IP ECN into a shallow CE-marked L4S queue and a
    /// deep tail-dropping Classic queue. The headline, robust result: the L4S flow holds a
    /// **sub-millisecond** standing queue while the classic flow bloats to **tens of milliseconds** —
    /// its latency is fully isolated from the classic flow's bufferbloat, on the *same* bottleneck,
    /// which a single shared FIFO cannot do (there the classic flow's bloat is everyone's latency). And
    /// the two flows *coexist* — both complete intact, neither is starved, each takes a substantial
    /// share of the link. (The exact throughput *split* in this simplified model depends on the
    /// buffer/threshold balance — robust throughput *fairness* across RTT and config is what dualPI2's
    /// coupled PI-controller marking law would add, the documented refinement on [`DualQueue`].)
    #[test]
    #[cfg_attr(miri, ignore)]
    fn dualqueue_isolates_l4s_latency_while_both_flows_coexist() {
        let cfg = DualQueue {
            rate_bytes_per_sec: 3_000_000,
            base_delay_us: 2_000,
            l4s_threshold_us: 1_000,
            classic_buffer_bytes: 512 * 1024,
            l4s_buffer_bytes: 256 * 1024,
        };
        let bytes = 3 * 1024 * 1024;
        let (l4s, classic) = run_dualqueue(42, cfg, bytes, CcKind::Prague, CcKind::Reno);

        // Both flows deliver every byte intact — coexistence, not starvation.
        assert!(l4s.completed && classic.completed, "both flows deliver intact: l4s {l4s:?} classic {classic:?}");

        // Teeth: the L4S (ECT) data was CE-marked in the shallow queue; the classic (Not-ECT) data was
        // never marked (it took the deep tail-dropping queue) — ECN classification actually split the
        // two flows into the two class queues.
        assert!(l4s.marked > 0, "the L4S queue CE-marked the Prague flow's ECT data: {l4s:?}");
        assert_eq!(classic.marked, 0, "the classic Not-ECT flow is never CE-marked: {classic:?}");

        // The headline: the L4S flow holds a sub-ms queue, the classic flow bloats by orders of
        // magnitude — full latency isolation on a shared bottleneck.
        assert!(l4s.mean_queue_us < 1_500, "the L4S flow holds a sub-ms queue: {} µs", l4s.mean_queue_us);
        assert!(
            classic.mean_queue_us > 20 * l4s.mean_queue_us,
            "the classic flow's queue dwarfs the L4S flow's (isolation): classic {} µs vs l4s {} µs",
            classic.mean_queue_us,
            l4s.mean_queue_us
        );

        // Coexistence: neither flow is starved — each gets a substantial share of the 3 MB/s link, and
        // neither runs away with it (not a strict 50/50 without the coupling, but the same order).
        let lo = l4s.throughput_bytes_per_sec().min(classic.throughput_bytes_per_sec());
        let hi = l4s.throughput_bytes_per_sec().max(classic.throughput_bytes_per_sec());
        assert!(lo > cfg.rate_bytes_per_sec / 5, "neither flow is starved: l4s {} vs classic {} B/s", l4s.throughput_bytes_per_sec(), classic.throughput_bytes_per_sec());
        assert!(hi < 3 * lo, "neither flow runs away with the link: {hi} vs {lo} B/s");

        // Pin the measured split *direction*, per-flow: the polite L4S flow keeps its queue near-empty,
        // so the round-robin scheduler hands its slack to the classic flow, which therefore finishes
        // **sooner** (its own completion time is shorter). This single check has teeth two ways — it
        // catches a scheduler that strict-prioritises L4S (which flips the split) and a regression that
        // collapses the per-flow completion timing to the shared global end (which would make them equal).
        assert!(
            classic.sim_time_us < l4s.sim_time_us,
            "the classic flow takes the L4S flow's slack and finishes sooner (per-flow timing): classic {} µs vs l4s {} µs",
            classic.sim_time_us,
            l4s.sim_time_us
        );
    }

    /// Prague's loss response is the *classic* Reno fallback (the "be safe with drop-based traffic"
    /// requirement): on the fault link (which never CE-marks) it must be exactly as robust as any other
    /// controller — every byte intact under heavy loss, duplication and reordering.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn dst_prague_is_robust_under_loss() {
        for loss in [1u32, 5, 10] {
            for seed in 0..40u64 {
                let scn = Scenario { seed, link: LinkConfig::lossy(loss), bytes: 32_000, cc: CcKind::Prague };
                let outcome = run(&scn);
                assert!(outcome.is_completed(), "Prague must survive loss: {scn:?} -> {outcome:?}");
            }
        }
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

    /// The evolved `Learned` controller must be as robust as any other under genuine loss: on the fault
    /// link (which never CE-marks) it runs as a loss-based AIMD with its evolved gains, and it must
    /// still deliver every byte intact and terminate — its gains were tuned for queue, never at the
    /// cost of reliability.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn dst_learned_is_robust_under_loss() {
        for loss in [1u32, 5, 10] {
            for seed in 0..40u64 {
                let scn = Scenario { seed, link: LinkConfig::lossy(loss), bytes: 32_000, cc: CcKind::Learned };
                let outcome = run(&scn);
                assert!(outcome.is_completed(), "Learned must survive loss: {scn:?} -> {outcome:?}");
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

    // ── adversarial worst-case discovery ────────────────────────────────────────────────────────────

    /// A bottleneck the adversary may reshape the *capacity* of: a 2.5 MB/s base line, a deep 1 MiB
    /// buffer (room for a queue to bloat before anything tail-drops), a 3 ms one-way delay, and a 6 ms
    /// schedule slice (a few slices per RTT, so a drop can be timed within a controller's probe cycle).
    fn adv_env() -> AdvEnv {
        AdvEnv { base_rate_bytes_per_sec: 2_500_000, buffer_bytes: 1024 * 1024, base_delay_us: 3_000, slice_us: 6_000, aqm: Aqm::TailDrop }
    }

    /// THE ADVERSARY HAS TEETH (the standing-queue lever). Pointed at BBR with the **mean-queue**
    /// objective, the search finds a reproducible capacity profile that bloats BBR's standing queue
    /// **far past** the queue it holds on the steady (full-rate) link. For *this* objective the worst
    /// case is a **sustained throttle** — a low near-constant rate (the search drives toward the
    /// floor), since mean sojourn is maximised by the slowest drain, compounded on a short transfer by
    /// BBR overshooting a link slower than its start-up probe expects. So the cost here is a worse
    /// *operating point*, not a timing trick (the genuine timing pathology is the throughput objective;
    /// see `adversary_breaks_bbr_specifically_on_a_time_varying_trace`). The worst trace replays
    /// bit-for-bit, so it is a concrete artefact, not an anecdote. (Measured: flat ≈ 7.9 ms, guided
    /// ≈ 26–32 ms — 3–4× — and the full 1 MiB reproduction in `adversary_worst_case_report` reaches
    /// ~6×.)
    #[test]
    #[cfg_attr(miri, ignore)] // a search over dozens of full transfers — far too slow for Miri
    fn adversary_finds_a_capacity_profile_that_bloats_bbrs_queue() {
        let env = adv_env();
        let bytes = 192 * 1024;
        let budget = 56;
        let seed = 0xB0A7;
        let report = adversary_search(CcKind::Bbr, AdvObjective::MeanQueueUs, env, bytes, budget, seed);
        let baseline = adversary_random_baseline(CcKind::Bbr, AdvObjective::MeanQueueUs, env, bytes, budget, seed);

        // Survivability oracle (for THIS objective): the mean-queue search never rewards stalling, so
        // every trace still delivers every byte intact. A non-completion here would be a genuine stack
        // bug (a wedge under capacity variation), not an un-survivably-hostile link.
        assert!(report.best_completed, "the worst-case trace must still complete with integrity: {report:?}");
        assert!(baseline.all_completed, "every random trace completes too: {baseline:?}");

        // The search machinery actually operated (the elite corpus filled — the analogue of the
        // fuzzer's corpus-populated guard) and moved the capacity off the flat base line.
        assert!(report.corpus_size >= 8, "the search kept a populated elite corpus: {}", report.corpus_size);
        assert!(report.best_trace.is_varying(), "the worst case moved the capacity off the flat base: {:?}", report.best_trace);

        // The load-bearing teeth: the found worst case bloats BBR's queue far past BOTH its steady
        // full-rate queue AND the average random trace at equal budget (this margin is robust across
        // seeds — guided/flat and guided/random-mean both ≈ 3–4×).
        assert!(
            report.best_cost > report.flat_cost * 2,
            "the adversary bloats BBR's queue well past its steady full-rate queue: worst {} µs vs flat {} µs",
            report.best_cost,
            report.flat_cost
        );
        assert!(
            report.best_cost > baseline.mean_cost * 2,
            "guided worst ≫ the average random trace at equal budget: {} vs mean {}",
            report.best_cost,
            baseline.mean_cost
        );
        // Guidance is at least competitive with blind sampling's *best* at equal budget. (We don't
        // claim it strictly dominates: this 16-slice space is low-dimensional, so blind sampling is a
        // strong baseline — as with the coverage fuzzer, guidance's surer value is the single refined,
        // reproducible artefact. This `>= max` holds at this seed; it is not asserted as a general law.)
        assert!(
            report.best_cost >= baseline.max_cost,
            "guided meets-or-beats blind at this seed/budget: guided {} vs random-max {}",
            report.best_cost,
            baseline.max_cost
        );

        // The whole campaign and the worst trace replay bit-for-bit — a found seed is a complete repro.
        let again = adversary_search(CcKind::Bbr, AdvObjective::MeanQueueUs, env, bytes, budget, seed);
        assert_eq!(report.best_cost, again.best_cost, "the campaign replays to the same worst cost");
        assert!(report.best_trace == again.best_trace, "...and the same worst trace");
        let replay = run_adversarial(env, report.best_trace, bytes, CcKind::Bbr);
        assert_eq!(replay.mean_queue_us, report.best_cost, "the worst trace replays bit-for-bit to its cost");
    }

    /// THE HEADLINE FINDING (CI-verified): a **time-varying** capacity trace the adversary discovered
    /// — `AdvTrace::KNOWN_BBR_BREAKER`, the output of `adversary_search(Bbr, ThroughputShortfall, …)`
    /// reproduced in the ignored report — **collapses BBR's goodput specifically**, while a loss-based
    /// controller on the *same trace* is barely affected. This is the real timing pathology: bandwidth
    /// moving underneath BBR's windowed-max rate estimate drives it into a near-livelock. The asymmetry
    /// (BBR alone suffers) is the proof it is a genuine BBR weakness, not an artefact of the link model
    /// — the link is controller-agnostic, so a controller-specific outcome is the controller's doing.
    /// Baked as a constant (like the evolved genome), so this runs fast and deterministically without
    /// re-running the search.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn adversary_breaks_bbr_specifically_on_a_time_varying_trace() {
        let env = adv_env();
        let trace = AdvTrace::KNOWN_BBR_BREAKER;
        let bytes = 512 * 1024;

        // It is a genuine *time-varying* trace (slices differ), not a flat throttle.
        assert!(trace.time_varies(), "the discovered trace genuinely varies over time: {trace:?}");

        let bbr = run_adversarial(env, trace, bytes, CcKind::Bbr);
        let reno = run_adversarial(env, trace, bytes, CcKind::Reno);
        let cubic = run_adversarial(env, trace, bytes, CcKind::Cubic);
        let dctcp = run_adversarial(env, trace, bytes, CcKind::Dctcp);

        // All deliver intact (the link is survivable for every controller) — BBR's problem is *speed*,
        // not correctness.
        assert!(bbr.completed && reno.completed && cubic.completed && dctcp.completed, "all complete intact: bbr {bbr:?} reno {reno:?}");

        // The collapse is BBR-specific: on the SAME trace BBR's goodput is a fraction of the loss-based
        // controllers' (measured ≈ 6× slower — 168 KB/s vs ~1 MB/s); a 3× gap leaves wide margin.
        assert!(
            bbr.throughput_bytes_per_sec() * 3 < reno.throughput_bytes_per_sec(),
            "BBR's goodput collapses where Reno's does not: bbr {} B/s vs reno {} B/s",
            bbr.throughput_bytes_per_sec(),
            reno.throughput_bytes_per_sec()
        );
        // And it really is BBR-specific, not "loss-based vs scalable": CUBIC and DCTCP also sail through.
        assert!(bbr.throughput_bytes_per_sec() * 3 < cubic.throughput_bytes_per_sec(), "...also far below CUBIC: {} vs {}", bbr.throughput_bytes_per_sec(), cubic.throughput_bytes_per_sec());
        assert!(bbr.throughput_bytes_per_sec() * 3 < dctcp.throughput_bytes_per_sec(), "...and DCTCP: {} vs {}", bbr.throughput_bytes_per_sec(), dctcp.throughput_bytes_per_sec());

        // The loss-based controllers are unaffected enough to roughly hold the line (a clear majority of
        // the 2.5 MB/s base), so the trace isn't simply a slow link for everyone.
        assert!(reno.throughput_bytes_per_sec() > 700_000, "Reno roughly holds the line on the same trace: {} B/s", reno.throughput_bytes_per_sec());

        // Deterministic: the baked trace replays bit-for-bit to the same goodput.
        let again = run_adversarial(env, trace, bytes, CcKind::Bbr);
        assert_eq!(bbr.throughput_bytes_per_sec(), again.throughput_bytes_per_sec(), "replays bit-for-bit");
    }

    /// Correctness cross-check for the new time-varying link: on a **flat** trace (constant base rate)
    /// the adversarial bottleneck must reproduce the same physics the trusted [`run_bottleneck`] testbed
    /// shows — a loss-based controller (Reno) fills the deep buffer (bufferbloat) while paced BBR holds a
    /// far smaller standing queue, both delivering intact with nothing tail-dropped (buffer > receive
    /// window, so Reno is window-limited). This pins the link model: a flat [`AdvTrace`] is just an
    /// ordinary fixed-rate bottleneck, so any bloat the adversary later finds is the *trace's* doing.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn adversarial_bottleneck_matches_known_physics_on_a_flat_trace() {
        let env = adv_env();
        let bytes = 512 * 1024;
        let reno = run_adversarial(env, AdvTrace::FLAT, bytes, CcKind::Reno);
        let bbr = run_adversarial(env, AdvTrace::FLAT, bytes, CcKind::Bbr);
        assert!(reno.completed && bbr.completed, "both deliver intact on the flat link: reno {reno:?} bbr {bbr:?}");
        assert_eq!(reno.dropped, 0, "Reno is window-limited under a buffer > rwnd — pure bufferbloat, no drops: {reno:?}");
        // Measured: bbr ≈ 17.9 ms vs reno ≈ 42.4 ms (2.37×), so `bbr*2 < reno` captures "Reno bloats
        // materially more than paced BBR" with margin (and is deterministic, so it cannot flake).
        assert!(
            bbr.mean_queue_us * 2 < reno.mean_queue_us,
            "paced BBR holds a far smaller standing queue than loss-based Reno: bbr {} µs vs reno {} µs",
            bbr.mean_queue_us,
            reno.mean_queue_us
        );
        // A flat trace does not vary — the reference, by construction.
        assert!(!AdvTrace::FLAT.is_varying() && !AdvTrace::FLAT.time_varies());
    }

    /// The full reproduction (ignored — dozens of 1 MiB searches). Prints, for each controller, the
    /// mean-queue an adversary can inflict vs its flat/random baselines; then the headline
    /// **throughput-collapse** finding: the capacity trace the adversary discovers against BBR drives
    /// BBR's goodput into the floor (a near-livelock that *worsens* with transfer size) while the *same
    /// trace* lets Reno/CUBIC/DCTCP complete at ~1 MB/s — a BBR-specific pathology under variable
    /// capacity, found automatically and replayable bit-for-bit. (`done=false` is a budget timeout, not
    /// an integrity violation: BBR makes 90 %+ progress then crawls.)
    #[test]
    #[ignore]
    fn adversary_worst_case_report() {
        let env = adv_env();
        let mib = 1024 * 1024;
        let budget = 160;

        eprintln!("== mean standing queue (µs) an adversary can inflict, 1 MiB, budget {budget} ==");
        let bbr_q = adversary_search(CcKind::Bbr, AdvObjective::MeanQueueUs, env, mib, budget, 0xB0A7);
        for cc in [CcKind::Bbr, CcKind::Reno, CcKind::Cubic, CcKind::Dctcp, CcKind::Prague, CcKind::Learned] {
            let g = adversary_search(cc, AdvObjective::MeanQueueUs, env, mib, budget, 0xB0A7);
            let b = adversary_random_baseline(cc, AdvObjective::MeanQueueUs, env, mib, budget, 0xB0A7);
            eprintln!(
                "  {cc:>8?}: flat {:>7} | random mean {:>7} max {:>7} | GUIDED {:>7}  ({:.1}× flat)",
                g.flat_cost, b.mean_cost, b.max_cost, g.best_cost, g.best_cost as f64 / g.flat_cost.max(1) as f64
            );
        }
        // Guard the headline number so a regression that weakened it fails loudly (not just prints low).
        assert!(bbr_q.best_cost > bbr_q.flat_cost * 5, "BBR mean queue bloats >5× flat: {} vs {}", bbr_q.best_cost, bbr_q.flat_cost);

        eprintln!("== the trace that breaks BBR (throughput-shortfall objective) ==");
        let g = adversary_search(CcKind::Bbr, AdvObjective::ThroughputShortfall, env, mib, budget, 0xCAFE);
        eprintln!("  worst trace {:?}  (BBR completed: {})", g.best_trace, g.best_completed);
        let mut bbr_gp = 0u64;
        let mut reno_gp = 0u64;
        for cc in [CcKind::Bbr, CcKind::Reno, CcKind::Cubic, CcKind::Dctcp] {
            let r = run_adversarial(env, g.best_trace, mib, cc);
            if cc == CcKind::Bbr { bbr_gp = r.throughput_bytes_per_sec(); }
            if cc == CcKind::Reno { reno_gp = r.throughput_bytes_per_sec(); }
            eprintln!(
                "  {cc:>8?} on that trace: completed {:>5} | {:>4} s sim | goodput {:>8} B/s",
                r.completed, r.sim_time_us / 1_000_000, r.throughput_bytes_per_sec()
            );
        }
        // Guard the asymmetry: BBR's goodput on its worst trace is far below Reno's on the same trace.
        assert!(bbr_gp * 10 < reno_gp, "BBR goodput collapses where Reno's holds: bbr {bbr_gp} vs reno {reno_gp} B/s");
    }

    fn coev_env() -> AdvEnv {
        AdvEnv { base_rate_bytes_per_sec: 2_500_000, buffer_bytes: 512 * 1024, base_delay_us: 2_000, slice_us: 4_000, aqm: Aqm::CeMark { threshold_us: 1_000 } }
    }

    fn flat_penalty(genome: Option<LearnedParams>, env: AdvEnv, bytes: usize) -> u64 {
        set_learned_override(genome);
        let r = run_adversarial(env, AdvTrace::FLAT, bytes, CcKind::Learned);
        set_learned_override(None);
        adv_single_cost(AdvObjective::FrontierPenalty, &env, &r)
    }

    /// THE CEGIS LOOP CLOSES — co-evolution synthesises a controller that is **safe by construction and
    /// empirically robust to a held-out attack**, on the real stack engine. The loop alternates synthesis
    /// (CEM) and attack (the adversary), accumulating an archive of counterexample traces and
    /// re-synthesising against the worst case. The synthesised controller is then measured on a **held-out
    /// fresh attack** (a brand-new adversarial search it never trained on): it resists it better than its
    /// own warm start *and* better than the average-optimal baked `Learned` genome. It is **safe by
    /// construction** — sanitised into the bounded-proven envelope, so `bmc::check_controller_safety`
    /// finds zero violations. (Measured: ~1.5–2.4× more robust than baked at full budget; the trade-off —
    /// it is more conservative, so it pays average-case throughput — is the honest robustness/performance
    /// Pareto, shown in the ignored `coevolution_reproduction`.)
    #[test]
    #[cfg_attr(miri, ignore)] // a synthesis loop over many full transfers — far too slow for Miri
    fn coevolution_synthesises_a_robust_certified_controller() {
        let env = coev_env();
        let bytes = 256 * 1024;
        let (rep, _archive) = coevolve(env, bytes, 4, 5, 6, 0.3, 30, 0xC0E0);

        // The loop actually ran and accumulated counterexamples beyond the flat seed (smoke check).
        assert!(rep.rounds >= 2 && rep.archive_size >= 2, "the loop ran and collected counterexamples: {rep:?}");

        let robust_worst = worst_under_fresh_attack(Some(rep.genome), env, bytes, 40, 0xFEED);

        // TEETH — co-evolution actually *did something*: the synthesised controller resists a held-out
        // fresh attack better than its own **warm start** (the `DEFAULT` genome the loop began from). A
        // broken loop that returned ~its start would fail this — unlike a comparison against the baked
        // genome alone, which `DEFAULT` already clears (the average-optimal baked genome is itself
        // fragile to capacity variation, so beating *it* does not prove the loop synthesised anything).
        let default_worst = worst_under_fresh_attack(Some(crate::congestion::LearnedParams::DEFAULT), env, bytes, 40, 0xFEED);
        assert!(robust_worst < default_worst, "co-evolution improved over its warm start: {robust_worst} vs default {default_worst}");

        // ...and it is materially more robust than the average-optimal baked controller, on the held-out attack.
        let baked_worst = worst_under_fresh_attack(None, env, bytes, 40, 0xFEED);
        assert!(
            robust_worst * 4 < baked_worst * 3,
            "the co-evolved controller resists a held-out attack far better than baked: {robust_worst} vs {baked_worst}"
        );

        // Convergence: the adversary's best attack at the LAST round is materially below the FIRST
        // round's — the controller is closing the gaps the adversary keeps probing (tolerant of the
        // usual round-to-round wobble; it checks the trend, not strict monotonicity).
        let w = &rep.worst_cost_per_round;
        assert!(w.len() >= 2 && *w.last().unwrap() * 4 < w[0] * 3, "the adversary's reach shrinks across rounds: {w:?}");

        // Safe *by construction*: the synthesised genome is sanitised into the bounded-proven genome
        // envelope (the family `check_learned_genome_space` certifies), so the model checker finds none.
        let safety = crate::bmc::check_controller_safety(crate::congestion::Learned::with_params(1460, rep.genome), 1460, 3);
        assert_eq!(safety.violations, 0, "the synthesised controller is bounded-safe: {safety:?}");

        // Determinism: the *exact same* run replays to the same controller, bit-for-bit.
        let (again, _) = coevolve(env, bytes, 4, 5, 6, 0.3, 30, 0xC0E0);
        assert_eq!(rep.genome, again.genome, "co-evolution replays to the same controller");
    }

    /// The full reproduction (ignored — a multi-seed synthesis sweep). Prints, per seed, the
    /// convergence of the adversary's best attack, the held-out robustness vs the baked genome, the
    /// average-case (flat-path) trade-off, and the BMC safety certificate.
    #[test]
    #[ignore]
    fn coevolution_reproduction() {
        let env = coev_env();
        let bytes = 256 * 1024;
        let baked_worst = worst_under_fresh_attack(None, env, bytes, 60, 0xFEED);
        eprintln!("baked (average-optimal): held-out worst {} | flat penalty {}", baked_worst, flat_penalty(None, env, bytes));
        for seed in [0xC0E0u64, 0x1357, 0xABCD] {
            let (rep, _archive) = coevolve(env, bytes, 6, 6, 8, 0.3, 40, seed);
            let robust_worst = worst_under_fresh_attack(Some(rep.genome), env, bytes, 60, 0xFEED);
            let safety = crate::bmc::check_controller_safety(crate::congestion::Learned::with_params(1460, rep.genome), 1460, 4);
            eprintln!(
                "seed {seed:#x}: rounds {} archive {} adv/round {:?} | held-out worst {} ({:.0}% of baked) | flat {} | BMC violations {} | {:?}",
                rep.rounds, rep.archive_size, rep.worst_cost_per_round, robust_worst,
                100.0 * robust_worst as f64 / baked_worst.max(1) as f64, flat_penalty(Some(rep.genome), env, bytes), safety.violations, rep.genome
            );
        }
    }

    /// A BOUNDED PERFORMANCE CERTIFICATE that **discriminates controllers**: by exhausting the
    /// discretised capacity-trace envelope we certify each controller's worst-case standing queue, and
    /// the ECN-reactive scalable controller (Prague) has a worst-case latency *far* below the loss-based
    /// one (Reno). For these controllers the worst case is — *over this envelope* — the minimum-rate trace,
    /// and the bound has **converged**: a coarser (nested) `n_slices` envelope already certifies the same
    /// number, so the exhaustion found nothing worse at finer period granularity. (The bound is sound over
    /// the discretised periodic envelope; we do not claim it is the continuum worst case — that would need
    /// an unproven monotonicity argument.)
    #[test]
    #[cfg_attr(miri, ignore)] // exhausts dozens of full transfers — far too slow for Miri
    fn certified_worst_case_latency_discriminates_controllers() {
        let env = coev_env();
        let bytes = 192 * 1024;
        // Exhaustive worst-case mean standing queue over the n=4, 3-level (81-trace) envelope.
        let prague = certify_worst(CcKind::Prague, env, bytes, 4, 3, AdvObjective::MeanQueueUs);
        let reno = certify_worst(CcKind::Reno, env, bytes, 4, 3, AdvObjective::MeanQueueUs);
        assert!(prague.traces_checked == 81 && reno.traces_checked == 81, "exhausted the 81-trace envelope");

        // The scalable ECN controller's certified worst-case queue is far below the loss-based one's.
        assert!(
            prague.bound_us * 4 < reno.bound_us,
            "Prague's certified worst-case queue is far below Reno's: {} µs vs {} µs",
            prague.bound_us, reno.bound_us
        );

        // ANCHOR the bound to the structural floor: the certified-worst trace is the all-minimum-rate one
        // (every slice at the 30% floor), NOT the flat-100% baseline — so a certifier that merely returned
        // the flat-trace cost (no exhaustion) would fail here, and the bound is genuinely the floor's queue.
        let floor = certify_worst(CcKind::Reno, env, bytes, 1, 1, AdvObjective::MeanQueueUs); // the all-floor trace alone
        assert!(reno.worst_trace.schedule().iter().all(|&p| p == ADV_MIN_PCT), "Reno's worst trace is the all-floor one: {:?}", reno.worst_trace);
        assert_eq!(reno.bound_us, floor.bound_us, "Reno's certified bound is the floor-rate queue, not the flat baseline");
        assert!(!reno.worst_trace.time_varies(), "...the structural floor, not a timing pattern");

        // The bound has CONVERGED across nested period granularities (n=2 ⊆ n=4): the same number.
        let prague2 = certify_worst(CcKind::Prague, env, bytes, 2, 3, AdvObjective::MeanQueueUs);
        let reno2 = certify_worst(CcKind::Reno, env, bytes, 2, 3, AdvObjective::MeanQueueUs);
        assert_eq!(prague.bound_us, prague2.bound_us, "Prague bound converged across period granularity");
        assert_eq!(reno.bound_us, reno2.bound_us, "Reno bound converged across period granularity");

        // Deterministic — same envelope → same certificate.
        assert_eq!(prague.bound_us, certify_worst(CcKind::Prague, env, bytes, 4, 3, AdvObjective::MeanQueueUs).bound_us);
    }

    /// WHERE EXHAUSTION EARNS ITS KEEP — for BBR, whose windowed-max rate estimator has no structural
    /// worst case, the certificate finds a **resonant timing pattern** (a capacity spike that primes the
    /// estimate high, then a crash) that drives the queue *higher than the sampling adversary finds at a
    /// comparable budget*. The exhaustive periodic enumeration reaches a worst case neither a structural
    /// shortcut nor random sampling does — exactly what a performance model checker is for: the
    /// controller whose worst case is not obvious.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn exhaustive_certificate_finds_bbrs_resonant_worst_a_sampler_misses() {
        let env = coev_env();
        let bytes = 192 * 1024;
        // BBR's worst-case max standing queue over the n=4, 3-level envelope.
        let cert = certify_worst(CcKind::Bbr, env, bytes, 4, 3, AdvObjective::MaxQueueUs);

        // The worst case is a genuine resonant SPIKE/CRASH pattern: the worst trace contains both a
        // raised level (a spike that primes BBR's rate estimate) and the floor (the crash) — not the
        // flat minimum-rate trace a structural shortcut would assume.
        let sched = cert.worst_trace.schedule();
        assert!(sched.iter().any(|&p| p >= 90) && sched.contains(&ADV_MIN_PCT),
            "BBR's worst case is a spike/crash resonance, not the floor: {:?}", cert.worst_trace);

        // The exhaustive certificate EXCEEDS what the sampling adversary turns up at a comparable budget,
        // with margin (a near-tie regression would be caught): the periodic resonance the sampler misses.
        let sampled = adversary_search(CcKind::Bbr, AdvObjective::MaxQueueUs, env, bytes, 80, 0xBEEF).best_cost;
        assert!(
            cert.bound_us > sampled + sampled / 20,
            "the exhaustive certificate beats sampling on BBR by >5%: certified {} µs vs sampled {} µs",
            cert.bound_us, sampled
        );

        // Deterministic.
        assert_eq!(cert.bound_us, certify_worst(CcKind::Bbr, env, bytes, 4, 3, AdvObjective::MaxQueueUs).bound_us);
    }

    /// The full performance-certificate picture (ignored — exhausts thousands of transfers). Prints, per
    /// controller and objective, the certified worst-case at nested granularities n ∈ {2,4,8} (so the
    /// bound's convergence — or, for BBR, its continued growth — is visible), the worst trace, and the
    /// sampling adversary's best for the tightness comparison; plus the co-evolved controller's bound.
    #[test]
    #[ignore]
    fn perfproof_reproduction() {
        let env = coev_env();
        let bytes = 192 * 1024;
        let (rep, _) = coevolve(env, bytes, 4, 5, 6, 0.3, 30, 0xC0E0);
        for obj in [AdvObjective::MeanQueueUs, AdvObjective::MaxQueueUs] {
            eprintln!("=== objective {obj:?} (certified worst-case µs, nested n=2/4/8) ===");
            set_learned_override(Some(rep.genome));
            let r: Vec<_> = [2usize, 4, 8].iter().map(|&n| certify_worst(CcKind::Learned, env, bytes, n, 3, obj).bound_us).collect();
            set_learned_override(None);
            eprintln!("   co-evolved: {} / {} / {}", r[0], r[1], r[2]);
            for (name, cc) in [("DCTCP", CcKind::Dctcp), ("Prague", CcKind::Prague), ("Reno", CcKind::Reno), ("BBR", CcKind::Bbr)] {
                let c: Vec<_> = [2usize, 4, 8].iter().map(|&n| certify_worst(cc, env, bytes, n, 3, obj)).collect();
                eprintln!("   {name:>7}: {} / {} / {}  (worst {:?})", c[0].bound_us, c[1].bound_us, c[2].bound_us, c[2].worst_trace.schedule());
            }
            let s = adversary_search(CcKind::Bbr, obj, env, bytes, 80, 0xBEEF).best_cost;
            eprintln!("   tightness: BBR sampling-best {} vs BBR certified@8 {}", s, certify_worst(CcKind::Bbr, env, bytes, 8, 3, obj).bound_us);
        }
    }

    /// THE CONTINUUM-LIFT OBSTRUCTION (ignored) — *why* the bounded certificate does not yet become a
    /// tight continuum bound, characterised precisely (an honest negative result, useful in itself).
    /// Over the n=4 grid it measures, per controller/objective: monotonicity violations (raising a slice's
    /// capacity that *raises* the cost — so the all-floor trace cannot be proven the continuum worst by
    /// monotonicity), the Lipschitz sensitivity `L` (µs per 1% capacity) and the slack `n·L·half-step` a
    /// Lipschitz lift would carry (≈ the bound itself — too loose to be useful), and the empirical
    /// discretisation error (a coarse 3-level vs a fine 9-level grid changes the bound by ≤ 1%). So a
    /// *tight* continuum proof is open: monotonicity is near-but-not-exact and the Lipschitz slack is large,
    /// while the bound is empirically grid-converged on both axes.
    #[test]
    #[ignore]
    fn continuum_lift_obstruction() {
        let env = coev_env();
        let bytes = 192 * 1024;
        let levels = [30u16, 90, 150];
        let n = 4usize;
        let cost = |sched: [u16; ADV_SLICES], cc, obj| adv_single_cost(obj, &env, &run_adversarial(env, AdvTrace { schedule: sched }, bytes, cc));
        let tile = |pat: &[u16; 4]| {
            let mut s = [100u16; ADV_SLICES];
            for (i, slot) in s.iter_mut().enumerate() {
                *slot = pat[i % n];
            }
            s
        };
        for (name, cc) in [("Prague", CcKind::Prague), ("DCTCP", CcKind::Dctcp), ("BBR", CcKind::Bbr)] {
            for obj in [AdvObjective::MeanQueueUs, AdvObjective::MaxQueueUs] {
                let (mut mono_viol, mut max_sens, mut max_jump) = (0u32, 0.0f64, 0u64);
                for idx in 0..levels.len().pow(n as u32) {
                    let mut pat = [30u16; 4];
                    let mut x = idx;
                    for p in pat.iter_mut() {
                        *p = levels[x % levels.len()];
                        x /= levels.len();
                    }
                    let base = cost(tile(&pat), cc, obj);
                    for s in 0..n {
                        let li = levels.iter().position(|&l| l == pat[s]).unwrap();
                        if li + 1 < levels.len() {
                            let mut p2 = pat;
                            p2[s] = levels[li + 1];
                            let c2 = cost(tile(&p2), cc, obj);
                            if c2 > base {
                                mono_viol += 1;
                            }
                            let djump = base.abs_diff(c2);
                            max_sens = max_sens.max(djump as f64 / (levels[li + 1] - pat[s]) as f64);
                            max_jump = max_jump.max(djump);
                        }
                    }
                }
                let coarse = certify_worst(cc, env, bytes, n, 3, obj).bound_us;
                eprintln!("{name:>7}/{obj:?}: mono_viol {mono_viol} | L {max_sens:>5.0} us/% | max_jump {max_jump:>6} | bound {coarse} | lipschitz-slack {:.0}", n as f64 * max_sens * 30.0);
            }
        }
        for (name, cc) in [("Prague", CcKind::Prague), ("BBR", CcKind::Bbr)] {
            let coarse = certify_worst(cc, env, bytes, n, 3, AdvObjective::MeanQueueUs).bound_us;
            let fine = certify_worst(cc, env, bytes, n, 9, AdvObjective::MeanQueueUs).bound_us;
            eprintln!("{name:>7} mean: coarse(3lvl) {coarse} vs fine(9lvl) {fine} (+{}% — grid-converged)", 100 * fine.saturating_sub(coarse) / coarse.max(1));
        }
    }
}
