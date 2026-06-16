# ferrumnet

A **userspace TCP/IP stack written from scratch in Rust** — kernel-bypass networking. It sits
between a raw Linux **TUN** device and the application and does, in userspace, everything the
kernel normally does invisibly: parse packets, run the TCP state machine, retransmit lost data,
control congestion, and expose an `async` socket API.

```console
$ curl -v http://10.0.0.2:8080/
*   Trying 10.0.0.2:8080...
* Connected to 10.0.0.2 (10.0.0.2) port 8080 (#0)
> GET / HTTP/1.1
< HTTP/1.1 200 OK
< Server: ferrumnet
< Content-Type: text/html; charset=utf-8
< Content-Length: 442
< Connection: close
```

`curl` believes it is talking to the Linux kernel. It is talking to a few thousand lines of Rust.

## Why it's interesting

- **Zero dependencies.** Only the Rust standard library. The TCP/IP logic (no `smoltcp`), the
  async runtime — executor, reactor, `Waker` plumbing (no `tokio`) — and even the syscall
  bindings (including a hand-rolled `io_uring`) are all hand-written. The protocol core is
  `#![deny(unsafe_code)]`; the *only* `unsafe` in the entire project is the syscall FFI in the TUN
  backend — `ioctl`/`poll` in `sys.rs` and the `io_uring` setup/enter/`mmap` in `iou.rs`.
- **sans-IO core.** `tcp-core` performs no I/O and contains no OS-specific code — it ingests
  received bytes and emits bytes to send, with time injected as a parameter. So the whole
  engine, *including the async runtime* (via an in-memory mock device), is deterministically
  unit-testable off-device, including under simulated packet loss, reordering, SACK-based
  selective recovery, **pluggable congestion control** (Reno / CUBIC / BBR), and a **two-stack
  userspace loopback** (two instances connecting to each other entirely in memory). **160 tests**,
  green on Rust 1.92 and the 1.75 MSRV; Miri-clean (no UB, no leaks, no suppression).
- **It connects both ways.** Not just a server: it does **active open** (`connect`) as well as
  passive open — the full RFC 793 §3.9 client path, including simultaneous open — so two instances
  can talk to each other with no kernel TCP involved.
- **It's real.** It runs on a Linux box over an actual `/dev/net/tun` device, answers `ping`,
  and serves HTTP to a stock `curl` — handshake, retransmission, congestion control, SACK loss
  recovery, RFC 7323 timestamps, window scaling, delayed ACKs, orderly teardown and TIME-WAIT,
  all on the wire. An optional `io_uring` backend batches the packet I/O.

## Benchmarks

Measured on a 2-vCPU ("Common KVM processor") Ubuntu 22.04.5 VPS (kernel 5.15, Rust 1.75) over
`tun0`, a same-host path — so it measures the stack's processing efficiency, not link speed.
Figures are **medians** over the runs noted; the VPS is shared, so the occasional outlier is a
contention dip (median is robust).

- **Throughput** (`GET /bench`, 64 MiB, single-threaded): **~140 MB/s** at the default 1500-byte
  MTU (median of 10), and **~337 MB/s** at MTU 65535 (median of 10; 9 of 10 runs in 316–356). The
  advertised MSS auto-adapts to the device MTU, so a larger MTU sends the same data in ~2.4× fewer
  packets — and `write` syscalls. (SACK does not change no-loss throughput; it is inactive at 0%
  loss.)
- **io_uring backend** (`FERRUM_IO=uring`, opt-in, falls back to blocking I/O): batches every read
  and write into **one `io_uring_enter` per event-loop turn**, lifting MTU-1500 throughput
  **~1.24× (148.6 → 184.3 MB/s, medians of 9, same session)** by removing the per-packet syscall
  overhead — exactly the syscall-bound regime the CPU profile below identifies. `IORING_OP_READ`/
  `WRITE` are generic file ops, so (unlike `sendmmsg`, which returns `ENOTSOCK`) they work on a TUN
  fd. It trades single-packet latency for batch throughput (ICMP RTT 0.10 → 0.32 ms), which bulk
  transfer hides; the sans-IO core is untouched.
- **Two userspace instances, over the wire** (one `connect`s and downloads from the other; the
  kernel forwards between their two TUNs — *both* peers are this stack, so neither end is a
  `curl`-sized window): **125 MB/s** at MTU 1500, **300 MB/s** at MTU 65535 (still ~2.4× — match-MTU
  holds between two fast peers). And the window-scaling result the same-host `curl` bench can't
  show: with **+20 ms RTT** (`netem`) so the window, not CPU, is the limiter, it sustains **11.2
  MB/s** — **3.5× the 3.2 MB/s a 64 KiB window allows at 20 ms** (≈224 KiB in flight), which only
  window scaling (RFC 7323) enables.
- **Latency:** ICMP RTT (100 packets), blocking backend, min/avg/max/mdev =
  **0.047 / 0.099 / 0.180 / 0.028 ms**.
- **CPU** under sustained load (`vmstat`, system-wide over 2 vCPU): MTU 1500 → 30% user /
  **50% system** / 20% idle; MTU 65535 → 28% user / **17% system** / 55% idle. **System time
  collapses with the larger MTU** — the stack is *syscall-bound* at small MTU (a TUN is one packet
  per `write`; it is not a socket, so `sendmmsg` does not apply, and `writev` only *gathers* into a
  single packet). At large MTU the remaining 55% idle is *not* our window: window scaling (RFC 7323)
  is implemented and lifts our 64 KiB cap, but on this same-host bench the limit is the **receiver's**
  window (a localhost `curl` advertises ~64 KiB and refills one ~65 KB segment at a time) and the
  **serial** per-segment processing across the two cores. So scaling doesn't move this number — it's
  what keeps the pipe full on a real high-latency path, which the **two-instance benchmark above
  measures directly** (11.2 MB/s at +20 ms RTT, 3.5× the 64 KiB cap). The remaining lever is
  pipelined I/O — the **io_uring backend above** does exactly that at MTU 1500, where the profile is
  syscall-bound.

**Under packet loss** (live `tc netem` dropping our *outbound* data, 4 MiB), measured **before and
after SACK in the same session** — every transfer completes correctly, and **SACK selective
repair** (RFC 2018 + RFC 6675) recovers the tail far faster than go-back-N:

| packet loss | 0% | 1% | 2% | 5% | 10% |
|---|---|---|---|---|---|
| go-back-N (before) | 93.9 | 9.2 | 2.5 | 0.40 | 0.10 |
| **SACK (now)** | **94.6** | **91.4** | **9.3** | **2.0** | **0.4** |
| speedup | 1.0× | ~9.9× | ~3.7× | ~5.0× | ~4.0× |

(MB/s, medians; ~4–10× faster across the tail. Loss is stochastic — the 2% cell is bimodal,
splitting between ~6–14 and ~70–78 MB/s depending on where losses fall.)

**Congestion control — Reno vs CUBIC vs BBR.** The controller is **pluggable**: a
`CongestionControl` trait behind a match-dispatched `Cc` enum (no `Box<dyn>`, zero-alloc, sans-IO),
selectable at runtime with `FERRUM_CC={reno,cubic,bbr}`. All three are hand-written from the RFCs —
**Reno** (RFC 5681), **CUBIC** (RFC 8312, the Linux default: cubic window growth + the TCP-friendly
region), and **BBR** v1 (model-based — it estimates bottleneck bandwidth and min-RTT and *paces* to
the bandwidth-delay product instead of reacting to loss, with a full STARTUP→DRAIN→PROBE_BW→PROBE_RTT
state machine and a Cheng/Cardwell delivery-rate estimator). The sans-IO core makes every phase
deterministically unit-testable off-device. Measured over the two-instance bench (one stack
downloads 8 MiB from another across two kernel-forwarded TUNs) at a `netem`-imposed **20 ms RTT** so
the *window*, not the CPU, is the bottleneck (MB/s, medians of 3):

| 20 ms RTT | 0% loss | 0.5% | 1% | 2% |
|---|---|---|---|---|
| Reno    | 7.6 | 1.1 | 0.7 | 0.5 |
| CUBIC   | 7.2 | 1.1 | 0.9 | 0.5 |
| **BBR** | **10.5** | †  | † | † |

At **0% loss** BBR leads by ~40%: pacing to the BDP fills a short high-RTT flow faster than
Reno/CUBIC's slow-start ramp. **Under loss**, Reno collapses (multiplicative decrease, costly at
20 ms RTT) and CUBIC's gentler β = 0.7 cut holds marginally better. † **BBR under random loss is a
known limitation:** BBR v1 is loss-*agnostic* by design and should excel here, but the from-scratch
delivery-rate estimator under-measures bandwidth under random loss and spirals into RTO-based
recovery — the documented BBRv1 random-loss weakness, amplified. Making BBR robust under random loss
is the next congestion-control task. At **sub-millisecond RTT** (no shaping, CPU-bound) the ranking
inverts: Reno's aggressive window (~111 MB/s) beats BBR's pacing (~80 MB/s), which carries overhead
at a tiny BDP. The honest takeaway is the *bottleneck story* — at high BDP the model wins, under
loss the loss-based controllers are more robust in this build, and at tiny BDP window aggression
wins.

**Kernel baseline** (Python `http.server` over `lo`, kernel TCP, 16 MiB): median **~800 MB/s**
(556–893). *Not* apples-to-apples — `lo`'s MTU is 65536 and it is fully in-kernel (no per-packet
syscall or user/kernel copy), so it is structurally faster on this path. Matching the MTU closes
much of the gap (~2.4× here) and io_uring cuts the remaining syscall overhead (~1.24× at MTU 1500);
neither beats in-kernel loopback, which has neither a per-packet syscall nor a user/kernel copy.

## Architecture

```
  curl ──speaks ordinary TCP──▶ Linux routing ──▶ tun0 (10.0.0.0/24) ──raw IP──▶ ferrumnet
                                                                                     │
  ┌─────────────────────── ferrumnet — one process, one thread ──────────────────────┐
  │  tcp-tun (Linux backend, the only `unsafe`)                                        │
  │    TunDevice (blocking read/write/poll) │ io_uring backend (FERRUM_IO=uring)       │
  │    HTTP app (one task per connection)                                              │
  │  ── trait Device ────────────────────────────────────────────────────────────────│
  │  tcp-core (sans-IO · zero deps · #![deny(unsafe_code)])                            │
  │    runtime:  executor + reactor + Wakers  →  TcpListener / TcpStream / TcpConnector│
  │    Stack  →  TCB per connection (active + passive open)                            │
  │      wire (parse + RFC 1071 checksum) · seq (RFC 1982) · isn (RFC 6528)            │
  │      rtt (RFC 6298) · congestion: Reno/CUBIC/BBR (pluggable) · sack+reasm (2018/6675)│
  │      timestamps (RFC 7323) · delayed ACKs (RFC 1122) · buffers · timers            │
  └────────────────────────────────────────────────────────────────────────────────────┘
```

`tcp-core` is driven by three calls in a loop: `on_recv(bytes)` (update state), `poll_transmit`
(drain bytes to send), and `poll_at`/`on_timer` (timers). The reactor wires those to the device
and wakes the async tasks.

> **The thinking lives in [`docs/DESIGN.md`](docs/DESIGN.md).** It's a component-by-component
> walkthrough that, for each piece, lists the specific correctness traps it has to avoid —
> sequence-number wraparound, the checksum carry-fold and pseudo-header, Karn's rule for RTT
> sampling under loss, the `ack_of_fin` teardown subtlety, the async lost-wakeup race. Every one
> was pinned down by an adversarial design review *before* a line was written, then re-checked by
> a multi-agent adversarial review of the finished code before each commit (the initial review
> found and fixed 11 real bugs; later reviews of active open and delayed ACKs caught 5 more). If
> you read one file, read that one.

## The five hard problems

1. **TCP state machine** — 11 RFC 793 states, the three-way handshake, **active open (`connect`)**
   as well as passive, simultaneous open and close, and TIME-WAIT (2·MSL). (`state`, `tcb`)
2. **Retransmission & selective repair** — a send ring with go-back-N retransmission, Jacobson/
   Karn RTO estimation (RFC 6298), SACK-based selective loss recovery with out-of-order
   reassembly (RFC 2018 + RFC 6675), RFC 7323 **timestamps** (Karn-free RTT + PAWS), and **delayed
   ACKs** (RFC 1122). (`tcb`, `rtt`, `sack`, `reasm`)
3. **Congestion control** — **pluggable** behind a `CongestionControl` trait + match-dispatched
   `Cc` enum (no `Box<dyn>`): **Reno** (RFC 5681 + 6928), **CUBIC** (RFC 8312), and **BBR** v1
   (model-based, paced to the BDP). Selectable with `FERRUM_CC`. (`congestion`, `bbr`)
4. **Zero-copy parsing** — header views over `&[u8]` and the one's-complement Internet checksum
   (RFC 1071), with a clean RX/TX borrow split. (`wire`)
5. **Async integration** — the `Waker` lifecycle over the sans-IO core, built on the safe
   `std::task::Wake` trait. (`runtime`)

## What I learned

The bug that taught me the most wasn't in the TCP state machine — it was the checksum, and it
was invisible. `ping` worked perfectly, which "proved" the device, the IPv4 layer, and my
one's-complement checksum were all fine. But `curl` would complete the handshake and then hang.
`tcpdump` showed my SYN-ACK and data segments leaving the interface looking correct — yet the
client never made progress.

The cause lives at the boundary between my code and the kernel. When a packet is generated on
the same host and handed to a TUN device, Linux leaves the TCP checksum field **zero**: it
assumes a real NIC will fill it in on the way out via hardware TX offload. A software TUN device
has no NIC, so those segments reached my stack with a checksum of `0x0000`, and my verifier was —
correctly, per the RFC — rejecting every single one as corrupt, silently. ICMP slipped through
only because the kernel checksums ICMP itself. The fix was twofold: disable TX checksum offload
on the interface (`ethtool -K tun0 tx off`), and have the stack treat an on-wire checksum of
`0x0000` as "offloaded, accept" rather than "corrupt, drop."

The lesson stuck: *"the protocol is correct"* and *"it works end to end"* are completely
different claims, and the hardest problems in a network stack aren't in the spec — they're in the
half-truths about what the layer beneath you actually does. (Close runner-up: a parked
`read().await` that hung forever when the peer sent a RST, because the reactor only woke a reader
on *new data*, never on *the connection going away*.)

## Layout

| Crate | Role |
|---|---|
| `tcp-core` | Device- & OS-agnostic, `std`-only TCP/IP engine + async runtime. Builds & tests anywhere. |
| `tcp-tun` | Linux backend: `TunDevice`, the reactor, and the HTTP demo. |

## Build & test

The protocol core builds and tests on any platform:

```sh
cargo test -p tcp-core      # 160 tests: unit + in-memory integration + loss/SACK/teardown
                            #            + two-stack loopback + timestamps + delayed ACKs
                            #            + CUBIC + BBR (rate sampler, windowed filter, phases)
```

The TUN backend + live demo run on **Linux** (needs root for the device + routing):

```sh
cargo build --release -p tcp-tun
sudo ./target/release/tcp-tun tun0 &     # creates tun0, serves HTTP on 10.0.0.2:8080
# (FERRUM_IO=uring ./target/release/tcp-tun tun0  — the io_uring backend instead of blocking I/O)
sudo ./scripts/tun-up.sh                 # address + route + disable checksum offload
curl http://10.0.0.2:8080/               # the win condition
curl -o /dev/null http://10.0.0.2:8080/bench/64   # 64 MiB throughput test
sudo ./scripts/tun-down.sh
```

The setup is scoped to `10.0.0.0/24` on `tun0` and never touches the host's default route or
IP forwarding, so it is safe to run alongside other services.

## Roadmap

The big milestones are done — active open, SACK loss recovery, MTU-adaptive MSS, window scaling,
RFC 7323 timestamps, delayed ACKs, an io_uring backend, and **pluggable Reno/CUBIC/BBR congestion
control** measured head-to-head over the two-instance hardware bench. What's left:

- **BBR robustness under random loss** — BBR leads at 0% loss but its from-scratch delivery-rate
  estimator under-measures bandwidth under random loss and falls into RTO-based recovery (the known
  BBRv1 random-loss weakness). Loss-robust BtlBw estimation (and the BBRv1 recovery/restart cwnd
  states) is the active congestion-control task; the diagnosis is in `docs/DESIGN.md`.
- **IPv6** — a second wire format (parse/emit, the pseudo-header checksum); currently IPv4-only.
- **RFC 1122/9293 robustness** — PMTUD (RFC 1191), silly-window avoidance, ECN (RFC 3168), TCP Fast
  Open, keepalives, Nagle — the details that separate "a TCP" from "real TCP".

Deliberately *not* on the roadmap: AF_XDP / DPDK / RDMA (a different kind of project — RDMA replaces
the TCP stack rather than speeding it) and multi-threading (single-threaded by design; an
`Arc<Mutex>` variant is the documented extension). Nothing in the codebase is stubbed — every code
path that exists is complete and tested; BBR's random-loss behaviour is a measured limitation of a
complete implementation, not a stub.

## References

RFC 791 (IPv4), RFC 793 / 1122 / 9293 (TCP + host requirements, incl. delayed ACKs), RFC 1071
(checksum), RFC 1982 (serial numbers), RFC 5681 + 6928 (Reno + initial window), RFC 8312 (CUBIC),
the BBR congestion-control draft + Cheng/Cardwell delivery-rate estimation, RFC 6298 (RTO),
RFC 2018 + 6675 (SACK & selective recovery), RFC 7323 (timestamps & window scaling), RFC 5961 +
6528 (blind-attack hardening); W. R. Stevens, *TCP/IP Illustrated, Vol. 1*. Built milestone by
milestone; see [`docs/DESIGN.md`](docs/DESIGN.md).
