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
< Content-Length: 392
< Connection: close
```

`curl` believes it is talking to the Linux kernel. It is talking to a few thousand lines of Rust.

## Why it's interesting

- **Zero dependencies.** Only the Rust standard library. The TCP/IP logic (no `smoltcp`), the
  async runtime — executor, reactor, `Waker` plumbing (no `tokio`) — and even the syscall
  bindings are all hand-written. The protocol core is `#![deny(unsafe_code)]`; the *only*
  `unsafe` in the entire project is ~10 lines of `ioctl`/`poll` FFI in the TUN backend.
- **sans-IO core.** `tcp-core` performs no I/O and contains no OS-specific code — it ingests
  received bytes and emits bytes to send, with time injected as a parameter. So the whole
  engine, *including the async runtime* (via an in-memory mock device), is deterministically
  unit-testable off-device, including under simulated packet loss, reordering, and SACK-based
  selective recovery. **100 tests**, green on Rust 1.92 and the 1.75 MSRV; Miri-clean (no UB, no
  leaks).
- **It's real.** It runs on a Linux box over an actual `/dev/net/tun` device, answers `ping`,
  and serves HTTP to a stock `curl` — handshake, retransmission, congestion control, orderly
  teardown and TIME-WAIT, all on the wire.

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
- **Latency:** ICMP RTT (100 packets) min/avg/max/mdev = **0.047 / 0.099 / 0.180 / 0.028 ms**.
- **CPU** under sustained load (`vmstat`, system-wide over 2 vCPU): MTU 1500 → 30% user /
  **50% system** / 20% idle; MTU 65535 → 28% user / **17% system** / 55% idle. **System time
  collapses with the larger MTU** — the stack is *syscall-bound* at small MTU (a TUN is one packet
  per `write`; it is not a socket, so `sendmmsg` does not apply, and `writev` only *gathers* into a
  single packet). At large MTU the remaining 55% idle is *not* our window: window scaling (RFC 7323)
  is implemented and lifts our 64 KiB cap, but on this same-host bench the limit is the **receiver's**
  window (a localhost `curl` advertises ~64 KiB and refills one ~65 KB segment at a time) and the
  **serial** per-segment processing across the two cores. So scaling doesn't move this number — it's
  what keeps the pipe full on a real high-latency path; here the next lever is pipelined I/O (io_uring).

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

**Kernel baseline** (Python `http.server` over `lo`, kernel TCP, 16 MiB): median **~800 MB/s**
(556–893). *Not* apples-to-apples — `lo`'s MTU is 65536 and it is fully in-kernel (no per-packet
syscall or user/kernel copy), so it is structurally faster on this path. Matching the MTU closes
much of the gap (done — ~2.4× here) and io_uring would cut the remaining syscall overhead; it
won't beat in-kernel loopback, which has neither a per-packet syscall nor a user/kernel copy.

## Architecture

```
  curl ──speaks ordinary TCP──▶ Linux routing ──▶ tun0 (10.0.0.0/24) ──raw IP──▶ ferrumnet
                                                                                     │
  ┌─────────────────────── ferrumnet — one process, one thread ──────────────────────┐
  │  tcp-tun (Linux backend, the only `unsafe`)                                        │
  │    TunDevice: read()/write() raw IP packets · HTTP app (one task per connection)   │
  │  ── trait Device ────────────────────────────────────────────────────────────────│
  │  tcp-core (sans-IO · zero deps · #![deny(unsafe_code)])                            │
  │    runtime:  executor + reactor + Wakers  →  TcpListener / TcpStream               │
  │    Stack  →  TCB per connection                                                    │
  │      wire (zero-copy parse + RFC 1071 checksum) · seq (RFC 1982) · isn (RFC 6528)  │
  │      rtt (RFC 6298) · congestion (Reno) · buffers · per-connection timers         │
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
> a review of the finished code (which found, and I fixed, 11 real bugs). If you read one file,
> read that one.

## The five hard problems

1. **TCP state machine** — 11 RFC 793 states, the three-way handshake, active/passive/
   simultaneous close, and TIME-WAIT (2·MSL). (`state`, `tcb`)
2. **Retransmission & selective repair** — a send ring with go-back-N retransmission, Jacobson/
   Karn RTO estimation (RFC 6298), and SACK-based selective loss recovery with out-of-order
   reassembly (RFC 2018 + RFC 6675). (`tcb`, `rtt`, `sack`, `reasm`)
3. **Congestion control** — TCP Reno: slow start, congestion avoidance, fast retransmit on 3
   duplicate ACKs (RFC 5681 + 6928). (`congestion`)
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
cargo test -p tcp-core      # 100 tests: unit + in-memory integration + loss/SACK/teardown
```

The TUN backend + live demo run on **Linux** (needs root for the device + routing):

```sh
cargo build --release -p tcp-tun
sudo ./target/release/tcp-tun tun0 &     # creates tun0, serves HTTP on 10.0.0.2:8080
sudo ./scripts/tun-up.sh                 # address + route + disable checksum offload
curl http://10.0.0.2:8080/               # the win condition
curl -o /dev/null http://10.0.0.2:8080/bench   # 16 MiB throughput test
sudo ./scripts/tun-down.sh
```

The setup is scoped to `10.0.0.0/24` on `tun0` and never touches the host's default route or
IP forwarding, so it is safe to run alongside other services.

## Roadmap

The core is deliberately small and focused. These are the natural next milestones, each a
self-contained extension of an existing component:

- **Delayed ACKs and TCP timestamps (RFC 7323)** — fewer pure-ACK segments, and RTTM-based RTT
  sampling that sidesteps Karn's ambiguity.
- **io_uring backend** — its `READ`/`WRITE` are generic file ops, so (unlike `sendmmsg`) they
  work on a TUN fd; batching many packet I/Os per `io_uring_enter` cuts the syscall overhead the
  CPU profile is dominated by. The sans-IO core stays untouched.
- **Active open (`connect`)** — make it a client as well as a server, which also unlocks a
  two-stack loopback test harness.
- **A transmit scratch ring** — remove the one heap allocation per emitted segment. A minor lever
  on a syscall-bound path (match-MTU above is the larger one), but it would tighten the hot loop.

Nothing here is stubbed today — those code paths simply don't exist yet, which keeps the current
implementation honest about exactly what it does.

## References

RFC 791 (IPv4), RFC 793 / 1122 / 9293 (TCP), RFC 1071 (checksum), RFC 1982 (serial numbers),
RFC 5681 + 6928 (congestion control), RFC 6298 (RTO), RFC 2018 + 6675 (SACK & selective recovery),
RFC 5961 + 6528 (blind-attack hardening); W. R. Stevens, *TCP/IP Illustrated, Vol. 1*. Built
milestone by milestone (M0 → M8); see [`docs/DESIGN.md`](docs/DESIGN.md).
