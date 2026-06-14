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

`curl` believes it is talking to the Linux kernel. It is talking to ~3,000 lines of Rust.

## Why it's interesting

- **Zero dependencies.** Only the Rust standard library. The TCP/IP logic (no `smoltcp`), the
  async runtime — executor, reactor, `Waker` plumbing (no `tokio`) — and even the syscall
  bindings are all hand-written. The protocol core is `#![deny(unsafe_code)]`; the *only*
  `unsafe` in the entire project is ~10 lines of `ioctl`/`poll` FFI in the TUN backend.
- **sans-IO core.** `tcp-core` performs no I/O and contains no OS-specific code — it ingests
  received bytes and emits bytes to send, with time injected as a parameter. So the whole
  engine, *including the async runtime* (via an in-memory mock device), is deterministically
  unit-testable off-device, including under simulated packet loss. **68 tests**, green on Rust
  1.92 and the 1.75 MSRV.
- **It's real.** It runs on a Linux box over an actual `/dev/net/tun` device, answers `ping`,
  and serves HTTP to a stock `curl` — handshake, retransmission, congestion control, orderly
  teardown and TIME-WAIT, all on the wire.

## Benchmarks

Measured on an Ubuntu 22.04 VPS over the `tun0` device (a localhost path, so it's CPU-bound —
this measures the stack's processing efficiency, not link speed):

| Metric | Result |
|---|---|
| **Throughput** (`GET /bench`, 16 MiB) | **~140 MB/s** (≈ 1.1 Gbit/s) |
| **ICMP RTT** (mean / min / max) | **0.099 ms** / 0.056 / 0.151 |
| **HTTP request** (`GET /`, small response) | **~0.5 ms** |

Single-threaded, with one heap allocation per emitted segment on the egress path — replacing
that with a transmit scratch ring is the obvious next optimization.

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
2. **Retransmission** — a send ring with go-back-N retransmission and Jacobson/Karn RTO
   estimation (RFC 6298). (`tcb`, `rtt`)
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
cargo test -p tcp-core      # 68 tests: unit + in-memory integration + loss/teardown
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

- **SACK + selective repair** — today a gap is dropped and recovered by the RTO via go-back-N;
  selective acknowledgement would repair loss without resending data that already arrived.
- **Delayed ACKs and TCP timestamps (RFC 7323)** — fewer pure-ACK segments, and RTTM-based RTT
  sampling that sidesteps Karn's ambiguity.
- **Window scaling** — receive windows beyond 64 KiB for high bandwidth-delay paths.
- **Out-of-order reassembly** — buffer and stitch gaps instead of dropping them.
- **Active open (`connect`)** — make it a client as well as a server, which also unlocks a
  two-stack loopback test harness.
- **A transmit scratch ring** — remove the one heap allocation per emitted segment; this is the
  main lever on the throughput number above.

Nothing here is stubbed today — those code paths simply don't exist yet, which keeps the current
implementation honest about exactly what it does.

## References

RFC 791 (IPv4), RFC 793 / 1122 / 9293 (TCP), RFC 1071 (checksum), RFC 1982 (serial numbers),
RFC 5681 + 6928 (congestion control), RFC 6298 (RTO), RFC 5961 + 6528 (blind-attack hardening);
W. R. Stevens, *TCP/IP Illustrated, Vol. 1*. Built milestone by milestone (M0 → M6);
see [`docs/DESIGN.md`](docs/DESIGN.md).
