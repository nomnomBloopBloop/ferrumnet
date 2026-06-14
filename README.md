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
  │      rtt (RFC 6298) · congestion (Tahoe) · buffers · per-connection timers         │
  └────────────────────────────────────────────────────────────────────────────────────┘
```

`tcp-core` is driven by three calls in a loop: `on_recv(bytes)` (update state), `poll_transmit`
(drain bytes to send), and `poll_at`/`on_timer` (timers). The reactor wires those to the device
and wakes the async tasks. See [`docs/DESIGN.md`](docs/DESIGN.md) for the full design, including
the verified correctness traps each component avoids.

## The five hard problems

1. **TCP state machine** — 11 RFC 793 states, the three-way handshake, active/passive/
   simultaneous close, and TIME-WAIT (2·MSL). (`state`, `tcb`)
2. **Retransmission** — a send ring with go-back-N retransmission and Jacobson/Karn RTO
   estimation (RFC 6298). (`tcb`, `rtt`)
3. **Congestion control** — TCP Tahoe: slow start, congestion avoidance, fast retransmit on 3
   duplicate ACKs (RFC 5681 + 6928). (`congestion`)
4. **Zero-copy parsing** — header views over `&[u8]` and the one's-complement Internet checksum
   (RFC 1071), with a clean RX/TX borrow split. (`wire`)
5. **Async integration** — the `Waker` lifecycle over the sans-IO core, built on the safe
   `std::task::Wake` trait. (`runtime`)

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

## Deliberately out of scope

To keep the focus on the core mechanisms, these are not implemented (RTO recovers loss without
them): delayed-ACK (we ACK immediately), SACK, TCP timestamps, window scaling, out-of-order
reassembly, IP fragmentation, and active open (`connect` — this is a server). None are stubbed;
those code paths simply don't exist yet.

## References

RFC 791 (IPv4), RFC 793 / 1122 / 9293 (TCP), RFC 1071 (checksum), RFC 1982 (serial numbers),
RFC 5681 + 6928 (congestion control), RFC 6298 (RTO), RFC 5961 + 6528 (blind-attack hardening);
W. R. Stevens, *TCP/IP Illustrated, Vol. 1*. Built milestone by milestone (M0 → M6);
see [`docs/DESIGN.md`](docs/DESIGN.md).
