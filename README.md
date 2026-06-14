# userspace-tcp

A userspace TCP/IP stack written from scratch in Rust — *kernel-bypass networking*.
It sits between a raw Linux **TUN** device and the application, doing the job the kernel
normally does invisibly: parsing packets, running the TCP state machine, retransmission,
congestion control, and exposing an `async` socket API.

> **Win condition:** `curl http://10.0.0.2:8080` returns a real HTTP response, served
> entirely by this stack. `curl` believes it is talking to the kernel — it is talking to us.

## Highlights

- **Zero dependencies.** Only the Rust standard library. The TCP/IP logic (no `smoltcp`),
  the async runtime — executor, reactor, `Waker` plumbing (no `tokio`) — and even the
  syscall bindings are hand-written. The single `unsafe` block in the whole project is the
  TUN `ioctl`; the protocol core is `#![deny(unsafe_code)]`.
- **sans-IO core.** `tcp-core` performs no I/O and contains no OS-specific code: it ingests
  received IP bytes and emits bytes to send, with time injected as a parameter. This makes
  the entire engine — including the async runtime, via an in-memory mock device —
  deterministically unit-testable off-device, including under simulated packet loss and
  reordering.

## Layout

| Crate | Role |
|---|---|
| `tcp-core` | Device- & OS-agnostic, `std`-only TCP/IP engine + async runtime. Fully testable on any platform. |
| `tcp-tun`  | Linux backend: TUN device, `poll`-based reactor, HTTP demo. *(added in M0)* |

## The five hard problems (per `docs/DESIGN.md`)

1. **TCP state machine** — 11 RFC 793 states, TIME-WAIT + a hashed timer wheel.
2. **Retransmission** — ring buffer + Jacobson/Karn RTO (RFC 6298).
3. **Congestion control** — TCP Tahoe (slow start / congestion avoidance / fast retransmit).
4. **Zero-copy parsing** — header views over `&[u8]` + one's-complement checksums (RFC 1071).
5. **Async integration** — the `Waker` lifecycle over the sans-IO core.

## Building & running

The protocol core builds and tests anywhere:

```sh
cargo test -p tcp-core
```

The TUN backend + live demo run on Linux (see `scripts/tun-up.sh`):

```sh
sudo ./scripts/tun-up.sh           # create tun0, 10.0.0.0/24, disable checksum offload
cargo run --release -p tcp-tun     # run the stack
curl http://10.0.0.2:8080          # the win condition
sudo ./scripts/tun-down.sh
```

## References

RFC 793 / 1122 / 9293 (TCP), RFC 791 (IPv4), RFC 6298 (RTO), RFC 5681 + 6928 (congestion
control), RFC 1982 (serial-number arithmetic), RFC 5961 (blind-attack hardening);
W. R. Stevens, *TCP/IP Illustrated, Vol. 1*.

## Status

Work in progress — built milestone by milestone (M0 → M6). See `docs/DESIGN.md`.
