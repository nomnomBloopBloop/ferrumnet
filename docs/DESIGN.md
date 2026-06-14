# Design — Userspace TCP/IP Stack in Rust

This document is the engineering reference for the stack: the architecture, the per-component
design with its key algorithms, and — most importantly — the **verified correctness traps**
each component must avoid. The trap lists were produced by a 13-agent design +
adversarial-verification pass; the codes in parentheses (e.g. `state/N1`) are stable
references back to that review so every non-obvious decision is traceable.

## 1. Goals & the win condition

Replace the kernel's TCP/IP for one process: sit between a raw Linux **TUN** device and an
application and do, in userspace, everything the kernel normally does invisibly — parse
packets, run the TCP state machine, retransmit, control congestion, and present an `async`
socket API.

> **Win condition:** `curl http://10.0.0.2:8080` returns a real HTTP response served entirely
> by this stack. `curl` believes it is talking to the kernel.

## 2. The sans-IO philosophy

The protocol engine (`tcp-core`) performs **no I/O** and contains **no OS-specific code**. It
is a pure state machine:

- **Input:** received IP datagrams as `&[u8]`, application calls (`send`/`recv`/`close`), and
  the current time, *passed in as a parameter*.
- **Output:** the bytes it wants to transmit, and the next timer deadline (`poll_at`).

Everything that touches a real device, a real clock, or a real socket lives outside the core
(in `tcp-tun`). This is the single most important decision in the project, because it makes
the *entire* engine — including the async runtime, exercised through an in-memory
`MockDevice` — **deterministically unit-testable on any platform**, including under simulated
packet loss, reordering, and duplication. Bugs that would otherwise require a flaky network to
reproduce become ordinary unit tests.

A consequence we lean on: time is a value. `poll_at(now) -> Option<Instant>` tells the backend
when to wake; tests advance a fake clock and assert exact behavior (e.g. "TIME-WAIT is reaped
at `close_time + 2·MSL`").

## 3. Zero dependencies

The crate graph has **no third-party crates** — only `std`. This is partly forced (the build
VPS cannot reach `crates.io`; see §9) and partly a deliberate portfolio choice: we hand-write
the parts the brief calls hard rather than gluing libraries together.

- No `smoltcp` — the TCP/IP logic is ours.
- No `tokio` — the async executor, reactor, and `Waker` plumbing are ours.
- No `libc`/`nix` — the two syscalls we need (`ioctl` for `TUNSETIFF`, `poll` for the event
  loop) are bound by hand; everything else goes through `std::fs` / `std::os::fd`.

`tcp-core` is `#![deny(unsafe_code)]`. The only `unsafe` in the project is the ~10 lines of
syscall FFI in `tcp-tun/src/sys.rs`.

## 4. Architecture & layout

```
tcp-core/  (device- & OS-agnostic, std-only, #![deny(unsafe_code)])
  wire/        zero-copy IPv4/TCP/ICMP views + RFC 1071 checksum        [M0/M1]
  seq          SeqNumber — RFC 1982 serial arithmetic                   [M1]
  state, tcb   the 11-state TCP machine + transmission control block    [M1/M2]
  rtt          RFC 6298 RTO estimator (Jacobson/Karn)                   [M2]
  retx         retransmission queue                                     [M2]
  timerwheel   hashed timer wheel (generation counters)                 [M2]
  congestion   TCP Tahoe controller                                     [M3]
  buffers      rx/tx ring buffers                                       [M2]
  iface        the sans-IO driver: on_recv / poll_timers / poll_egress  [M1–M3]
  device       Device trait + in-memory MockDevice (loss/reorder sim)   [M2]
  runtime/     hand-rolled async: executor, reactor, TcpListener/Stream [M4]
tcp-tun/   (Linux-only backend + demo)
  sys          extern "C" ioctl/poll + repr(C) ifreq/pollfd            [M0]
  tun          TunDevice (IFF_TUN|IFF_NO_PI, O_NONBLOCK, poll wait)     [M0]
  http         minimal HTTP/1.1 responder                              [M5]
  main         the reactor loop wiring it together                     [M0–M5]
scripts/     tun-up.sh / tun-down.sh (host networking, scoped to 10.0.0.0/24)
```

**Async model.** A single-threaded executor and reactor on one thread; shared connection
state is `Rc<RefCell<ConnectionShared>>` — no hot-path locks (the brief's "mutex on every
packet" cost is removed by construction). The `Waker` still does the real work: parking app
tasks and marking them runnable when the reactor moves data. A multi-threaded `Arc<Mutex>`
variant is a documented extension. Wakers are built with the safe `std::task::Wake` trait, so
no `unsafe` is needed for the `RawWaker` vtable.

## 5. Components

### 5.1 Wire format & checksums (`wire`) — implemented (M0)

Read paths hand out borrowed zero-copy views (`Ipv4Packet<'_>`) over the device buffer; write
paths use value-typed emitters (`Ipv4Repr::emit`) that own no borrow. Keeping the two strictly
separate is what lets the RX (immutable-borrow) and TX (mutable-borrow) phases coexist.

Checksum is RFC 1071 one's-complement with end-around carry. Verified traps avoided:

- Zero the checksum field before summing; a trailing **odd byte is the high byte** (`<<8`).
  (`wire/T1,T4`)
- Fold carries until none remain (a single fold can leave a carry-of-carry). (`wire/N6`)
- The TCP pseudo-header length is the **TCP segment length**, never IP `total_len`; passed
  explicitly, never inferred from a buffer's `.len()`. (`wire/T3,N2`)
- Never normalize `0x0000 → 0xFFFF` for IP/ICMP/**TCP** (that is UDP-only). (`wire/T5`,
  `device-icmp/N9`)
- Decode via `from_be_bytes` at fixed offsets — never a `repr(C)` transmute (alignment +
  endianness). (`wire/T6`)
- `Ipv4Packet::new_checked` validates version, IHL ∈ 20..=60, `total_len ≤ buf.len()`, and
  rejects fragments; every accessor is then panic-free. `payload()` is trimmed to `total_len`
  so device slack never leaks into an L4 checksum. (`wire/T8,T9,T10,T11`)
- Emission is a single `emit()` entry point that writes fields in the correct order
  (version/IHL/total_len before payload, checksum last). (`wire/N3`)

### 5.2 Sequence arithmetic (`seq`) — M1

`SeqNumber(u32)` derives `PartialEq/Eq` **only — never `Ord`**; all comparisons go through
signed `wrapping_sub` (RFC 1982). This is "the single most common stack-killer." SYN and FIN
each consume one sequence slot in `SEG.LEN`. (`state/T1,T2`, `retx/T1`)

### 5.3 State machine (`state`, `tcb`) — M1/M2

All 11 RFC 793 states; transitions driven by both incoming segments and application calls, all
on one thread (enforced by `&mut self` transition methods — no interior mutability of the
sequence variables). Verified traps:

- Segment acceptability is an explicit 4-case match on `(SEG.LEN==0, RCV.WND==0)`. ACK bounds
  differ by state: handshake inclusive `[SND.UNA, SND.NXT]`, synchronized data-ACK strict
  `(SND.UNA, SND.NXT]`; window updates gated by WL1/WL2. (`state/T3,T4,T5`)
- **`ack_of_fin` discipline:** `LAST-ACK`/`FIN-WAIT-1`/`CLOSING` transition only when the ACK
  actually covers our FIN — *not* on any bare ACK (the smoltcp #470 regression). TIME-WAIT is
  a live state that keeps ACKing retransmitted FINs and resets its 2·MSL timer each time.
  (`state/N1,T6`)
- RST per RFC 5961: out-of-window RST → silent drop (no ACK); in-window ≠ RCV.NXT → a
  **challenge ACK**, rate-limited with a **per-connection** token bucket (a global counter was
  CVE-2016-5696); never RST-in-reply-to-RST. (`state/T10,N2,N3`)
- ISN = `M + SipHash2-4(secret, 4-tuple)` with `M = micros/4`; the secret is drawn from
  `/dev/urandom` once at startup and never logged (RFC 6528). (`state/T9,N11`)
- A single egress source of truth: `on_segment` records intent only; one `dispatch` builds at
  most one segment per call in a fixed priority order; `poll_at()` returns the min of **all**
  armed deadlines (RTO, delayed-ACK, persist, TIME-WAIT). (`state/T12,X12`)

### 5.4 Retransmission & RTO (`retx`, `rtt`, `timerwheel`) — M2

RTO per RFC 6298 with Jacobson's estimator and Karn's amendment. Verified traps:

- Arm an RTT sample **only when none is in flight** (`sample.is_none()`), always advancing
  `max_seq_sent`; otherwise SRTT is biased low. RTTVAR uses the **old** SRTT and is computed
  **before** SRTT; integer `div_ceil` forms. (`retx/N1,T3`)
- Initial RTO 1 s; clamp to `[1 s, 60 s]`; double on each timeout (Karn backoff); **clear the
  backoff on a clean ACK** of never-retransmitted data; after ≥3 RTOs drop the measurement to
  re-bootstrap. Never sample RTT from a retransmitted segment. (`retx/T2,N2,X4`, `state/N8`)
- Valid-ACK predicate is exactly `snd_una.lt(ack) && ack.le(snd_nxt)`. A partial ACK never
  pops a segment as fully acked. (`retx/N4,T10`)
- Timer wheel: one entry per connection = `poll_at()`, recomputed after **every** mutation;
  a generation counter is validated on pop; cascades re-hash from the *current* deadline; a
  late wakeup fires **all** sub-timers due at `now` (no else-if). The `poll_at → schedule()`
  contract is mandatory — it is the lost-wakeup guard for delayed-ACK and zero-window probes.
  (`retx/T7,N5,N6,X6`)

### 5.5 Congestion control (`congestion`) — M3

TCP Tahoe, everything in **bytes**. Verified traps:

- Congestion avoidance counts **bytes acked** with a `while` loop
  (`ca_acc += acked; while ca_acc >= cwnd { ca_acc -= cwnd; cwnd += mss }`). The naive
  `ca_acc += MSS` / `if` form under-grows under delayed or stretch ACKs. (`congestion/N1,N2`)
- On loss, `ssthresh = max(FlightSize/2, 2·MSS)` from a passed `flight_size`, **not cwnd**;
  Tahoe sets `cwnd = 1·MSS` on both a 3-dup-ACK and an RTO, with **no fast recovery**.
  `IW = min(10·MSS, max(2·MSS, 14600))` (RFC 6928). (`congestion/T1,T2`)
- The load-bearing send gate lives *inside* the tested module:
  `allowed_to_send = min(cwnd, rwnd).saturating_sub(snd_nxt − snd_una)`, unit-tested across a
  2³² wrap. The zero-window probe bypasses cwnd. (`congestion/X5,T4`)

### 5.6 Async runtime (`runtime`) — M4

Hand-rolled executor + reactor exposing `TcpListener`/`TcpStream`. Verified traps:

- Store the `Waker` **before** releasing the lock guarding the buffer check (lost wakeup);
  clone+overwrite on every `Pending`; one-shot `take()` in the reactor. (`async/T1,T2`)
- Errors are **sticky** (store `ErrorKind`, return a fresh `io::Error` each poll), with
  `peer_closed` (FIN → `Ok(0)`) tracked separately from reset (RST → `Err`). A zero-length
  read returns `Ok(0)` immediately. (`async/T6,N6,N8`)
- **Listener pool:** when a socket leaves LISTEN it is replaced immediately, so a second/
  keep-alive connection is accepted (the single biggest win-condition gap). Connections are
  reaped once `Closed` and the app handle is dropped. (`async/N1,N10`)
- Reactor: drive the core to quiescence each wake (bounded), recompute the deadline *after*
  processing TX, and clamp `poll_at` (None → block on the fd only; past → zero). (`async/N2,N7`)

### 5.7 Device & demo (`tun`, `sys`, scripts, `http`) — M0/M5

- Open `IFF_TUN | IFF_NO_PI` (Layer-3 raw IP, no 4-byte packet-info prefix; verified
  `== 0x1001`) and `O_NONBLOCK`. `EWOULDBLOCK` means "done", `EINTR` retries. Per-packet TX
  errors (`EMSGSIZE`) are dropped+logged, **never** fatal to the reactor. The read buffer is
  larger than the MTU and `total_len` is validated as the authoritative length.
  (`device-icmp/T1,T2,T3,N1,N3`)
- **No ARP, no Ethernet.** A TUN device is Layer 3; the framing in the original brief ("IP at
  byte 14") is the TAP layout. We demux IPv4 by the version nibble. (`state/X6`)
- **Checksum offload (the #1 demo-killer):** the host kernel leaves TCP checksums zero/partial
  on locally-originated `curl` traffic because it assumes hardware offload. `tun-up.sh`
  disables it (`ethtool -K tun0 tx off …`), and the core additionally accepts an inbound TCP
  checksum of `0x0000` as a fallback. (`device-icmp/N2,X1`)
- HTTP responder buffers until `\r\n\r\n`, responds exactly once (a `responded` flag; scans
  only newly-appended bytes), and sets `Content-Length`. (`device-icmp/T13,X7`)

## 6. End-to-end data flow (one `curl` request)

1. `curl` → kernel routes `10.0.0.2` to `tun0` → the IP datagram appears on our fd.
2. Reactor `recv` → `Ipv4Packet::new_checked` → demux to TCP → `TcpPacket` + checksum check.
3. `iface.on_recv` feeds the segment to the connection's `tcb`: state transition, ACK
   processing (RTT sample, cwnd update), data appended to the rx ring, RCV.NXT advanced.
4. The reactor wakes the parked `accept`/`read` future; the HTTP task runs, parses the request,
   and `write`s the response into the tx ring.
5. `iface.poll_egress` builds segments bounded by `min(cwnd, rwnd) − in_flight` and MSS,
   stamps checksums, and the reactor writes them to `tun0`; the retransmit timer is armed.
6. The peer's ACKs slide the window and free retransmit buffers; FIN/ACK then teardown into
   TIME-WAIT, reaped 2·MSL later.

## 7. Test strategy

- **Unit (runs on 1.92 locally and 1.75 on the VPS):** checksum RFC-1071 vectors (odd length,
  sums-to-0xFFFF); IPv4/TCP parse edge cases; `SeqNumber` wrap properties; RTO estimator vs
  RFC 6298 worked examples; Tahoe transitions + `allowed_to_send` across a 2³² wrap; timer-wheel
  cancel/reschedule/cascade.
- **Integration (in-memory `MockDevice`):** full handshake / transfer / teardown between two
  stack instances, under injected loss, reordering, and duplication; TIME-WAIT reaping via a
  fake clock; multi-connection accept; zero-window persist recovery.
- **End-to-end (VPS over TUN):** `ping 10.0.0.2`; `curl http://10.0.0.2:8080`; concurrent and
  keep-alive curls; `tcpdump -i tun0` captures archived as evidence.

## 8. Build milestones

| # | Deliverable | Demo |
|---|---|---|
| M0 | device + IPv4/ICMP + checksums + reactor skeleton | `ping 10.0.0.2` ✅ |
| M1 | TCP wire + SeqNumber + handshake + RST | `curl` completes the handshake |
| M2 | rings + retransmission + RTO + timer wheel + teardown | reliable echo under injected loss |
| M3 | Tahoe congestion control | bulk transfer: slow-start → CA → fast-retransmit |
| M4 | async executor + reactor + sockets | async echo server, concurrent connections |
| M5 | HTTP responder | **`curl http://10.0.0.2:8080`** |
| M6 | hardening + docs + portfolio polish | full suite green on 1.92 and 1.75 |

## 9. Environment

Built on a locked-down Ubuntu 22.04 VPS reached via an SSH jump host. Key constraints that
shaped the design: no general outbound internet (only the provider apt mirror — hence zero
dependencies and `apt`-installed `rustc`/`cargo` 1.75, which fixes the MSRV); a TUN subnet of
`10.0.0.0/24` deliberately disjoint from the host's SSH (22/2222/443), Docker (`172.x`), and
public (`185.243.x`) networks; and the checksum-offload fix above. We never add a default route
via `tun0` or enable system-wide IP forwarding, so the host's own networking is never at risk.

## 10. References

RFC 791 (IPv4), RFC 793 / 1122 / 9293 (TCP), RFC 1071 (Internet checksum), RFC 1982 (serial
numbers), RFC 5681 + 6928 (congestion control / initial window), RFC 6298 (RTO), RFC 5961 +
6528 (blind-attack hardening / ISN); W. R. Stevens, *TCP/IP Illustrated, Vol. 1*; the smoltcp
source as a cross-reference.
