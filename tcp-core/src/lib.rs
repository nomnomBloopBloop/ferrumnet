//! `tcp-core` — a device-agnostic, **sans-IO** TCP/IP engine.
//!
//! The engine performs **no I/O** and contains **no OS-specific code**. You feed it
//! received IP packets as byte slices and ask it for the bytes it wants to send; the
//! current time is passed in as a parameter rather than read from a clock. Everything that
//! touches a real device or the network lives outside this crate (see the `tcp-tun`
//! backend). That separation is what lets the entire protocol engine — and, later, the
//! async runtime built on top of it — be exhaustively unit-tested on any platform,
//! including under deterministically simulated packet loss and reordering.
//!
//! The crate is written in 100% safe Rust (`#![deny(unsafe_code)]`); the only `unsafe` in
//! the whole project is the handful of syscall bindings in the `tcp-tun` backend.
//!
//! # Module map (filled in milestone by milestone — see `docs/DESIGN.md`)
//!
//! - [`wire`] — zero-copy IPv4/TCP/ICMP header views and the RFC 1071 Internet checksum.
//!
//! Later milestones add: `seq` (RFC 1982 sequence arithmetic), `state`/`tcb` (the TCP
//! state machine), `rtt`/`retx`/`timerwheel` (reliability), `congestion` (Reno),
//! `buffers`, `iface` (the sans-IO driver), `device` (the `Device` trait + mock), and
//! `runtime` (the async executor, reactor, and socket API).

#![deny(unsafe_code)]

pub mod buffers;
pub mod congestion;
pub mod iface;
pub mod isn;
pub mod reasm;
pub mod rtt;
pub mod runtime;
pub mod sack;
pub mod seq;
pub mod state;
pub mod tcb;
pub mod time;
pub mod wire;

pub use congestion::CcKind;
pub use iface::{Endpoint, Stack};
pub use runtime::{
    Connect, Device, MockDevice, Runtime, Spawner, TcpConnector, TcpListener, TcpStream,
};
pub use seq::SeqNumber;
pub use state::State;
pub use time::Instant;
