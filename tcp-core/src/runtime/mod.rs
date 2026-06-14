//! A hand-rolled, zero-dependency async runtime layered on the sans-IO core.
//!
//! - [`executor`] — a single-threaded task executor with safe `Waker`s.
//! - [`reactor`] — the [`Runtime`]: a device + the `Stack` + waker registries, driven as one
//!   event loop. Tasks and the reactor share state via `Rc<RefCell<…>>` (single-threaded, so
//!   no hot-path locks).
//! - [`socket`] — [`TcpListener`] / [`TcpStream`] and their `accept`/`read`/`write` futures.
//!
//! A [`Device`] abstracts the wire so the entire runtime can run against the in-memory
//! [`MockDevice`] in tests and against a real Linux TUN device in production.

mod executor;
mod reactor;
mod socket;

pub use executor::{Executor, Spawner};
pub use reactor::Runtime;
pub use socket::{Accept, Read, TcpListener, TcpStream, Write};

use std::collections::VecDeque;

/// The wire the runtime drives: a packet source/sink. Implemented by the Linux TUN backend in
/// `tcp-tun` and by [`MockDevice`] for tests.
pub trait Device {
    /// Block until readable or `timeout_ms` elapses (`-1` = forever). Returns `true` if a
    /// packet is ready to read.
    fn poll_readable(&self, timeout_ms: i32) -> std::io::Result<bool>;
    /// Read one IP datagram. `Ok(Some(n))` is a packet of length `n`; `Ok(None)` means nothing
    /// was ready.
    fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<Option<usize>>;
    /// Write one IP datagram.
    fn send(&mut self, pkt: &[u8]) -> std::io::Result<()>;
    /// The device MTU in bytes.
    fn mtu(&self) -> usize;
}

/// An in-memory [`Device`] for deterministic testing: packets pushed into `inbound` are read
/// by the stack, and packets the stack sends are collected in `outbound`.
#[derive(Default)]
pub struct MockDevice {
    inbound: VecDeque<Vec<u8>>,
    pub outbound: Vec<Vec<u8>>,
}

impl MockDevice {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a datagram for the stack to receive.
    pub fn inject(&mut self, frame: Vec<u8>) {
        self.inbound.push_back(frame);
    }

    /// Take everything the stack has sent since the last call.
    pub fn take_outbound(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.outbound)
    }
}

impl Device for MockDevice {
    fn poll_readable(&self, _timeout_ms: i32) -> std::io::Result<bool> {
        Ok(!self.inbound.is_empty())
    }
    fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<Option<usize>> {
        match self.inbound.pop_front() {
            Some(frame) => {
                let n = frame.len().min(buf.len());
                buf[..n].copy_from_slice(&frame[..n]);
                Ok(Some(n))
            }
            None => Ok(None),
        }
    }
    fn send(&mut self, pkt: &[u8]) -> std::io::Result<()> {
        self.outbound.push(pkt.to_vec());
        Ok(())
    }
    fn mtu(&self) -> usize {
        1500
    }
}
