//! A safe `TunDevice` wrapper around a Linux TUN file descriptor.
//!
//! Opened with `IFF_TUN | IFF_NO_PI` (Layer-3 raw IP, no 4-byte packet-info prefix) and
//! `O_NONBLOCK`. Reads/writes go through `std::fs::File`; the device is created when this
//! opens and removed by the kernel when the process exits (unless it was pre-created
//! persistent).

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;

use crate::sys;

const O_NONBLOCK: i32 = 0o4000;
pub const DEFAULT_MTU: usize = 1500;

pub struct TunDevice {
    file: File,
    name: String,
    mtu: usize,
}

impl TunDevice {
    /// Open `/dev/net/tun` and attach to (creating if necessary) the named TUN interface.
    pub fn open(requested_name: &str) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(O_NONBLOCK)
            .open("/dev/net/tun")?;
        let flags = sys::IFF_TUN | sys::IFF_NO_PI;
        let name = sys::ioctl_tunsetiff(file.as_raw_fd(), requested_name, flags)?;
        Ok(TunDevice {
            file,
            name,
            mtu: DEFAULT_MTU,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    /// Read one IP datagram. `Ok(Some(n))` is a packet of length `n`; `Ok(None)` means the
    /// device had nothing ready (`EWOULDBLOCK`). `EINTR` is retried internally.
    pub fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<Option<usize>> {
        loop {
            match self.file.read(buf) {
                Ok(n) => return Ok(Some(n)),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// Write one IP datagram (atomic for a datagram device — no partial writes). Per-packet
    /// errors (`EMSGSIZE` for an oversize segment, `EWOULDBLOCK` under backpressure) are
    /// returned to the caller, which drops+logs them rather than tearing down the reactor.
    pub fn send(&mut self, pkt: &[u8]) -> std::io::Result<()> {
        loop {
            match self.file.write(pkt) {
                Ok(_) => return Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// Block until the device is readable or `timeout_ms` elapses (`-1` = forever).
    pub fn poll_readable(&self, timeout_ms: i32) -> std::io::Result<bool> {
        sys::poll_readable(self.as_raw_fd(), timeout_ms)
    }
}
