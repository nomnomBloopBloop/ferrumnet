//! A safe `TunDevice` wrapper around a Linux TUN file descriptor, implementing the runtime's
//! [`Device`] trait.
//!
//! Opened with `IFF_TUN | IFF_NO_PI` (Layer-3 raw IP, no 4-byte packet-info prefix) and
//! `O_NONBLOCK`. Reads/writes go through `std::fs::File`; the device is created when this opens
//! and removed by the kernel when the process exits (unless pre-created persistent).

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;

use tcp_core::Device;

use crate::sys;

const O_NONBLOCK: i32 = 0o4000;
pub const DEFAULT_MTU: usize = 1500;

pub struct TunDevice {
    file: File,
    name: String,
    mtu: usize,
}

impl TunDevice {
    /// Open `/dev/net/tun` and attach to (creating if necessary) the named TUN interface, with
    /// the device MTU the stack should assume. The MTU drives the advertised MSS, so it must
    /// match the kernel interface MTU set by `tun-up.sh` (default 1500). A larger MTU yields a
    /// larger MSS and far fewer packets — and `write` syscalls — for the same data.
    pub fn open(requested_name: &str, mtu: usize) -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(O_NONBLOCK)
            .open("/dev/net/tun")?;
        let flags = sys::IFF_TUN | sys::IFF_NO_PI;
        let name = sys::ioctl_tunsetiff(file.as_raw_fd(), requested_name, flags)?;
        Ok(TunDevice { file, name, mtu })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl Device for TunDevice {
    fn poll_readable(&self, timeout_ms: i32) -> std::io::Result<bool> {
        sys::poll_readable(self.as_raw_fd(), timeout_ms)
    }

    /// Read one IP datagram. `Ok(Some(n))` is a packet of length `n`; `Ok(None)` means the
    /// device had nothing ready (`EWOULDBLOCK`). `EINTR` is retried internally.
    fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<Option<usize>> {
        loop {
            match self.file.read(buf) {
                Ok(n) => return Ok(Some(n)),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// Write one IP datagram (atomic for a datagram device). Per-packet errors are returned to
    /// the caller, which drops+logs them rather than tearing down the reactor.
    fn send(&mut self, pkt: &[u8]) -> std::io::Result<()> {
        loop {
            match self.file.write(pkt) {
                Ok(_) => return Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }

    fn mtu(&self) -> usize {
        self.mtu
    }
}
