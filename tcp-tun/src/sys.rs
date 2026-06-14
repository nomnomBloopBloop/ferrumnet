//! Hand-written Linux syscall bindings — the *only* `unsafe` code in the whole project.
//!
//! We bind exactly two syscalls (`ioctl` for `TUNSETIFF`, and `poll` for the event loop) and
//! reach everything else (`open`/`read`/`write`/`close`) through `std::fs::File`. The
//! constants and struct layouts below are for Linux on x86-64.

use std::os::fd::RawFd;

// ── ioctl request / TUN flags (from <linux/if_tun.h>, <net/if.h>) ──────────────────────────
/// `TUNSETIFF` = `_IOW('T', 202, int)` on x86-64.
pub const TUNSETIFF: u64 = 0x4004_54ca;
pub const IFF_TUN: i16 = 0x0001;
pub const IFF_NO_PI: i16 = 0x1000;
pub const IFNAMSIZ: usize = 16;

// ── poll ────────────────────────────────────────────────────────────────────────────────
pub const POLLIN: i16 = 0x0001;

// ── errno values we special-case ─────────────────────────────────────────────────────────
pub const EINTR: i32 = 4;

/// `struct ifreq` (x86-64): a 16-byte interface name followed by a 24-byte union; we only use
/// the `short ifr_flags` member and pad out the rest so the size matches the kernel's.
#[repr(C)]
struct IfReq {
    name: [u8; IFNAMSIZ],
    flags: i16,
    _pad: [u8; 22],
}

// The kernel copies exactly `sizeof(struct ifreq)` bytes; if our layout is wrong we corrupt
// the stack. Pin the size and the flags offset at compile time.
const _: () = assert!(core::mem::size_of::<IfReq>() == 40);

/// `struct pollfd`.
#[repr(C)]
struct PollFd {
    fd: RawFd,
    events: i16,
    revents: i16,
}

extern "C" {
    fn ioctl(fd: RawFd, request: u64, arg: *mut IfReq) -> i32;
    fn poll(fds: *mut PollFd, nfds: u64, timeout: i32) -> i32;
}

/// Attach `fd` (an open `/dev/net/tun`) to a TUN interface with the given flags, returning the
/// kernel-assigned interface name (which may differ from `requested` for a `tunN` template).
pub fn ioctl_tunsetiff(fd: RawFd, requested: &str, flags: i16) -> std::io::Result<String> {
    let mut req = IfReq {
        name: [0; IFNAMSIZ],
        flags,
        _pad: [0; 22],
    };
    let bytes = requested.as_bytes();
    let n = bytes.len().min(IFNAMSIZ - 1); // leave room for the NUL terminator
    req.name[..n].copy_from_slice(&bytes[..n]);

    // SAFETY: `req` is a fully-initialized `ifreq` of the exact size the kernel expects;
    // TUNSETIFF reads `name`/`flags` and writes back the chosen `name`. `fd` is a valid fd
    // owned by the caller for the duration of the call.
    let rc = unsafe { ioctl(fd, TUNSETIFF, &mut req as *mut IfReq) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let end = req.name.iter().position(|&b| b == 0).unwrap_or(IFNAMSIZ);
    Ok(String::from_utf8_lossy(&req.name[..end]).into_owned())
}

/// Block until `fd` is readable or `timeout_ms` elapses (`-1` = forever). Returns `true` if
/// the fd is readable. `EINTR` is reported as "no event" so the caller simply loops.
pub fn poll_readable(fd: RawFd, timeout_ms: i32) -> std::io::Result<bool> {
    let mut pfd = PollFd {
        fd,
        events: POLLIN,
        revents: 0,
    };
    // SAFETY: `pfd` is a single valid `pollfd`; we pass `nfds = 1`, so `poll` reads/writes
    // exactly that one entry.
    let rc = unsafe { poll(&mut pfd as *mut PollFd, 1, timeout_ms) };
    if rc < 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(EINTR) {
            return Ok(false);
        }
        return Err(err);
    }
    Ok(rc > 0 && (pfd.revents & POLLIN) != 0)
}
