//! An `io_uring`-backed TUN device that batches all reads and writes.
//!
//! The blocking [`crate::tun::TunDevice`] pays one `read`/`write` syscall per packet, which at the
//! 1500-byte MTU is the dominant cost (≈50% system time on the VPS). This backend keeps a pool of
//! pre-posted READ buffers and queues WRITE submissions, then flushes **all** of them — plus the
//! re-posts for consumed read buffers — with a single `io_uring_enter` per event-loop iteration.
//! Completions are reaped straight from the mapped CQ with no syscall. The reactor's timeout wait
//! still goes through `poll()` on the ring fd (which becomes readable when a completion lands), so
//! the syscall count per iteration drops from `N reads + M writes + poll` to `enter + poll`.
//!
//! `IORING_OP_READ`/`WRITE` are generic file ops, so unlike `sendmmsg`/`writev` they work on a TUN
//! char device. Offsets are `-1` (current position) — the kernel reports `IORING_FEAT_RW_CUR_POS`.
//!
//! This is hand-rolled against the raw `io_uring_setup`/`io_uring_enter` syscalls and `mmap`
//! (zero dependencies); the struct layouts and constants are pinned to `<linux/io_uring.h>` for
//! x86-64 and checked at compile time. All of the project's io_uring `unsafe` lives here.

use std::collections::VecDeque;
use std::ffi::{c_int, c_long, c_void};
use std::io;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicU32, Ordering};

use tcp_core::Device;

use crate::tun::TunDevice;

// ── syscall numbers (x86-64) ──────────────────────────────────────────────────────────────────
const SYS_IO_URING_SETUP: c_long = 425;
const SYS_IO_URING_ENTER: c_long = 426;

// ── io_uring constants (<linux/io_uring.h>) ───────────────────────────────────────────────────
const IORING_OP_READ: u8 = 22;
const IORING_OP_WRITE: u8 = 23;
const IORING_OFF_SQ_RING: i64 = 0;
const IORING_OFF_SQES: i64 = 0x1000_0000;
const IORING_FEAT_SINGLE_MMAP: u32 = 1 << 0;
const IORING_FEAT_RW_CUR_POS: u32 = 1 << 3;

// ── mmap constants ────────────────────────────────────────────────────────────────────────────
const PROT_READ: c_int = 0x1;
const PROT_WRITE: c_int = 0x2;
const MAP_SHARED: c_int = 0x01;
const MAP_POPULATE: c_int = 0x8000;
const MAP_FAILED: *mut c_void = usize::MAX as *mut c_void; // (void*)-1

// `off == -1` selects the file's current position (read()/write() semantics) on a non-seekable fd.
const OFF_CUR_POS: u64 = u64::MAX;

extern "C" {
    fn syscall(num: c_long, ...) -> c_long;
    fn mmap(addr: *mut c_void, len: usize, prot: c_int, flags: c_int, fd: c_int, offset: i64) -> *mut c_void;
    fn munmap(addr: *mut c_void, len: usize) -> c_int;
}

// ── ABI structs, pinned to the kernel header and size-checked ─────────────────────────────────

#[repr(C)]
#[derive(Default)]
struct IoSqringOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    flags: u32,
    dropped: u32,
    array: u32,
    resv1: u32,
    resv2: u64,
}

#[repr(C)]
#[derive(Default)]
struct IoCqringOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    overflow: u32,
    cqes: u32,
    flags: u32,
    resv1: u32,
    resv2: u64,
}

#[repr(C)]
#[derive(Default)]
struct IoUringParams {
    sq_entries: u32,
    cq_entries: u32,
    flags: u32,
    sq_thread_cpu: u32,
    sq_thread_idle: u32,
    features: u32,
    wq_fd: u32,
    resv: [u32; 3],
    sq_off: IoSqringOffsets,
    cq_off: IoCqringOffsets,
}

#[repr(C)]
struct IoUringSqe {
    opcode: u8,
    flags: u8,
    ioprio: u16,
    fd: i32,
    off: u64,
    addr: u64,
    len: u32,
    rw_flags: u32,
    user_data: u64,
    buf_index: u16,
    personality: u16,
    splice_fd_in: i32,
    _pad2: [u64; 2],
}

#[repr(C)]
struct IoUringCqe {
    user_data: u64,
    res: i32,
    flags: u32,
}

const _: () = assert!(core::mem::size_of::<IoUringParams>() == 120);
const _: () = assert!(core::mem::size_of::<IoSqringOffsets>() == 40);
const _: () = assert!(core::mem::size_of::<IoUringCqe>() == 16);
const _: () = assert!(core::mem::size_of::<IoUringSqe>() == 64);

// ── the ring ──────────────────────────────────────────────────────────────────────────────────

/// A minimal single-threaded io_uring: a mapped SQ/CQ ring plus the SQE array. Not `Send`/`Sync`
/// (single reactor thread). Submissions are batched locally and published with one `submit`.
struct IoUring {
    ring_fd: RawFd,
    ring_ptr: *mut u8,
    ring_sz: usize,
    sqes_ptr: *mut IoUringSqe,
    sqes_sz: usize,

    sq_head: *mut u32,
    sq_tail: *mut u32,
    sq_mask: u32,
    cq_head: *mut u32,
    cq_tail: *mut u32,
    cq_mask: u32,
    cqes: *const IoUringCqe,

    /// Our cached SQ tail; published to the kernel by `submit`.
    sq_local_tail: u32,
    /// SQEs pushed since the last `submit` (the `to_submit` count for `io_uring_enter`).
    pending: u32,
}

impl IoUring {
    fn new(entries: u32) -> io::Result<Self> {
        let mut p = IoUringParams::default();
        // SAFETY: `p` is a zeroed, correctly-sized io_uring_params; io_uring_setup fills it.
        let fd = unsafe { syscall(SYS_IO_URING_SETUP, entries as c_long, &mut p as *mut IoUringParams) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let ring_fd = fd as RawFd;

        // This backend relies on the single-mmap layout (one mapping for both rings) and on
        // current-position reads/writes; both are reported on kernels >= 5.4. If absent, bail so
        // the caller falls back to the blocking device.
        if p.features & IORING_FEAT_SINGLE_MMAP == 0 || p.features & IORING_FEAT_RW_CUR_POS == 0 {
            // SAFETY: ring_fd is the just-created, still-owned io_uring fd.
            unsafe { close(ring_fd) };
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "io_uring lacks SINGLE_MMAP / RW_CUR_POS (kernel too old)",
            ));
        }

        let sq_ring_sz = (p.sq_off.array + p.sq_entries * 4) as usize;
        let cq_ring_sz = (p.cq_off.cqes + p.cq_entries * core::mem::size_of::<IoUringCqe>() as u32) as usize;
        let ring_sz = sq_ring_sz.max(cq_ring_sz);
        let sqes_sz = p.sq_entries as usize * core::mem::size_of::<IoUringSqe>();

        // SAFETY: map the kernel-provided SQ/CQ ring and the SQE array at the documented offsets.
        let ring_ptr = unsafe {
            mmap(core::ptr::null_mut(), ring_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring_fd, IORING_OFF_SQ_RING)
        };
        if ring_ptr == MAP_FAILED {
            let e = io::Error::last_os_error();
            unsafe { close(ring_fd) };
            return Err(e);
        }
        let sqes = unsafe {
            mmap(core::ptr::null_mut(), sqes_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring_fd, IORING_OFF_SQES)
        };
        if sqes == MAP_FAILED {
            let e = io::Error::last_os_error();
            unsafe {
                munmap(ring_ptr, ring_sz);
                close(ring_fd);
            }
            return Err(e);
        }

        // SAFETY: every offset below is within the just-mapped ring (the kernel sized it); each
        // field is a naturally-aligned u32 at a 4-byte-aligned offset.
        let ring = ring_ptr as *mut u8;
        let at = |off: u32| unsafe { ring.add(off as usize) as *mut u32 };
        let sq_mask = unsafe { *at(p.sq_off.ring_mask) };
        let cq_mask = unsafe { *at(p.cq_off.ring_mask) };
        let sq_array = at(p.sq_off.array);
        let sq_tail = at(p.sq_off.tail);
        let sq_head = at(p.sq_off.head);

        // Identity-map the SQ array (index i -> SQE i) once; we only ever bump the tail after.
        for i in 0..p.sq_entries {
            // SAFETY: i < sq_entries, so sq_array[i] is in bounds.
            unsafe { *sq_array.add(i as usize) = i };
        }

        Ok(IoUring {
            ring_fd,
            ring_ptr: ring,
            ring_sz,
            sqes_ptr: sqes as *mut IoUringSqe,
            sqes_sz,
            sq_head,
            sq_tail,
            sq_mask,
            cq_head: at(p.cq_off.head),
            cq_tail: at(p.cq_off.tail),
            cq_mask,
            cqes: unsafe { ring.add(p.cq_off.cqes as usize) } as *const IoUringCqe,
            sq_local_tail: 0,
            pending: 0,
        })
    }

    #[inline]
    fn ring_fd(&self) -> RawFd {
        self.ring_fd
    }

    /// Free SQ slots before the kernel-consumed head wraps onto unsubmitted entries.
    #[inline]
    fn sq_free(&self) -> u32 {
        let entries = self.sq_mask + 1;
        // SAFETY: sq_head points at a live u32 in the mapped ring; read it atomically.
        let head = unsafe { (*(self.sq_head as *const AtomicU32)).load(Ordering::Acquire) };
        entries - self.sq_local_tail.wrapping_sub(head)
    }

    /// Queue one SQE (not yet submitted). `addr`/`len` describe the buffer, which the caller must
    /// keep valid and untouched until the matching completion is reaped.
    ///
    /// # Safety
    /// `fd` must be a valid fd, and the `addr`/`len` region must stay alive and unaliased until the
    /// completion carrying `user_data` is observed. There must be a free SQ slot (`sq_free() > 0`).
    unsafe fn push(&mut self, opcode: u8, fd: RawFd, addr: u64, len: u32, off: u64, user_data: u64) {
        let idx = (self.sq_local_tail & self.sq_mask) as usize;
        let sqe = IoUringSqe {
            opcode,
            flags: 0,
            ioprio: 0,
            fd,
            off,
            addr,
            len,
            rw_flags: 0,
            user_data,
            buf_index: 0,
            personality: 0,
            splice_fd_in: 0,
            _pad2: [0; 2],
        };
        // The SQ array already maps idx -> idx, so writing the SQE at sqes[idx] is enough.
        core::ptr::write(self.sqes_ptr.add(idx), sqe);
        self.sq_local_tail = self.sq_local_tail.wrapping_add(1);
        self.pending += 1;
    }

    /// Publish the queued SQEs and ask the kernel to submit them (one `io_uring_enter`).
    fn submit(&mut self) -> io::Result<()> {
        if self.pending == 0 {
            return Ok(());
        }
        // Release-store the tail so the kernel sees every queued SQE before the new tail value.
        // SAFETY: sq_tail is a live u32 in the mapped ring.
        unsafe { (*(self.sq_tail as *const AtomicU32)).store(self.sq_local_tail, Ordering::Release) };
        let to_submit = self.pending;
        // SAFETY: a plain submit (no GETEVENTS, no sigmask) on our own ring fd.
        let rc = unsafe { syscall(SYS_IO_URING_ENTER, self.ring_fd as c_long, to_submit as c_long, 0, 0, 0, 0) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        self.pending = 0;
        Ok(())
    }

    /// Reap every available completion, calling `f(user_data, res)` for each.
    fn reap(&mut self, mut f: impl FnMut(u64, i32)) {
        // SAFETY: cq_head/cq_tail are live u32s in the mapped ring; cqes points at the CQE array.
        let mut head = unsafe { (*(self.cq_head as *const AtomicU32)).load(Ordering::Relaxed) };
        let tail = unsafe { (*(self.cq_tail as *const AtomicU32)).load(Ordering::Acquire) };
        while head != tail {
            let idx = (head & self.cq_mask) as usize;
            // SAFETY: idx <= cq_mask, so this CQE slot is in bounds.
            let cqe = unsafe { core::ptr::read(self.cqes.add(idx)) };
            f(cqe.user_data, cqe.res);
            head = head.wrapping_add(1);
        }
        // Release-store the head so the kernel may reuse the slots we just consumed.
        unsafe { (*(self.cq_head as *const AtomicU32)).store(head, Ordering::Release) };
    }
}

impl Drop for IoUring {
    fn drop(&mut self) {
        // SAFETY: the two mappings and the ring fd were created in `new` and are owned by self.
        unsafe {
            munmap(self.sqes_ptr as *mut c_void, self.sqes_sz);
            munmap(self.ring_ptr as *mut c_void, self.ring_sz);
            close(self.ring_fd);
        }
    }
}

// `close` via the libc symbol (std links libc); avoids dragging in another extern block elsewhere.
extern "C" {
    fn close(fd: c_int) -> c_int;
}

// ── completion tagging ────────────────────────────────────────────────────────────────────────
// user_data: high bit distinguishes WRITE (buffer index in the low bits) from READ.
const WRITE_TAG: u64 = 1 << 63;
#[inline]
fn read_ud(i: usize) -> u64 {
    i as u64
}
#[inline]
fn write_ud(j: usize) -> u64 {
    WRITE_TAG | j as u64
}

// ── the device ────────────────────────────────────────────────────────────────────────────────

const N_READ: usize = 256;
const N_WRITE: usize = 512;

/// A [`Device`] that drives a TUN fd through io_uring, batching I/O across the event loop.
pub struct IoUringTun {
    tun: TunDevice,
    ring: IoUring,
    bufsz: usize,
    read_bufs: Vec<Vec<u8>>,
    write_bufs: Vec<Vec<u8>>,
    /// Read buffers holding a received packet: `(buffer index, length)`.
    read_ready: VecDeque<(usize, usize)>,
    /// Read buffers drained by `recv`, awaiting a re-post on the next `poll_readable`.
    repost: Vec<usize>,
    /// Write buffers free for reuse.
    write_free: Vec<usize>,
}

impl IoUringTun {
    /// Open the TUN interface and set up io_uring over its fd. Falls back to an error (so the
    /// caller can use the blocking device) if the kernel's io_uring is too old.
    pub fn open(name: &str, mtu: usize) -> io::Result<Self> {
        let tun = TunDevice::open(name, mtu)?;
        let bufsz = mtu + 64;
        let entries = ((N_READ + N_WRITE).next_power_of_two()) as u32;
        let ring = IoUring::new(entries)?;
        let read_bufs: Vec<Vec<u8>> = (0..N_READ).map(|_| vec![0u8; bufsz]).collect();
        let write_bufs: Vec<Vec<u8>> = (0..N_WRITE).map(|_| vec![0u8; bufsz]).collect();
        let mut dev = IoUringTun {
            tun,
            ring,
            bufsz,
            read_bufs,
            write_bufs,
            read_ready: VecDeque::new(),
            repost: Vec::new(),
            write_free: (0..N_WRITE).collect(),
        };
        // Post a READ for every read buffer so the kernel starts filling them, and submit.
        let fd = dev.tun.as_raw_fd();
        for i in 0..N_READ {
            let addr = dev.read_bufs[i].as_mut_ptr() as u64;
            // SAFETY: fd is the open TUN fd; read_bufs[i] is owned by dev, stays alive and is not
            // touched until its completion (it is not in read_ready/write_free); the SQ has room
            // (entries >= N_READ). user_data tags it as read buffer i.
            unsafe { dev.ring.push(IORING_OP_READ, fd, addr, dev.bufsz as u32, OFF_CUR_POS, read_ud(i)) };
        }
        dev.ring.submit()?;
        Ok(dev)
    }

    pub fn name(&self) -> &str {
        self.tun.name()
    }

    /// Drain all available completions: read completions become ready packets, write completions
    /// free their buffers.
    fn drain_cq(&mut self) {
        let read_ready = &mut self.read_ready;
        let write_free = &mut self.write_free;
        let repost = &mut self.repost;
        self.ring.reap(|ud, res| {
            if ud & WRITE_TAG != 0 {
                // Write done (or errored): the buffer is reusable either way.
                write_free.push((ud & !WRITE_TAG) as usize);
            } else {
                let i = ud as usize;
                if res > 0 {
                    read_ready.push_back((i, res as usize));
                } else {
                    // Short/zero/errored read: nothing to deliver, just re-arm the buffer.
                    repost.push(i);
                }
            }
        });
    }

    /// Re-post READ submissions for every read buffer `recv` has drained.
    fn post_reposts(&mut self) {
        let fd = self.tun.as_raw_fd();
        while let Some(i) = self.repost.pop() {
            if self.ring.sq_free() == 0 {
                let _ = self.ring.submit();
            }
            let addr = self.read_bufs[i].as_mut_ptr() as u64;
            // SAFETY: as in `open` — read_bufs[i] is owned, idle (just consumed), and stays put
            // until its next completion; SQ room is ensured above.
            unsafe { self.ring.push(IORING_OP_READ, fd, addr, self.bufsz as u32, OFF_CUR_POS, read_ud(i)) };
        }
    }
}

impl Device for IoUringTun {
    fn poll_readable(&mut self, timeout_ms: i32) -> io::Result<bool> {
        // Flush queued writes + read re-posts in one io_uring_enter, then reap what completed.
        self.post_reposts();
        self.ring.submit()?;
        self.drain_cq();
        if !self.read_ready.is_empty() {
            return Ok(true);
        }
        // Nothing ready yet: block on the ring fd (readable once a completion lands), then reap.
        let ready = crate::sys::poll_readable(self.ring.ring_fd(), timeout_ms)?;
        if ready {
            self.drain_cq();
        }
        Ok(!self.read_ready.is_empty())
    }

    fn recv(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        match self.read_ready.pop_front() {
            Some((idx, len)) => {
                let n = len.min(buf.len());
                buf[..n].copy_from_slice(&self.read_bufs[idx][..n]);
                self.repost.push(idx); // re-armed on the next poll_readable
                Ok(Some(n))
            }
            None => Ok(None),
        }
    }

    fn send(&mut self, pkt: &[u8]) -> io::Result<()> {
        if self.write_free.is_empty() {
            // Push out what is queued and reap completions to recover buffers.
            self.post_reposts();
            self.ring.submit()?;
            self.drain_cq();
            if self.write_free.is_empty() {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "io_uring tx buffers exhausted"));
            }
        }
        let j = self.write_free.pop().unwrap();
        let n = pkt.len().min(self.bufsz);
        self.write_bufs[j][..n].copy_from_slice(&pkt[..n]);
        let addr = self.write_bufs[j].as_ptr() as u64;
        let fd = self.tun.as_raw_fd();
        if self.ring.sq_free() == 0 {
            self.ring.submit()?;
        }
        // SAFETY: write_bufs[j] is owned, now in use (popped from write_free), and is not touched
        // again until its write completion returns it to write_free; SQ room is ensured above.
        unsafe { self.ring.push(IORING_OP_WRITE, fd, addr, n as u32, OFF_CUR_POS, write_ud(j)) };
        Ok(())
    }

    fn mtu(&self) -> usize {
        self.tun.mtu()
    }
}
