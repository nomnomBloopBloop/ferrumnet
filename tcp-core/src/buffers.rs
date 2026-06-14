//! A bounded byte ring buffer, used for both the send and receive queues.
//!
//! Send side: bytes the application has written but the peer has not yet acknowledged live
//! here; `peek` reads at an offset (to (re)build a segment) without removing, and `consume`
//! drops bytes off the front when an ACK advances `SND.UNA`.
//!
//! Receive side: in-order bytes delivered by the peer wait here until the application reads
//! them; the free space drives the advertised window.

use std::collections::VecDeque;

pub struct RingBuffer {
    buf: VecDeque<u8>,
    capacity: usize,
}

impl RingBuffer {
    pub fn with_capacity(capacity: usize) -> Self {
        RingBuffer {
            buf: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    #[inline]
    pub fn free(&self) -> usize {
        self.capacity - self.buf.len()
    }

    /// Append up to `free()` bytes from `data`; returns how many were accepted.
    pub fn write(&mut self, data: &[u8]) -> usize {
        let n = data.len().min(self.free());
        self.buf.extend(&data[..n]);
        n
    }

    /// Copy up to `dst.len()` bytes starting `offset` bytes from the front into `dst`, WITHOUT
    /// removing them. Returns the number copied. Used to (re)build outbound segments.
    pub fn peek(&self, offset: usize, dst: &mut [u8]) -> usize {
        let mut n = 0;
        for (i, &byte) in self.buf.iter().skip(offset).enumerate() {
            if i >= dst.len() {
                break;
            }
            dst[i] = byte;
            n += 1;
        }
        n
    }

    /// Remove `n` bytes from the front (an ACK advanced `SND.UNA`). Returns bytes removed.
    pub fn consume(&mut self, n: usize) -> usize {
        let n = n.min(self.buf.len());
        self.buf.drain(..n);
        n
    }

    /// Pop up to `dst.len()` bytes from the front into `dst` (the application reading rx data).
    pub fn read(&mut self, dst: &mut [u8]) -> usize {
        let n = dst.len().min(self.buf.len());
        for slot in dst.iter_mut().take(n) {
            *slot = self.buf.pop_front().unwrap();
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_respects_capacity() {
        let mut rb = RingBuffer::with_capacity(4);
        assert_eq!(rb.write(b"abcdef"), 4); // only 4 fit
        assert_eq!(rb.len(), 4);
        assert_eq!(rb.free(), 0);
        assert_eq!(rb.write(b"x"), 0);
    }

    #[test]
    fn peek_does_not_consume_and_honors_offset() {
        let mut rb = RingBuffer::with_capacity(16);
        rb.write(b"hello world");
        let mut out = [0u8; 5];
        assert_eq!(rb.peek(6, &mut out), 5);
        assert_eq!(&out, b"world");
        assert_eq!(rb.len(), 11); // unchanged
        // Offset past the end copies nothing.
        assert_eq!(rb.peek(99, &mut out), 0);
    }

    #[test]
    fn consume_then_peek_reflects_new_front() {
        let mut rb = RingBuffer::with_capacity(16);
        rb.write(b"0123456789");
        assert_eq!(rb.consume(3), 3);
        assert_eq!(rb.len(), 7);
        assert_eq!(rb.free(), 16 - 7);
        let mut out = [0u8; 4];
        assert_eq!(rb.peek(0, &mut out), 4);
        assert_eq!(&out, b"3456");
    }

    #[test]
    fn read_pops_from_front() {
        let mut rb = RingBuffer::with_capacity(8);
        rb.write(b"abcd");
        let mut out = [0u8; 2];
        assert_eq!(rb.read(&mut out), 2);
        assert_eq!(&out, b"ab");
        assert_eq!(rb.len(), 2);
        let mut rest = [0u8; 8];
        assert_eq!(rb.read(&mut rest), 2);
        assert_eq!(&rest[..2], b"cd");
        assert!(rb.is_empty());
    }

    #[test]
    fn write_wraps_after_consume() {
        // Force the underlying ring to wrap and confirm peek still sees a logical view.
        let mut rb = RingBuffer::with_capacity(8);
        rb.write(b"12345678");
        rb.consume(5); // front now at logical "6"
        assert_eq!(rb.write(b"abcd"), 4); // wraps around
        let mut out = [0u8; 7];
        assert_eq!(rb.peek(0, &mut out), 7);
        assert_eq!(&out, b"678abcd");
    }
}
