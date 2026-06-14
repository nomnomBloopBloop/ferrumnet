//! RFC 1982 serial-number arithmetic for 32-bit TCP sequence numbers.
//!
//! The cardinal rule of a TCP implementation: **never** compare sequence numbers with `<` or
//! a derived `Ord`. Sequence space wraps at 2^32, so "before/after" is defined by *signed
//! distance*, not magnitude — `0xFFFF_FFFF` is one *before* `0`, not four billion after it.
//!
//! [`SeqNumber`] therefore derives `PartialEq`/`Eq` but deliberately **not** `Ord`; every
//! comparison goes through [`SeqNumber::distance`] (a `wrapping_sub` reinterpreted as `i32`).
//! Distance is well defined for offsets in `(-2^31, 2^31)`; callers must keep windows below
//! 2^31 (TCP windows are at most 2^30 with scaling, so this always holds).

/// A 32-bit TCP sequence (or acknowledgement) number with serial arithmetic.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct SeqNumber(pub u32);

impl SeqNumber {
    #[inline]
    pub const fn new(value: u32) -> Self {
        SeqNumber(value)
    }

    #[inline]
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Signed distance `self - other` (mod 2^32). Positive means `self` is *after* `other`.
    #[inline]
    pub fn distance(self, other: SeqNumber) -> i32 {
        self.0.wrapping_sub(other.0) as i32
    }

    /// Unsigned forward offset `self - base` (mod 2^32). Use when the caller knows `self` is
    /// at or after `base` (e.g. `FlightSize = snd_nxt.offset_from(snd_una)`).
    #[inline]
    pub fn offset_from(self, base: SeqNumber) -> u32 {
        self.0.wrapping_sub(base.0)
    }

    #[inline]
    pub fn lt(self, other: SeqNumber) -> bool {
        self.distance(other) < 0
    }
    #[inline]
    pub fn le(self, other: SeqNumber) -> bool {
        self.distance(other) <= 0
    }
    #[inline]
    pub fn gt(self, other: SeqNumber) -> bool {
        self.distance(other) > 0
    }
    #[inline]
    pub fn ge(self, other: SeqNumber) -> bool {
        self.distance(other) >= 0
    }

    /// Smaller of two sequence numbers in serial order.
    #[inline]
    pub fn min(self, other: SeqNumber) -> SeqNumber {
        if self.le(other) {
            self
        } else {
            other
        }
    }

    /// Larger of two sequence numbers in serial order.
    #[inline]
    pub fn max(self, other: SeqNumber) -> SeqNumber {
        if self.ge(other) {
            self
        } else {
            other
        }
    }
}

// `seq + len` advances by a byte count, wrapping. We intentionally do NOT implement
// `Sub<u32>` or `Sub<SeqNumber>` as operators: subtraction is ambiguous (signed distance vs
// unsigned offset), so it is spelled out via `distance` / `offset_from`.
impl core::ops::Add<u32> for SeqNumber {
    type Output = SeqNumber;
    #[inline]
    fn add(self, rhs: u32) -> SeqNumber {
        SeqNumber(self.0.wrapping_add(rhs))
    }
}

impl core::ops::AddAssign<u32> for SeqNumber {
    #[inline]
    fn add_assign(&mut self, rhs: u32) {
        self.0 = self.0.wrapping_add(rhs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_wraps_around_zero() {
        let a = SeqNumber::new(0xFFFF_FFFF);
        let b = SeqNumber::new(0);
        assert!(a.lt(b), "0xFFFFFFFF is one *before* 0");
        assert!(b.gt(a));
        assert_eq!(b.distance(a), 1);
        assert_eq!(a.distance(b), -1);
    }

    #[test]
    fn add_wraps() {
        assert_eq!(SeqNumber::new(0xFFFF_FFFF) + 2, SeqNumber::new(1));
        let mut s = SeqNumber::new(0xFFFF_FFFE);
        s += 5;
        assert_eq!(s, SeqNumber::new(3));
    }

    #[test]
    fn offset_from_is_unsigned_forward_distance() {
        assert_eq!(SeqNumber::new(10).offset_from(SeqNumber::new(4)), 6);
        // FlightSize across the wrap: nxt just past the boundary, una just before it.
        let una = SeqNumber::new(0xFFFF_FF00);
        let nxt = SeqNumber::new(0x40);
        assert_eq!(nxt.offset_from(una), 0x140);
    }

    #[test]
    fn near_half_window_orders_correctly() {
        // Just under 2^31 apart: ordering is unambiguous.
        let a = SeqNumber::new(0);
        let b = SeqNumber::new(0x7FFF_FFFF);
        assert!(a.lt(b));
        assert!(b.gt(a));
    }

    #[test]
    fn min_max_in_serial_order() {
        let lo = SeqNumber::new(0xFFFF_FFF0);
        let hi = SeqNumber::new(0x10); // after lo across the wrap
        assert_eq!(lo.min(hi), lo);
        assert_eq!(lo.max(hi), hi);
    }
}
