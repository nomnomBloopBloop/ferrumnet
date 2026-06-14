//! A minimal injected monotonic clock. `tcp-core` never reads a real clock; the backend
//! converts `std::time::Instant` into this and passes it into every entry point, which is what
//! makes timer behaviour deterministically testable.

/// A monotonic instant, measured in microseconds since an arbitrary epoch chosen by the
/// backend (typically the moment the stack started).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Instant {
    micros: u64,
}

impl Instant {
    pub const ZERO: Instant = Instant { micros: 0 };

    #[inline]
    pub const fn from_micros(micros: u64) -> Self {
        Instant { micros }
    }

    #[inline]
    pub const fn from_millis(millis: u64) -> Self {
        Instant {
            micros: millis.saturating_mul(1_000),
        }
    }

    #[inline]
    pub const fn micros(self) -> u64 {
        self.micros
    }

    #[inline]
    pub const fn millis(self) -> u64 {
        self.micros / 1_000
    }

    /// Microseconds elapsed from `earlier` to `self`, saturating at 0 if `self` precedes it.
    #[inline]
    pub const fn saturating_micros_since(self, earlier: Instant) -> u64 {
        self.micros.saturating_sub(earlier.micros)
    }

    /// This instant advanced by `millis` milliseconds.
    #[inline]
    pub const fn plus_millis(self, millis: u64) -> Instant {
        Instant {
            micros: self.micros.saturating_add(millis.saturating_mul(1_000)),
        }
    }
}
