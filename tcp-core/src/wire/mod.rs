//! Zero-copy wire-format parsing/emission and the Internet checksum.
//!
//! Read paths hand out borrowed views (`Ipv4Packet<'_>`) over the device's receive buffer;
//! write paths use value-typed `*Repr` emitters that own no borrow. Keeping the two strictly
//! separate is what lets the RX (immutable-borrow) phase and the TX (mutable-borrow) phase
//! coexist without fighting the borrow checker.

pub mod checksum;
pub mod icmp;
pub mod ipv4;

pub use checksum::{IPPROTO_ICMP, IPPROTO_TCP};
pub use icmp::echo_reply;
pub use ipv4::{Ipv4Packet, Ipv4Repr, ParseError};
