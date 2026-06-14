//! The eleven TCP connection states (RFC 793 §3.2). All are defined up front; the handshake
//! milestone (M1) drives `Listen → SynReceived → Established` (and `CloseWait` on a peer FIN),
//! and the teardown milestone (M2) exercises the remaining closing states. The enum is part of
//! the public API, so unused-for-now variants are not dead code.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}
