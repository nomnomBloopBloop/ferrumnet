//! The sans-IO connection driver: owns the listening endpoint and the connection table.
//!
//! The backend drives it in a loop:
//! - [`Stack::on_recv`] — feed one parsed IPv4 datagram (updates state, buffers data, arms
//!   timers); it never emits directly.
//! - [`Stack::on_timer`] — fire every connection's due timers.
//! - [`Stack::poll_transmit`] — drain all datagrams the stack wants to send into a buffer.
//! - [`Stack::poll_at`] — the earliest armed deadline across all connections.

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;

use crate::isn::IsnGenerator;
use crate::seq::SeqNumber;
use crate::state::State;
use crate::tcb::Tcb;
use crate::time::Instant;
use crate::wire::{checksum, Ipv4Packet, Ipv4Repr, SackBlocks, TcpFlags, TcpPacket, TcpRepr, IPPROTO_TCP};

/// An IPv4 address + TCP port. The connection table is keyed by the *remote* endpoint.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Endpoint {
    pub ip: Ipv4Addr,
    pub port: u16,
}

impl Endpoint {
    pub const fn new(ip: Ipv4Addr, port: u16) -> Self {
        Endpoint { ip, port }
    }
}

/// Build one complete IPv4 + TCP datagram (header + options + payload, checksums filled).
pub(crate) fn build_segment(
    local: Endpoint,
    remote: Endpoint,
    tcp: &TcpRepr,
    payload: &[u8],
) -> Vec<u8> {
    let seg_len = tcp.header_len() + payload.len();
    let ip = Ipv4Repr {
        src: local.ip,
        dst: remote.ip,
        protocol: IPPROTO_TCP,
        payload_len: seg_len as u16,
        ttl: 64,
    };
    let mut buf = vec![0u8; ip.total_len()];
    ip.emit(&mut buf);
    tcp.emit(local.ip, remote.ip, payload, &mut buf[Ipv4Repr::HEADER_LEN..]);
    buf
}

/// RFC 793 reset generation for a segment that hit a non-existent connection.
fn connectionless_reset(local: Endpoint, remote: Endpoint, tcp: &TcpPacket<'_>) -> Vec<u8> {
    let (seq, ack, flags) = if tcp.flags().ack() {
        // Reflect the ACK as the RST sequence; no ACK flag.
        (tcp.ack(), SeqNumber::new(0), TcpFlags(TcpFlags::RST))
    } else {
        // No ACK to reflect: RST carries seq 0 and ACKs the incoming sequence span.
        let seg_len = tcp.payload().len() as u32
            + u32::from(tcp.flags().syn())
            + u32::from(tcp.flags().fin());
        (
            SeqNumber::new(0),
            tcp.seq() + seg_len,
            TcpFlags(TcpFlags::RST | TcpFlags::ACK),
        )
    };
    let repr = TcpRepr {
        src_port: local.port,
        dst_port: remote.port,
        seq,
        ack,
        flags,
        window: 0,
        mss: None,
        sack_permitted: false,
        sack: SackBlocks::default(),
    };
    build_segment(local, remote, &repr, b"")
}

/// A single-endpoint TCP stack: it listens on `local` and tracks connections by remote peer.
pub struct Stack {
    local: Endpoint,
    isn: IsnGenerator,
    conns: HashMap<Endpoint, Tcb>,
    /// Datagrams not associated with a connection (e.g. resets to unknown peers).
    pending: VecDeque<Vec<u8>>,
    /// MSS advertised on every SYN-ACK (derived from the device MTU).
    mss_advertise: u16,
}

impl Stack {
    /// `isn_secret` must come from the OS CSPRNG (the backend reads `/dev/urandom`).
    /// `mss_advertise` is the MSS to advertise, derived from the device MTU via
    /// [`crate::tcb::mss_for_mtu`].
    pub fn new(local: Endpoint, isn_secret: [u8; 16], mss_advertise: u16) -> Self {
        Stack {
            local,
            isn: IsnGenerator::new(isn_secret),
            conns: HashMap::new(),
            pending: VecDeque::new(),
            mss_advertise,
        }
    }

    pub fn local(&self) -> Endpoint {
        self.local
    }

    pub fn connection_count(&self) -> usize {
        self.conns.len()
    }

    /// Borrow a connection's TCB by remote endpoint (for the application to read/write).
    pub fn connection_mut(&mut self, remote: &Endpoint) -> Option<&mut Tcb> {
        self.conns.get_mut(remote)
    }

    /// Iterate all live connections (for an application to service each).
    pub fn connections_mut(&mut self) -> impl Iterator<Item = (&Endpoint, &mut Tcb)> {
        self.conns.iter_mut()
    }

    /// Feed one received IPv4 datagram.
    pub fn on_recv(&mut self, now: Instant, ip: &Ipv4Packet<'_>) {
        if ip.protocol() != IPPROTO_TCP || ip.dst() != self.local.ip {
            return;
        }
        let tcp = match TcpPacket::new_checked(ip.payload()) {
            Ok(t) => t,
            Err(_) => return,
        };
        if tcp.dst_port() != self.local.port {
            return;
        }
        // Accept a zero checksum (TX-offload on locally-originated traffic); else verify.
        let csum = tcp.checksum();
        if csum != 0 && !checksum::tcp_checksum_valid(ip.src(), ip.dst(), tcp.as_bytes()) {
            return;
        }

        let remote = Endpoint {
            ip: ip.src(),
            port: tcp.src_port(),
        };

        if let Some(tcb) = self.conns.get_mut(&remote) {
            tcb.on_segment(now, &tcp);
        } else if tcp.flags().syn() && !tcp.flags().ack() && !tcp.flags().rst() {
            // Passive open.
            let iss = self.isn.generate(
                self.local.ip,
                self.local.port,
                remote.ip,
                remote.port,
                now.micros(),
            );
            let tcb = Tcb::new_syn_received(self.local, remote, &tcp, iss, now, self.mss_advertise);
            self.conns.insert(remote, tcb);
        } else if !tcp.flags().rst() {
            // Segment to a non-existent connection (and not itself a RST): reset it.
            self.pending
                .push_back(connectionless_reset(self.local, remote, &tcp));
        }
    }

    /// Fire every connection's due timers.
    pub fn on_timer(&mut self, now: Instant) {
        for tcb in self.conns.values_mut() {
            tcb.on_timer(now);
        }
    }

    /// Drain every datagram the stack currently wants to send into `out`, and reap any
    /// connections that have reached `Closed`.
    pub fn poll_transmit(&mut self, now: Instant, out: &mut Vec<Vec<u8>>) {
        while let Some(seg) = self.pending.pop_front() {
            out.push(seg);
        }
        let keys: Vec<Endpoint> = self.conns.keys().copied().collect();
        for key in keys {
            if let Some(tcb) = self.conns.get_mut(&key) {
                while let Some(seg) = tcb.poll_transmit(now) {
                    out.push(seg);
                }
                if tcb.state == State::Closed {
                    self.conns.remove(&key);
                }
            }
        }
    }

    /// The earliest armed deadline across all connections.
    pub fn poll_at(&self) -> Option<Instant> {
        self.conns.values().filter_map(|t| t.poll_at()).min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const US: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const CLIENT_PORT: u16 = 40000;

    fn us() -> Endpoint {
        Endpoint::new(US, 8080)
    }

    fn inbound(seq: SeqNumber, ack: SeqNumber, flag_bits: u8, mss: Option<u16>, payload: &[u8]) -> Vec<u8> {
        let repr = TcpRepr {
            src_port: CLIENT_PORT,
            dst_port: 8080,
            seq,
            ack,
            flags: TcpFlags(flag_bits),
            window: 64000,
            mss,
            sack_permitted: false,
            sack: SackBlocks::default(),
        };
        build_segment(Endpoint::new(HOST, CLIENT_PORT), us(), &repr, payload)
    }

    /// Feed a frame and return everything the stack emits in response.
    fn feed(stack: &mut Stack, now: Instant, frame: &[u8]) -> Vec<Vec<u8>> {
        let ip = Ipv4Packet::new_checked(frame).unwrap();
        stack.on_recv(now, &ip);
        let mut out = Vec::new();
        stack.poll_transmit(now, &mut out);
        out
    }

    fn with_tcp<R>(frame: &[u8], f: impl FnOnce(TcpPacket<'_>) -> R) -> R {
        let ip = Ipv4Packet::new_checked(frame).unwrap();
        assert!(ip.checksum_valid());
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        assert!(checksum::tcp_checksum_valid(ip.src(), ip.dst(), tcp.as_bytes()));
        f(tcp)
    }

    #[test]
    fn three_way_handshake_then_data() {
        let mut stack = Stack::new(us(), [0x42; 16], 1460);
        let now = Instant::from_millis(0);

        let out = feed(&mut stack, now, &inbound(SeqNumber::new(1000), SeqNumber::new(0), TcpFlags::SYN, Some(1460), b""));
        assert_eq!(out.len(), 1);
        let our_iss = with_tcp(&out[0], |t| {
            assert!(t.flags().syn() && t.flags().ack());
            assert_eq!(t.ack(), SeqNumber::new(1001));
            assert_eq!(t.mss_option(), Some(1460));
            t.seq()
        });

        let out = feed(&mut stack, now, &inbound(SeqNumber::new(1001), our_iss + 1, TcpFlags::ACK, None, b""));
        assert!(out.is_empty());
        assert_eq!(stack.connection_count(), 1);

        let out = feed(
            &mut stack,
            now,
            &inbound(SeqNumber::new(1001), our_iss + 1, TcpFlags::ACK | TcpFlags::PSH, None, b"hello"),
        );
        assert_eq!(out.len(), 1);
        with_tcp(&out[0], |t| {
            assert!(t.flags().ack());
            assert_eq!(t.ack(), SeqNumber::new(1006));
        });
    }

    #[test]
    fn rst_at_rcv_nxt_closes_connection() {
        let mut stack = Stack::new(us(), [1; 16], 1460);
        let now = Instant::from_millis(0);
        let out = feed(&mut stack, now, &inbound(SeqNumber::new(5000), SeqNumber::new(0), TcpFlags::SYN, Some(1460), b""));
        let our_iss = with_tcp(&out[0], |t| t.seq());
        feed(&mut stack, now, &inbound(SeqNumber::new(5001), our_iss + 1, TcpFlags::ACK, None, b""));
        assert_eq!(stack.connection_count(), 1);

        let out = feed(&mut stack, now, &inbound(SeqNumber::new(5001), SeqNumber::new(0), TcpFlags::RST, None, b""));
        assert!(out.is_empty()); // never ACK a RST
        assert_eq!(stack.connection_count(), 0);
    }

    #[test]
    fn segment_to_unknown_connection_is_reset() {
        let mut stack = Stack::new(us(), [3; 16], 1460);
        let now = Instant::from_millis(0);
        let out = feed(&mut stack, now, &inbound(SeqNumber::new(1), SeqNumber::new(99), TcpFlags::ACK, None, b""));
        assert_eq!(out.len(), 1);
        with_tcp(&out[0], |t| {
            assert!(t.flags().rst());
            assert_eq!(t.seq(), SeqNumber::new(99));
        });
    }
}
