//! The reactor: one event loop that drives a [`Device`], the sans-IO [`Stack`], the task
//! executor, and the per-connection waker registries.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::rc::Rc;
use std::task::Waker;

use crate::iface::{Endpoint, Stack};
use crate::state::State;
use crate::time::Instant;
use crate::wire::{echo_reply, Ipv4Packet, IPPROTO_ICMP, IPPROTO_TCP};

use super::executor::{Executor, Spawner};
use super::socket::TcpListener;
use super::Device;

/// State shared between the reactor and the socket futures (single-threaded; `Rc<RefCell>`).
pub(crate) struct ReactorState {
    pub(crate) stack: Stack,
    pub(crate) read_wakers: HashMap<Endpoint, Waker>,
    pub(crate) write_wakers: HashMap<Endpoint, Waker>,
    pub(crate) accept_waker: Option<Waker>,
    pub(crate) accept_queue: VecDeque<Endpoint>,
    /// Connections already handed to `accept` (so we enqueue each exactly once).
    announced: HashSet<Endpoint>,
}

pub struct Runtime<D: Device> {
    device: D,
    state: Rc<RefCell<ReactorState>>,
    exec: Executor,
    rx: Vec<u8>,
    tx: Vec<u8>,
    egress: Vec<Vec<u8>>,
}

impl<D: Device> Runtime<D> {
    pub fn new(device: D, local: Endpoint, isn_secret: [u8; 16]) -> Self {
        let mtu = device.mtu();
        let mss = crate::tcb::mss_for_mtu(mtu);
        Runtime {
            device,
            state: Rc::new(RefCell::new(ReactorState {
                stack: Stack::new(local, isn_secret, mss),
                read_wakers: HashMap::new(),
                write_wakers: HashMap::new(),
                accept_waker: None,
                accept_queue: VecDeque::new(),
                announced: HashSet::new(),
            })),
            exec: Executor::new(),
            rx: vec![0u8; mtu + 64],
            tx: vec![0u8; mtu + 64],
            egress: Vec::new(),
        }
    }

    /// A listener bound to the runtime's local endpoint.
    pub fn listener(&self) -> TcpListener {
        TcpListener::new(self.state.clone())
    }

    /// A handle for spawning tasks.
    pub fn spawner(&self) -> Spawner {
        self.exec.spawner()
    }

    pub fn spawn(&self, fut: impl Future<Output = ()> + 'static) {
        self.exec.spawner().spawn(fut);
    }

    /// The earliest timer deadline across all connections.
    pub fn poll_at(&self) -> Option<Instant> {
        self.state.borrow().stack.poll_at()
    }

    /// Mutable access to the underlying device (used by tests to inject/collect frames).
    pub fn device_mut(&mut self) -> &mut D {
        &mut self.device
    }

    /// Number of live connections.
    pub fn connection_count(&self) -> usize {
        self.state.borrow().stack.connection_count()
    }

    /// One reactor iteration at logical time `now`: fire timers, ingest packets, wake ready
    /// futures, run tasks, then flush everything the stack wants to send.
    pub fn turn(&mut self, now: Instant) -> std::io::Result<()> {
        self.state.borrow_mut().stack.on_timer(now);

        while let Some(n) = self.device.recv(&mut self.rx)? {
            let ip = match Ipv4Packet::new_checked(&self.rx[..n]) {
                Ok(ip) => ip,
                Err(_) => continue,
            };
            match ip.protocol() {
                IPPROTO_ICMP => {
                    if let Some(len) = echo_reply(&ip, &mut self.tx) {
                        let _ = self.device.send(&self.tx[..len]);
                    }
                }
                IPPROTO_TCP => self.state.borrow_mut().stack.on_recv(now, &ip),
                _ => {}
            }
        }

        self.dispatch_wakeups();
        self.exec.run_ready();

        self.egress.clear();
        self.state.borrow_mut().stack.poll_transmit(now, &mut self.egress);
        for pkt in &self.egress {
            if let Err(e) = self.device.send(pkt) {
                eprintln!("tcp-tun: dropped segment ({e})");
            }
        }
        Ok(())
    }

    /// Run the blocking event loop forever, using the real wall clock.
    pub fn run(&mut self) -> std::io::Result<()> {
        let start = std::time::Instant::now();
        let now = || Instant::from_micros(start.elapsed().as_micros() as u64);
        loop {
            let timeout_ms: i32 = match self.poll_at() {
                None => -1,
                Some(deadline) => {
                    let micros = deadline.saturating_micros_since(now());
                    micros.div_ceil(1000).min(i32::MAX as u64) as i32
                }
            };
            self.device.poll_readable(timeout_ms)?;
            self.turn(now())?;
        }
    }

    /// Promote newly-established connections to the accept queue and wake any futures whose
    /// socket became ready (data available, send space free, or a new connection).
    fn dispatch_wakeups(&self) {
        let mut s = self.state.borrow_mut();

        // Any connection past the handshake -> accept queue (each announced exactly once).
        // We announce on *any* synchronized state, not just Established, because a request +
        // FIN delivered in one batch can leave the connection in CloseWait before we look.
        let synced: Vec<Endpoint> = s
            .stack
            .connections_mut()
            .filter(|(_, t)| t.is_synchronized())
            .map(|(e, _)| *e)
            .collect();
        for ep in synced {
            if s.announced.insert(ep) {
                s.accept_queue.push_back(ep);
            }
        }
        if !s.accept_queue.is_empty() {
            if let Some(w) = s.accept_waker.take() {
                w.wake();
            }
        }

        // Wake reads whose connection has data, reached EOF, was reset, or vanished.
        let read_keys: Vec<Endpoint> = s.read_wakers.keys().copied().collect();
        for ep in read_keys {
            let ready = match s.stack.connection_mut(&ep) {
                Some(t) => t.rx_available() > 0 || t.recv_eof() || t.state == State::Closed,
                None => true,
            };
            if ready {
                if let Some(w) = s.read_wakers.remove(&ep) {
                    w.wake();
                }
            }
        }

        // Wake writes whose connection can accept more data, or can no longer send (so the
        // future observes the error) — or vanished.
        let write_keys: Vec<Endpoint> = s.write_wakers.keys().copied().collect();
        for ep in write_keys {
            let ready = match s.stack.connection_mut(&ep) {
                Some(t) => {
                    !matches!(t.state, State::Established | State::CloseWait) || t.tx_free() > 0
                }
                None => true,
            };
            if ready {
                if let Some(w) = s.write_wakers.remove(&ep) {
                    w.wake();
                }
            }
        }

        // Drop bookkeeping for connections the stack has reaped, and prune the accept queue so
        // it never hands out a stream for a connection that no longer exists.
        let live: HashSet<Endpoint> = s.stack.connections_mut().map(|(e, _)| *e).collect();
        s.announced.retain(|ep| live.contains(ep));
        s.accept_queue.retain(|ep| live.contains(ep));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iface::build_segment;
    use crate::seq::SeqNumber;
    use crate::wire::{SackBlocks, TcpFlags, TcpPacket, TcpRepr};
    use crate::runtime::MockDevice;
    use std::net::Ipv4Addr;

    const HOST: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
    const US: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
    const CPORT: u16 = 44444;

    fn client_seg(seq: SeqNumber, ack: SeqNumber, flags: u8, payload: &[u8]) -> Vec<u8> {
        let repr = TcpRepr {
            src_port: CPORT,
            dst_port: 8080,
            seq,
            ack,
            flags: TcpFlags(flags),
            window: 64000,
            mss: if flags & TcpFlags::SYN != 0 { Some(1460) } else { None },
            sack_permitted: false,
            window_scale: None,
            sack: SackBlocks::default(),
        };
        build_segment(
            Endpoint::new(HOST, CPORT),
            Endpoint::new(US, 8080),
            &repr,
            payload,
        )
    }

    struct Parsed {
        flags: TcpFlags,
        seq: SeqNumber,
        payload: Vec<u8>,
    }

    fn parse(frame: &[u8]) -> Parsed {
        let ip = Ipv4Packet::new_checked(frame).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        Parsed {
            flags: tcp.flags(),
            seq: tcp.seq(),
            payload: tcp.payload().to_vec(),
        }
    }

    #[test]
    fn serves_a_request_end_to_end_over_mock_device() {
        let mut rt = Runtime::new(MockDevice::new(), Endpoint::new(US, 8080), [9u8; 16]);

        // The application: accept, read until CRLFCRLF, write a fixed response, close.
        let listener = rt.listener();
        rt.spawn(async move {
            let stream = listener.accept().await;
            let mut req = Vec::new();
            let mut buf = [0u8; 256];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..n]);
                if req.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let body = b"hi";
            let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
            stream.write_all(head.as_bytes()).await.unwrap();
            stream.write_all(body).await.unwrap();
            stream.close();
        });

        let t = Instant::from_millis(0);

        // 1) client SYN -> SYN-ACK
        rt.device_mut().inject(client_seg(SeqNumber::new(100), SeqNumber::new(0), TcpFlags::SYN, b""));
        rt.turn(t).unwrap();
        let out = rt.device_mut().take_outbound();
        let synack = parse(&out[0]);
        assert!(synack.flags.syn() && synack.flags.ack());
        let iss = synack.seq;

        // 2) client ACK -> handshake complete, accept resolves
        rt.device_mut().inject(client_seg(SeqNumber::new(101), iss + 1, TcpFlags::ACK, b""));
        rt.turn(t).unwrap();
        rt.device_mut().take_outbound();

        // 3) client sends the request -> app reads it and writes the response
        let get = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        rt.device_mut().inject(client_seg(SeqNumber::new(101), iss + 1, TcpFlags::ACK | TcpFlags::PSH, get));
        rt.turn(t).unwrap();
        let out = rt.device_mut().take_outbound();

        let mut bytes = Vec::new();
        let mut saw_fin = false;
        for f in &out {
            let p = parse(f);
            bytes.extend_from_slice(&p.payload);
            saw_fin |= p.flags.fin();
        }
        let response = String::from_utf8_lossy(&bytes);
        assert!(response.contains("HTTP/1.1 200 OK"), "got: {response:?}");
        assert!(response.contains("Content-Length: 2"));
        assert!(response.ends_with("hi"));
        assert!(saw_fin, "server should FIN after close()");
    }

    #[test]
    fn handles_two_sequential_connections() {
        let mut rt = Runtime::new(MockDevice::new(), Endpoint::new(US, 8080), [5u8; 16]);
        let listener = rt.listener();
        let spawner = rt.spawner();
        spawner.clone().spawn(async move {
            loop {
                let stream = listener.accept().await;
                let sp = spawner.clone();
                sp.spawn(async move {
                    let mut buf = [0u8; 64];
                    let _ = stream.read(&mut buf).await;
                    let _ = stream.write_all(b"ok").await;
                    stream.close();
                });
            }
        });

        let t = Instant::from_millis(0);
        for (i, cport_seq) in [200u32, 300u32].into_iter().enumerate() {
            // Each connection uses a distinct client port via a fresh source seq space.
            let base = SeqNumber::new(cport_seq);
            rt.device_mut().inject(conn_seg(i, base, SeqNumber::new(0), TcpFlags::SYN, b""));
            rt.turn(t).unwrap();
            let out = rt.device_mut().take_outbound();
            let iss = parse(&out[0]).seq;
            rt.device_mut().inject(conn_seg(i, base + 1, iss + 1, TcpFlags::ACK, b""));
            rt.turn(t).unwrap();
            rt.device_mut().take_outbound();
            rt.device_mut().inject(conn_seg(i, base + 1, iss + 1, TcpFlags::ACK | TcpFlags::PSH, b"x"));
            rt.turn(t).unwrap();
            let out = rt.device_mut().take_outbound();
            let got: Vec<u8> = out.iter().flat_map(|f| parse(f).payload).collect();
            assert_eq!(&got, b"ok", "connection {i} should be served");
        }
    }

    #[test]
    fn reset_wakes_a_blocked_reader_with_an_error() {
        let mut rt = Runtime::new(MockDevice::new(), Endpoint::new(US, 8080), [7u8; 16]);
        let listener = rt.listener();
        let errored = std::rc::Rc::new(std::cell::RefCell::new(None::<bool>));
        let e = errored.clone();
        rt.spawn(async move {
            let stream = listener.accept().await;
            let mut buf = [0u8; 16];
            let res = stream.read(&mut buf).await; // parks: no data yet
            *e.borrow_mut() = Some(res.is_err());
        });

        let t = Instant::from_millis(0);
        rt.device_mut().inject(client_seg(SeqNumber::new(100), SeqNumber::new(0), TcpFlags::SYN, b""));
        rt.turn(t).unwrap();
        let iss = parse(&rt.device_mut().take_outbound()[0]).seq;
        rt.device_mut().inject(client_seg(SeqNumber::new(101), iss + 1, TcpFlags::ACK, b""));
        rt.turn(t).unwrap();
        rt.device_mut().take_outbound();
        assert_eq!(*errored.borrow(), None, "reader should still be parked");

        // RST the connection: the parked read must resolve (with an error), not hang.
        rt.device_mut().inject(client_seg(SeqNumber::new(101), iss + 1, TcpFlags::RST, b""));
        rt.turn(t).unwrap();
        assert_eq!(*errored.borrow(), Some(true));
    }

    #[test]
    fn accepts_a_connection_that_reaches_closewait_in_one_batch() {
        let mut rt = Runtime::new(MockDevice::new(), Endpoint::new(US, 8080), [8u8; 16]);
        let listener = rt.listener();
        let served = std::rc::Rc::new(std::cell::RefCell::new(false));
        let sv = served.clone();
        rt.spawn(async move {
            let stream = listener.accept().await;
            let mut got = Vec::new();
            let mut buf = [0u8; 64];
            loop {
                let n = stream.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                got.extend_from_slice(&buf[..n]);
            }
            if got == b"hello" {
                *sv.borrow_mut() = true;
            }
            let _ = stream.write_all(b"bye").await;
            stream.close();
        });

        let t = Instant::from_millis(0);
        rt.device_mut().inject(client_seg(SeqNumber::new(200), SeqNumber::new(0), TcpFlags::SYN, b""));
        rt.turn(t).unwrap();
        let iss = parse(&rt.device_mut().take_outbound()[0]).seq;
        // The handshake ACK and a data+FIN segment arrive in the SAME ingest batch, so the
        // connection goes Established -> CloseWait before dispatch_wakeups runs.
        rt.device_mut().inject(client_seg(SeqNumber::new(201), iss + 1, TcpFlags::ACK, b""));
        rt.device_mut().inject(client_seg(
            SeqNumber::new(201),
            iss + 1,
            TcpFlags::ACK | TcpFlags::PSH | TcpFlags::FIN,
            b"hello",
        ));
        rt.turn(t).unwrap();

        assert!(*served.borrow(), "a connection that closed in one batch must still be accepted");
        let body: Vec<u8> = rt
            .device_mut()
            .take_outbound()
            .iter()
            .flat_map(|f| parse(f).payload)
            .collect();
        assert!(body.windows(3).any(|w| w == b"bye"), "server should still respond");
    }

    // Build a segment for connection `idx` (distinct client port).
    fn conn_seg(idx: usize, seq: SeqNumber, ack: SeqNumber, flags: u8, payload: &[u8]) -> Vec<u8> {
        let cport = 44444 + idx as u16;
        let repr = TcpRepr {
            src_port: cport,
            dst_port: 8080,
            seq,
            ack,
            flags: TcpFlags(flags),
            window: 64000,
            mss: if flags & TcpFlags::SYN != 0 { Some(1460) } else { None },
            sack_permitted: false,
            window_scale: None,
            sack: SackBlocks::default(),
        };
        build_segment(Endpoint::new(HOST, cport), Endpoint::new(US, 8080), &repr, payload)
    }
}
