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
use super::socket::{TcpConnector, TcpListener};
use super::Device;

/// State shared between the reactor and the socket futures (single-threaded; `Rc<RefCell>`).
pub(crate) struct ReactorState {
    pub(crate) stack: Stack,
    pub(crate) read_wakers: HashMap<Endpoint, Waker>,
    pub(crate) write_wakers: HashMap<Endpoint, Waker>,
    /// Wakers for in-flight active opens, keyed by remote, woken when the connection becomes
    /// established (success) or reaches Closed / vanishes (refused or timed out).
    pub(crate) connect_wakers: HashMap<Endpoint, Waker>,
    pub(crate) accept_waker: Option<Waker>,
    pub(crate) accept_queue: VecDeque<Endpoint>,
    /// The most recent logical time handed to `turn` — used to stamp an active open's ISN (RFC
    /// 6528) when the application calls `connect` from inside a task.
    pub(crate) now: Instant,
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
                connect_wakers: HashMap::new(),
                accept_waker: None,
                accept_queue: VecDeque::new(),
                now: Instant::from_micros(0),
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

    /// A connector for initiating active opens (`connector.connect(remote).await`).
    pub fn connector(&self) -> TcpConnector {
        TcpConnector::new(self.state.clone())
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
        {
            let mut s = self.state.borrow_mut();
            s.now = now; // available to `connect` (ISN stamping) when tasks run below
            s.stack.on_timer(now);
        }

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

        // Any *passively-opened* connection past the handshake -> accept queue (each announced
        // exactly once). We announce on any synchronized state, not just Established, because a
        // request + FIN delivered in one batch can leave the connection in CloseWait before we
        // look. Connections we actively opened (`connect`) have an ephemeral local port, not the
        // listen port, so this filter keeps them out of `accept` — the connector wakes on them.
        let listen_port = s.stack.local().port;
        let synced: Vec<Endpoint> = s
            .stack
            .connections_mut()
            .filter(|(_, t)| t.is_synchronized() && t.local().port == listen_port)
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

        // Wake active opens that established (synchronized), were refused / timed out (Closed),
        // or vanished. The Connect future then resolves to a stream or the right error.
        let connect_keys: Vec<Endpoint> = s.connect_wakers.keys().copied().collect();
        for ep in connect_keys {
            let ready = match s.stack.connection_mut(&ep) {
                Some(t) => t.is_synchronized() || t.state == State::Closed,
                None => true,
            };
            if ready {
                if let Some(w) = s.connect_wakers.remove(&ep) {
                    w.wake();
                }
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

    // ── two-stack userspace loopback (active open end to end) ─────────────────────────────────

    fn payload_len(frame: &[u8]) -> usize {
        parse(frame).payload.len()
    }

    /// Cross-wire two runtimes: each runtime's egress becomes the other's ingress next turn.
    /// Returns the total TCP payload bytes the *client* emitted this round (its in-flight burst).
    fn pump_once(client: &mut Runtime<MockDevice>, server: &mut Runtime<MockDevice>, t: Instant) -> usize {
        client.turn(t).unwrap();
        server.turn(t).unwrap();
        let c_out = client.device_mut().take_outbound();
        let s_out = server.device_mut().take_outbound();
        let burst: usize = c_out.iter().map(|f| payload_len(f)).sum();
        for f in s_out {
            client.device_mut().inject(f);
        }
        for f in c_out {
            server.device_mut().inject(f);
        }
        burst
    }

    #[test]
    fn two_stacks_connect_and_round_trip_in_userspace() {
        // Server listens on US:8080; the client lives on HOST and dials it. Both run entirely in
        // userspace over mock devices — the SYN, SYN-ACK, ACK, data and FINs all cross the wire.
        let mut server = Runtime::new(MockDevice::new(), Endpoint::new(US, 8080), [1u8; 16]);
        let mut client = Runtime::new(MockDevice::new(), Endpoint::new(HOST, 9), [2u8; 16]);

        let listener = server.listener();
        let got_server = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let gs = got_server.clone();
        server.spawn(async move {
            let stream = listener.accept().await;
            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).await.unwrap();
            gs.borrow_mut().extend_from_slice(&buf[..n]);
            stream.write_all(b"pong").await.unwrap();
            stream.close();
        });

        let connector = client.connector();
        let got_client = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let connected = std::rc::Rc::new(std::cell::RefCell::new(false));
        let gc = got_client.clone();
        let cf = connected.clone();
        client.spawn(async move {
            let stream = connector.connect(Endpoint::new(US, 8080)).await.unwrap();
            *cf.borrow_mut() = true;
            stream.write_all(b"ping").await.unwrap();
            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).await.unwrap();
            gc.borrow_mut().extend_from_slice(&buf[..n]);
            stream.close();
        });

        let t = Instant::from_millis(0);
        for _ in 0..50 {
            pump_once(&mut client, &mut server, t);
            if &*got_client.borrow() == b"pong" && &*got_server.borrow() == b"ping" {
                break;
            }
        }
        assert!(*connected.borrow(), "the active open established");
        assert_eq!(&*got_server.borrow(), b"ping", "server received the request");
        assert_eq!(&*got_client.borrow(), b"pong", "client received the reply");
    }

    #[test]
    #[cfg_attr(miri, ignore)] // pumps ~2 MiB through both stacks — far too slow under Miri
    fn two_stacks_bulk_transfer_puts_over_64k_in_flight() {
        // With two fast peers (unlike the curl bench, where curl's ~64 KiB receive window is the
        // limiter), window scaling lets the client keep more than a 16-bit window in flight. We
        // assert the client emits a single >64 KiB burst with no intervening ACK — impossible
        // without the scaled window — and that the whole payload arrives intact.
        let mut server = Runtime::new(MockDevice::new(), Endpoint::new(US, 8080), [3u8; 16]);
        let mut client = Runtime::new(MockDevice::new(), Endpoint::new(HOST, 9), [4u8; 16]);

        const N: usize = 2 * 1024 * 1024;
        let payload: std::rc::Rc<Vec<u8>> = std::rc::Rc::new((0..N).map(|i| (i % 251) as u8).collect());

        let listener = server.listener();
        let received = std::rc::Rc::new(std::cell::RefCell::new(Vec::<u8>::new()));
        let rv = received.clone();
        server.spawn(async move {
            let stream = listener.accept().await;
            let mut buf = [0u8; 8192];
            loop {
                let n = stream.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                rv.borrow_mut().extend_from_slice(&buf[..n]);
            }
        });

        let connector = client.connector();
        let to_send = payload.clone();
        client.spawn(async move {
            let stream = connector.connect(Endpoint::new(US, 8080)).await.unwrap();
            stream.write_all(&to_send).await.unwrap();
            stream.close();
        });

        let t = Instant::from_millis(0);
        let mut max_burst = 0usize;
        for _ in 0..20_000 {
            max_burst = max_burst.max(pump_once(&mut client, &mut server, t));
            if received.borrow().len() == N {
                break;
            }
        }
        assert_eq!(received.borrow().len(), N, "the whole payload arrived");
        assert_eq!(&**received.borrow(), &payload[..], "data integrity across both userspace stacks");
        assert!(max_burst > 65_536, "window scaling let the client put >64 KiB in flight in one burst; got {max_burst}");
    }

    /// A segment from a peer at US:8080 to our client at HOST:`our_port`.
    fn peer_to(seq: SeqNumber, ack: SeqNumber, flags: u8, our_port: u16) -> Vec<u8> {
        let repr = TcpRepr {
            src_port: 8080,
            dst_port: our_port,
            seq,
            ack,
            flags: TcpFlags(flags),
            window: 64000,
            mss: None,
            sack_permitted: false,
            window_scale: None,
            sack: SackBlocks::default(),
        };
        build_segment(Endpoint::new(US, 8080), Endpoint::new(HOST, our_port), &repr, b"")
    }

    /// Drive the connect handshake far enough to learn our ephemeral port and ISS, returning
    /// `(client_runtime_state via outcome, iss, ephemeral_port)`. The SYN has been emitted.
    fn start_connect(secret: u8) -> (Runtime<MockDevice>, std::rc::Rc<std::cell::RefCell<Option<bool>>>, SeqNumber, u16) {
        let mut client = Runtime::new(MockDevice::new(), Endpoint::new(HOST, 9), [secret; 16]);
        let connector = client.connector();
        let outcome = std::rc::Rc::new(std::cell::RefCell::new(None::<bool>)); // Some(is_err)
        let oc = outcome.clone();
        client.spawn(async move {
            let res = connector.connect(Endpoint::new(US, 8080)).await;
            *oc.borrow_mut() = Some(res.is_err());
        });
        let t = Instant::from_millis(0);
        client.turn(t).unwrap(); // installs SYN-SENT, emits the SYN
        let syn = client.device_mut().take_outbound();
        assert_eq!(syn.len(), 1);
        let ip = Ipv4Packet::new_checked(&syn[0]).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        assert!(tcp.flags().syn() && !tcp.flags().ack());
        (client, outcome, tcp.seq(), tcp.src_port())
    }

    #[test]
    fn connect_refused_by_rst_resolves_with_an_error() {
        let (mut client, outcome, iss, lport) = start_connect(21);
        let t = Instant::from_millis(0);
        // The peer refuses with RST+ACK acknowledging our SYN.
        client.device_mut().inject(peer_to(SeqNumber::new(1), iss + 1, TcpFlags::RST | TcpFlags::ACK, lport));
        client.turn(t).unwrap();
        assert_eq!(*outcome.borrow(), Some(true), "a refused connect resolves to an error, not a hang");
    }

    #[test]
    fn connect_closed_during_simultaneous_open_does_not_hang() {
        // Regression (review finding): the conn reaches Closed inside poll_transmit's RST path only
        // if the close is deferred there; with the close applied in on_segment, dispatch_wakeups
        // sees Closed the same turn and the parked connect future resolves rather than hanging.
        let (mut client, outcome, iss, lport) = start_connect(22);
        let t = Instant::from_millis(0);

        // A bare SYN crosses ours (simultaneous open): the client answers with a SYN-ACK.
        client.device_mut().inject(peer_to(SeqNumber::new(9000), SeqNumber::new(0), TcpFlags::SYN, lport));
        client.turn(t).unwrap();
        let _ = client.device_mut().take_outbound(); // the SYN-ACK
        assert_eq!(*outcome.borrow(), None, "still connecting after the simultaneous open");

        // Now an in-window segment whose ACK does not acknowledge our SYN: the half-open conn is
        // rejected and closed. The connect must resolve (with an error) this very turn.
        client.device_mut().inject(peer_to(SeqNumber::new(9001), iss + 5, TcpFlags::ACK, lport));
        client.turn(t).unwrap();
        assert_eq!(*outcome.borrow(), Some(true), "the failed connect resolves, it does not hang");
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
