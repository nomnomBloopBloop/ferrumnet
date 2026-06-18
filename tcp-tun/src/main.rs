//! `tcp-tun` — the Linux backend that drives the `tcp-core` async runtime over a real TUN
//! device, serving HTTP so that `curl http://10.0.0.2:8080` works end to end.
//!
//! All device code is `#[cfg(target_os = "linux")]`; other platforms build to a notice so the
//! workspace stays buildable.

#[cfg(target_os = "linux")]
mod http;
#[cfg(target_os = "linux")]
mod iou;
#[cfg(target_os = "linux")]
mod sys;
#[cfg(target_os = "linux")]
mod tun;

/// What this instance does: serve HTTP, or dial a peer and download `/bench` for a throughput
/// measurement (the two-instance window-scaling experiment — two fast userspace stacks talk over
/// two TUNs the kernel forwards between, so neither end is limited by a `curl`-sized window).
#[cfg(target_os = "linux")]
enum Mode {
    Server,
    Client { server: tcp_core::Endpoint, path: String },
}

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    use std::io::Read;
    use std::net::Ipv4Addr;

    use iou::IoUringTun;
    use tcp_core::{CcKind, Endpoint};
    use tun::TunDevice;

    let args: Vec<String> = std::env::args().collect();
    let dev_name = args.get(1).cloned().unwrap_or_else(|| "tun0".to_string());
    // The MTU the stack assumes (drives the advertised MSS); must match the kernel interface MTU.
    let mtu = std::env::var("FERRUM_MTU")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(tun::DEFAULT_MTU);
    // I/O backend: `FERRUM_IO=uring` batches I/O into one `io_uring_enter` per turn (falls back to
    // blocking read/write/poll if the kernel is too old).
    let want_uring = std::env::var("FERRUM_IO").map(|v| v == "uring").unwrap_or(false);
    // Our local IP on this TUN (server defaults to 10.0.0.2; a client peer sets e.g. 10.1.0.2).
    let local_ip: Ipv4Addr = std::env::var("FERRUM_IP")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(Ipv4Addr::new(10, 0, 0, 2));
    // Congestion controller: `FERRUM_CC=cubic` runs CUBIC (RFC 8312), `=bbr` runs BBR, `=dctcp`
    // runs DCTCP (RFC 8257, L4S/ECN), `=prague` runs TCP Prague (L4S scalable + RTT-independent);
    // anything else (default) is Reno. The swappable knob for the controller comparison. (DCTCP and
    // Prague only react to congestion if the path marks CE — over a plain TUN with no ECN AQM they
    // behave like Reno; the marking demos are the in-process bottleneck sim.)
    let cc_kind = match std::env::var("FERRUM_CC").as_deref() {
        Ok("cubic") => CcKind::Cubic,
        Ok("bbr") => CcKind::Bbr,
        Ok("dctcp") => CcKind::Dctcp,
        Ok("learned") => CcKind::Learned,
        Ok("prague") => CcKind::Prague,
        _ => CcKind::Reno,
    };
    let cc_name = match cc_kind {
        CcKind::Reno => "reno",
        CcKind::Cubic => "cubic",
        CcKind::Bbr => "bbr",
        CcKind::Dctcp => "dctcp",
        CcKind::Learned => "learned",
        CcKind::Prague => "prague",
    };

    // `tcp-tun <dev> connect <server-ip> [path]` is the download client; otherwise serve.
    let (mode, local) = if args.get(2).map(|s| s == "connect").unwrap_or(false) {
        let server_ip: Ipv4Addr = args
            .get(3)
            .and_then(|s| s.parse().ok())
            .expect("usage: tcp-tun <dev> connect <server-ip> [path]");
        let path = args.get(4).cloned().unwrap_or_else(|| "/bench/256".to_string());
        let server = Endpoint::new(server_ip, 8080);
        // The client's "listen port" is unused (port 9); connect picks its own ephemeral port.
        (Mode::Client { server, path }, Endpoint::new(local_ip, 9))
    } else {
        (Mode::Server, Endpoint::new(local_ip, 8080))
    };

    // ISN secret from the OS CSPRNG (RFC 6528) — read once, never logged.
    let mut secret = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut secret)?;

    let backend = if want_uring { "io_uring" } else { "blocking" };
    if want_uring {
        match IoUringTun::open(&dev_name, mtu) {
            Ok(dev) => {
                eprintln!("tcp-tun: {} up (MTU {mtu}, {backend}, IP {local_ip}, cc {cc_name})", dev.name());
                return run(dev, mode, local, secret, cc_kind);
            }
            Err(e) => eprintln!("tcp-tun: io_uring unavailable ({e}); using blocking I/O."),
        }
    }
    let dev = TunDevice::open(&dev_name, mtu)?;
    eprintln!("tcp-tun: {} up (MTU {mtu}, blocking, IP {local_ip}, cc {cc_name})", dev.name());
    run(dev, mode, local, secret, cc_kind)
}

/// Dispatch to the server or client event loop over `dev` (generic so both I/O backends share it).
#[cfg(target_os = "linux")]
fn run<D: tcp_core::Device>(
    dev: D,
    mode: Mode,
    local: tcp_core::Endpoint,
    secret: [u8; 16],
    cc_kind: tcp_core::CcKind,
) -> std::io::Result<()> {
    match mode {
        Mode::Server => run_server(dev, local, secret, cc_kind),
        Mode::Client { server, path } => run_client(dev, local, secret, server, path, cc_kind),
    }
}

/// Serve HTTP: one handler task per accepted connection; runs forever.
#[cfg(target_os = "linux")]
fn run_server<D: tcp_core::Device>(
    dev: D,
    local: tcp_core::Endpoint,
    secret: [u8; 16],
    cc_kind: tcp_core::CcKind,
) -> std::io::Result<()> {
    use tcp_core::Runtime;

    eprintln!("tcp-tun: serving HTTP on {local:?}");
    let mut rt = Runtime::new(dev, local, secret);
    rt.set_congestion_control(cc_kind);
    let listener = rt.listener();
    let spawner = rt.spawner();
    rt.spawn(async move {
        loop {
            let stream = listener.accept().await;
            spawner.spawn(http::serve(stream));
        }
    });
    rt.run()
}

/// Dial `server`, `GET path`, read the whole body, and report wall-clock download throughput, then
/// exit the process (which removes the TUN). The connect/request/teardown all run through the stack.
#[cfg(target_os = "linux")]
fn run_client<D: tcp_core::Device>(
    dev: D,
    local: tcp_core::Endpoint,
    secret: [u8; 16],
    server: tcp_core::Endpoint,
    path: String,
    cc_kind: tcp_core::CcKind,
) -> std::io::Result<()> {
    use tcp_core::Runtime;

    let mut rt = Runtime::new(dev, local, secret);
    rt.set_congestion_control(cc_kind);
    let connector = rt.connector();
    rt.spawn(async move {
        let stream = match connector.connect(server).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("client: connect to {server:?} failed: {e}");
                std::process::exit(1);
            }
        };
        let req = format!("GET {path} HTTP/1.0\r\nHost: bench\r\n\r\n");
        if stream.write_all(req.as_bytes()).await.is_err() {
            eprintln!("client: request write failed");
            std::process::exit(1);
        }
        let start = std::time::Instant::now();
        let mut total = 0usize;
        let mut buf = vec![0u8; 256 * 1024];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(e) => {
                    eprintln!("client: read error after {total} bytes: {e}");
                    break;
                }
            }
        }
        let secs = start.elapsed().as_secs_f64();
        let mbps = if secs > 0.0 { (total as f64 / 1e6) / secs } else { 0.0 };
        eprintln!("client: GET {path} -> {total} bytes in {secs:.3}s = {mbps:.1} MB/s");
        std::process::exit(0);
    });
    rt.run()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("tcp-tun requires Linux (it uses a /dev/net/tun device). Build and run it on the VPS.");
}
