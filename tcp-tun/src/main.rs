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

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    use std::io::Read;
    use std::net::Ipv4Addr;

    use iou::IoUringTun;
    use tcp_core::Endpoint;
    use tun::TunDevice;

    let dev_name = std::env::args().nth(1).unwrap_or_else(|| "tun0".to_string());
    // The MTU the stack assumes (drives the advertised MSS); must match the kernel interface MTU
    // set by tun-up.sh. Override for the match-MTU experiment, e.g. `FERRUM_MTU=65535`.
    let mtu = std::env::var("FERRUM_MTU")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(tun::DEFAULT_MTU);
    // I/O backend: `FERRUM_IO=uring` batches every read/write into one `io_uring_enter` per
    // event-loop turn (the syscall-bound MTU-1500 regime); anything else uses blocking
    // read/write/poll. io_uring falls back to the blocking path if the kernel is too old.
    let want_uring = std::env::var("FERRUM_IO").map(|v| v == "uring").unwrap_or(false);

    // ISN secret from the OS CSPRNG (RFC 6528) — read once, never logged.
    let mut secret = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut secret)?;
    let local = Endpoint::new(Ipv4Addr::new(10, 0, 0, 2), 8080);

    if want_uring {
        match IoUringTun::open(&dev_name, mtu) {
            Ok(dev) => {
                eprintln!(
                    "tcp-tun: {} up (MTU {mtu}, io_uring); serving HTTP on 10.0.0.2:8080. \
                     Configure with scripts/tun-up.sh, then `curl http://10.0.0.2:8080/`.",
                    dev.name(),
                );
                return run_server(dev, local, secret);
            }
            Err(e) => eprintln!("tcp-tun: io_uring unavailable ({e}); using blocking I/O."),
        }
    }

    let dev = TunDevice::open(&dev_name, mtu)?;
    eprintln!(
        "tcp-tun: {} up (MTU {mtu}); serving HTTP on 10.0.0.2:8080. Configure with \
         scripts/tun-up.sh, then `curl http://10.0.0.2:8080/`.",
        dev.name(),
    );
    run_server(dev, local, secret)
}

/// Build the runtime over `dev`, install the accept loop (one HTTP handler task per connection),
/// and run the event loop forever. Generic over the device so the io_uring and blocking backends
/// share one path.
#[cfg(target_os = "linux")]
fn run_server<D: tcp_core::Device>(
    dev: D,
    local: tcp_core::Endpoint,
    secret: [u8; 16],
) -> std::io::Result<()> {
    use tcp_core::Runtime;

    let mut rt = Runtime::new(dev, local, secret);
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

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("tcp-tun requires Linux (it uses a /dev/net/tun device). Build and run it on the VPS.");
}
