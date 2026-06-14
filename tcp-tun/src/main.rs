//! `tcp-tun` — the Linux backend that drives the `tcp-core` async runtime over a real TUN
//! device, serving HTTP so that `curl http://10.0.0.2:8080` works end to end.
//!
//! All device code is `#[cfg(target_os = "linux")]`; other platforms build to a notice so the
//! workspace stays buildable.

#[cfg(target_os = "linux")]
mod http;
#[cfg(target_os = "linux")]
mod sys;
#[cfg(target_os = "linux")]
mod tun;

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    use std::io::Read;
    use std::net::Ipv4Addr;

    use tcp_core::{Endpoint, Runtime};
    use tun::TunDevice;

    let dev_name = std::env::args().nth(1).unwrap_or_else(|| "tun0".to_string());
    let dev = TunDevice::open(&dev_name)?;
    eprintln!(
        "tcp-tun: {} up; serving HTTP on 10.0.0.2:8080. Configure with scripts/tun-up.sh, \
         then `curl http://10.0.0.2:8080/`.",
        dev.name(),
    );

    // ISN secret from the OS CSPRNG (RFC 6528) — read once, never logged.
    let mut secret = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut secret)?;

    let local = Endpoint::new(Ipv4Addr::new(10, 0, 0, 2), 8080);
    let mut rt = Runtime::new(dev, local, secret);

    // Accept loop: one HTTP handler task per connection.
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
