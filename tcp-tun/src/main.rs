//! `tcp-tun` — the Linux backend that drives the `tcp-core` sans-IO engine over a real TUN
//! device.
//!
//! M0 answered ICMP echo. M1 adds the TCP path: each received datagram is demuxed by IP
//! protocol — ICMP echo replies as before, TCP segments are fed to the `Stack`, whose emitted
//! datagrams are written back to the device. All device code is `#[cfg(target_os = "linux")]`;
//! other platforms build to a friendly notice so the workspace stays buildable.

#[cfg(target_os = "linux")]
mod sys;
#[cfg(target_os = "linux")]
mod tun;

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    use std::io::Read;
    use std::net::Ipv4Addr;
    use std::time::Instant as StdInstant;

    use tcp_core::wire::{echo_reply, Ipv4Packet, IPPROTO_ICMP, IPPROTO_TCP};
    use tcp_core::{Endpoint, Instant, Stack};
    use tun::TunDevice;

    let dev_name = std::env::args().nth(1).unwrap_or_else(|| "tun0".to_string());
    let mut dev = TunDevice::open(&dev_name)?;

    // Our stack answers as 10.0.0.2:8080 on the device subnet.
    let local = Endpoint::new(Ipv4Addr::new(10, 0, 0, 2), 8080);

    // ISN secret from the OS CSPRNG (RFC 6528) — read once, never logged.
    let mut secret = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut secret)?;
    let mut stack = Stack::new(local, secret);

    eprintln!(
        "tcp-tun: {} up (mtu {}); answering ICMP + TCP on {}:{}. Configure with scripts/tun-up.sh.",
        dev.name(),
        dev.mtu(),
        local.ip,
        local.port,
    );

    let start = StdInstant::now();
    let mut rx = vec![0u8; dev.mtu() + 64];
    let mut tx = vec![0u8; dev.mtu() + 64];
    let mut egress: Vec<Vec<u8>> = Vec::new();

    loop {
        // M1 has no timers yet, so block until the device is readable.
        if !dev.poll_readable(-1)? {
            continue;
        }
        while let Some(n) = dev.recv(&mut rx)? {
            let now = Instant::from_micros(start.elapsed().as_micros() as u64);
            let ip = match Ipv4Packet::new_checked(&rx[..n]) {
                Ok(ip) => ip,
                Err(_) => continue, // not IPv4 / truncated / a fragment
            };
            match ip.protocol() {
                IPPROTO_ICMP => {
                    if let Some(len) = echo_reply(&ip, &mut tx) {
                        if let Err(e) = dev.send(&tx[..len]) {
                            eprintln!("tcp-tun: dropped ICMP reply ({e})");
                        }
                    }
                }
                IPPROTO_TCP => {
                    egress.clear();
                    stack.on_recv(now, &ip, &mut egress);
                    for pkt in &egress {
                        if let Err(e) = dev.send(pkt) {
                            eprintln!("tcp-tun: dropped TCP segment ({e})");
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("tcp-tun requires Linux (it uses a /dev/net/tun device). Build and run it on the VPS.");
}
