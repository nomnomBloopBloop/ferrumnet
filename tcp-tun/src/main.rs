//! `tcp-tun` — the Linux backend that drives the `tcp-core` sans-IO engine over a real TUN
//! device.
//!
//! Milestone M0: open the device and answer ICMP echo (`ping`). Later milestones add the TCP
//! reactor and the HTTP demo. All device code is `#[cfg(target_os = "linux")]`; on other
//! platforms the binary builds to a friendly notice so the workspace stays buildable.

#[cfg(target_os = "linux")]
mod sys;
#[cfg(target_os = "linux")]
mod tun;

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    use tcp_core::wire::{echo_reply, Ipv4Packet};
    use tun::TunDevice;

    let dev_name = std::env::args().nth(1).unwrap_or_else(|| "tun0".to_string());
    let mut dev = TunDevice::open(&dev_name)?;
    eprintln!(
        "tcp-tun: opened {} (mtu {}). Configure it with scripts/tun-up.sh, then `ping 10.0.0.2`.",
        dev.name(),
        dev.mtu()
    );

    // Read buffer larger than the MTU so a truncated/oversize frame is detected (and dropped
    // by Ipv4Packet::new_checked) rather than silently parsed.
    let mut rx = vec![0u8; dev.mtu() + 64];
    let mut tx = vec![0u8; dev.mtu() + 64];

    loop {
        // M0 has no timers yet, so block until the device is readable.
        if !dev.poll_readable(-1)? {
            continue;
        }
        // Drain every queued datagram before blocking again.
        while let Some(n) = dev.recv(&mut rx)? {
            let ip = match Ipv4Packet::new_checked(&rx[..n]) {
                Ok(ip) => ip,
                Err(_) => continue, // not IPv4 / truncated / a fragment — ignore
            };
            if let Some(len) = echo_reply(&ip, &mut tx) {
                if let Err(e) = dev.send(&tx[..len]) {
                    eprintln!("tcp-tun: dropped reply ({e})");
                }
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("tcp-tun requires Linux (it uses a /dev/net/tun device). Build and run it on the VPS.");
}
