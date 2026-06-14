//! Initial sequence number selection per RFC 6528.
//!
//! `ISS = M + F(localip, localport, remoteip, remoteport, secret)` where `M` is a 4-µs clock
//! and `F` is a **keyed** cryptographic hash (SipHash-2-4). The keying is the whole point: a
//! predictable ISN enables off-path connection spoofing / TIME-WAIT assassination, so the
//! 128-bit secret is drawn from the OS CSPRNG once at startup (by the backend, which passes it
//! in) and never logged.

use std::net::Ipv4Addr;

use crate::seq::SeqNumber;

/// SipHash-2-4 over `data` with the 128-bit key `(k0, k1)`. A compact, allocation-free
/// implementation of the reference algorithm (Aumasson & Bernstein, 2012).
fn siphash24(k0: u64, k1: u64, data: &[u8]) -> u64 {
    let mut v0 = k0 ^ 0x736f_6d65_7073_6575;
    let mut v1 = k1 ^ 0x646f_7261_6e64_6f6d;
    let mut v2 = k0 ^ 0x6c79_6765_6e65_7261;
    let mut v3 = k1 ^ 0x7465_6462_7974_6573;

    macro_rules! round {
        () => {{
            v0 = v0.wrapping_add(v1);
            v1 = v1.rotate_left(13);
            v1 ^= v0;
            v0 = v0.rotate_left(32);
            v2 = v2.wrapping_add(v3);
            v3 = v3.rotate_left(16);
            v3 ^= v2;
            v0 = v0.wrapping_add(v3);
            v3 = v3.rotate_left(21);
            v3 ^= v0;
            v2 = v2.wrapping_add(v1);
            v1 = v1.rotate_left(17);
            v1 ^= v2;
            v2 = v2.rotate_left(32);
        }};
    }

    let len = data.len();
    let mut chunks = data.chunks_exact(8);
    for chunk in &mut chunks {
        let m = u64::from_le_bytes(chunk.try_into().unwrap());
        v3 ^= m;
        round!();
        round!();
        v0 ^= m;
    }

    // Final block: the remaining (< 8) bytes, with the total length in the top byte.
    let mut b = (len as u64) << 56;
    for (i, &byte) in chunks.remainder().iter().enumerate() {
        b |= (byte as u64) << (8 * i);
    }
    v3 ^= b;
    round!();
    round!();
    v0 ^= b;

    v2 ^= 0xff;
    round!();
    round!();
    round!();
    round!();

    v0 ^ v1 ^ v2 ^ v3
}

/// Keyed ISN generator. Construct once at startup from a CSPRNG secret.
#[derive(Clone, Copy)]
pub struct IsnGenerator {
    k0: u64,
    k1: u64,
}

impl IsnGenerator {
    pub fn new(secret: [u8; 16]) -> Self {
        IsnGenerator {
            k0: u64::from_le_bytes(secret[0..8].try_into().unwrap()),
            k1: u64::from_le_bytes(secret[8..16].try_into().unwrap()),
        }
    }

    /// `ISS = (now_micros / 4) + F(4-tuple, secret)` (RFC 6528). The `/4` clock advances the
    /// ISN ~250k/s so reused 4-tuples get distinct ISNs over time.
    pub fn generate(
        &self,
        local_ip: Ipv4Addr,
        local_port: u16,
        remote_ip: Ipv4Addr,
        remote_port: u16,
        now_micros: u64,
    ) -> SeqNumber {
        let mut tuple = [0u8; 12];
        tuple[0..4].copy_from_slice(&local_ip.octets());
        tuple[4..8].copy_from_slice(&remote_ip.octets());
        tuple[8..10].copy_from_slice(&local_port.to_be_bytes());
        tuple[10..12].copy_from_slice(&remote_port.to_be_bytes());
        let f = siphash24(self.k0, self.k1, &tuple) as u32;
        let m = (now_micros / 4) as u32;
        SeqNumber::new(m.wrapping_add(f))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn siphash_reference_vector() {
        // Canonical SipHash-2-4 vector: key = 00..0f, input = 00..0e (15 bytes).
        let k0 = 0x0706_0504_0302_0100;
        let k1 = 0x0f0e_0d0c_0b0a_0908;
        let data: Vec<u8> = (0u8..15).collect();
        assert_eq!(siphash24(k0, k1, &data), 0xa129_ca61_49be_45e5);
    }

    #[test]
    fn isn_differs_by_tuple_and_time() {
        let gen = IsnGenerator::new([0x42; 16]);
        let a = Ipv4Addr::new(10, 0, 0, 2);
        let b = Ipv4Addr::new(10, 0, 0, 1);
        let base = gen.generate(a, 8080, b, 40000, 0);
        // Different remote port => different F => different ISN.
        assert_ne!(base, gen.generate(a, 8080, b, 40001, 0));
        // Same tuple, later time => different M => different ISN.
        assert_ne!(base, gen.generate(a, 8080, b, 40000, 1_000_000));
    }

    #[test]
    fn isn_is_deterministic_for_same_inputs() {
        let gen = IsnGenerator::new([7; 16]);
        let a = Ipv4Addr::new(192, 168, 1, 1);
        let b = Ipv4Addr::new(192, 168, 1, 2);
        assert_eq!(gen.generate(a, 80, b, 1234, 555), gen.generate(a, 80, b, 1234, 555));
    }
}
