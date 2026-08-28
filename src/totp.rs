use crate::{base32, crypto};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn code(secret: &[u8], timestamp: u64) -> u32 {
    let counter = timestamp / 30;
    let digest = crypto::hmac_sha1(secret, &counter.to_be_bytes());
    let offset = (digest[19] & 15) as usize;
    (u32::from_be_bytes(digest[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff) % 1_000_000
}
pub fn verify(secret: &[u8], supplied: &str) -> bool {
    let Ok(value) = supplied.parse::<u32>() else {
        return false;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    (0..=2).any(|n| code(secret, now.saturating_sub(n * 30)) == value)
        || code(secret, now + 30) == value
}
pub fn new_secret() -> [u8; 20] {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let mut seed = now.as_nanos() as u64 ^ std::process::id() as u64;
    let mut out = [0u8; 20];
    for byte in &mut out {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        *byte = (seed >> 24) as u8;
    }
    out
}
pub fn secret_text(secret: &[u8]) -> String {
    base32::encode(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rfc6238_sha1() {
        let secret = b"12345678901234567890";
        assert_eq!(code(secret, 59), 287082);
        assert_eq!(code(secret, 1111111109), 81804);
    }
}
