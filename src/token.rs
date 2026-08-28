use crate::crypto;
use std::time::{SystemTime, UNIX_EPOCH};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| format!("{:02x}", b)).collect()
}
fn unhex(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("invalid token".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "invalid token".into()))
        .collect()
}
pub fn issue(secret: &[u8], seconds: u64, parent: u32) -> String {
    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        + seconds;
    let mut p = Vec::new();
    p.extend_from_slice(&expiry.to_be_bytes());
    p.extend_from_slice(&(parent as u64).to_be_bytes());
    let mac = crypto::hmac_sha1(secret, &p);
    p.extend_from_slice(&mac);
    hex(&p)
}
pub fn verify(secret: &[u8], value: &str, parent: u32) -> Result<(), String> {
    let p = unhex(value)?;
    if p.len() != 36 {
        return Err("invalid token length".into());
    }
    // Compare the full MAC with constant-time accumulation rather than a
    // short-circuiting partial match.
    let mac = crypto::hmac_sha1(secret, &p[..16]);
    let mut diff = 0u8;
    for i in 0..20 {
        diff |= mac[i] ^ p[16 + i];
    }
    if diff != 0 {
        return Err("invalid token signature".into());
    }
    let expiry = u64::from_be_bytes(p[..8].try_into().unwrap());
    let stored = u64::from_be_bytes(p[8..16].try_into().unwrap());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if expiry < now {
        return Err("token expired".into());
    }
    if stored != 0 && stored != parent as u64 {
        return Err("token parent process mismatch".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trip() {
        let t = issue(b"secret", 120, 42);
        assert_eq!(verify(b"secret", &t, 42), Ok(()));
        assert!(verify(b"wrong", &t, 42).is_err());
        assert!(verify(b"secret", &t, 7).is_err());
    }
}
