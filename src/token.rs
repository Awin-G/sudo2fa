use crate::crypto;
use std::time::{SystemTime, UNIX_EPOCH};

// Layout: 4-byte expiry (u32 epoch seconds, good past 2106) followed by an
// 8-byte truncated HMAC-SHA1. The bound parent pid is not stored; it is folded
// into the signed message and re-supplied by the verifier, which keeps the
// token to 12 bytes -> 16 URL-safe base64 characters.
const EXPIRY_LEN: usize = 4;
const MAC_LEN: usize = 8;
const TOKEN_LEN: usize = EXPIRY_LEN + MAC_LEN;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn sign(secret: &[u8], expiry: u32, parent: u32) -> [u8; 20] {
    let mut msg = [0u8; 8];
    msg[..4].copy_from_slice(&expiry.to_be_bytes());
    msg[4..].copy_from_slice(&parent.to_be_bytes());
    crypto::hmac_sha1(secret, &msg)
}

pub fn issue(secret: &[u8], seconds: u64, parent: u32) -> String {
    let expiry = (now() + seconds) as u32;
    let mac = sign(secret, expiry, parent);
    let mut p = Vec::with_capacity(TOKEN_LEN);
    p.extend_from_slice(&expiry.to_be_bytes());
    p.extend_from_slice(&mac[..MAC_LEN]);
    crate::base64::encode(&p)
}

pub fn verify(secret: &[u8], value: &str, parent: u32) -> Result<(), String> {
    let p = crate::base64::decode(value)?;
    if p.len() != TOKEN_LEN {
        return Err("invalid token length".into());
    }
    let expiry = u32::from_be_bytes(p[..EXPIRY_LEN].try_into().unwrap());
    // A cross-process token is signed with parent 0, so both candidates are
    // tried. Each MAC covers the expiry, so the loop always runs twice and
    // keeps the comparison constant-time regardless of which one matches.
    let mut ok = false;
    for candidate in [parent, 0] {
        let mac = sign(secret, expiry, candidate);
        let mut diff = 0u8;
        for i in 0..MAC_LEN {
            diff |= mac[i] ^ p[EXPIRY_LEN + i];
        }
        ok |= diff == 0;
    }
    if !ok {
        return Err("invalid token signature".into());
    }
    if (expiry as u64) < now() {
        return Err("token expired".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trip() {
        let t = issue(b"secret", 120, 42);
        assert_eq!(t.len(), 16);
        assert_eq!(verify(b"secret", &t, 42), Ok(()));
        assert!(verify(b"wrong", &t, 42).is_err());
        assert!(verify(b"secret", &t, 7).is_err());
    }
    #[test]
    fn cross_process_token_matches_any_parent() {
        let t = issue(b"secret", 120, 0);
        assert_eq!(verify(b"secret", &t, 12345), Ok(()));
    }
    #[test]
    fn tampering_is_rejected() {
        let t = issue(b"secret", 120, 42);
        let mut chars: Vec<char> = t.chars().collect();
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
        let bad: String = chars.into_iter().collect();
        assert!(verify(b"secret", &bad, 42).is_err());
    }
}
