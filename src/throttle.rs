//! Global failed-attempt rate limiting, shared by TOTP codes and tokens.
//!
//! One root-owned file records the timestamp (milliseconds) of the last failed
//! authentication. Any attempt arriving less than [`WINDOW_MS`] after it is
//! rejected without verification. The state is global on purpose — a single
//! attacker must not be able to lock everyone out for long — which is why the
//! window is short. Rate-limited attempts are *not* recorded, so hammering the
//! binary cannot extend the lockout indefinitely.
use std::{
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    time::{SystemTime, UNIX_EPOCH},
};

const WINDOW_MS: u128 = 3_000;

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

// Remaining lockout for a failure at `last`, or None if the window has passed.
fn retry_after(last: u128, now: u128) -> Option<u128> {
    let elapsed = now.saturating_sub(last);
    (elapsed < WINDOW_MS).then(|| WINDOW_MS - elapsed)
}

// A missing, unreadable, corrupt, or non-root-owned file means "no recent
// failure": we never refuse an attempt based on state we cannot trust.
fn last_failure(path: &str) -> Option<u128> {
    let meta = fs::metadata(path).ok()?;
    if meta.uid() != 0 || meta.permissions().mode() & 0o777 != 0o600 {
        return None;
    }
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

pub fn check(path: &str) -> Result<(), String> {
    if let Some(last) = last_failure(path) {
        if let Some(remaining) = retry_after(last, now_ms()) {
            return Err(format!(
                "too many failed attempts; try again in {}s",
                remaining.div_ceil(1000)
            ));
        }
    }
    Ok(())
}

pub fn record_failure(path: &str) {
    // Best effort: if the state cannot be persisted, authorization still wins.
    let _ = write_state(path, &now_ms().to_string());
}

// Same-directory temp file + rename, so a crash mid-write cannot leave a
// truncated counter behind.
fn write_state(path: &str, data: &str) -> std::io::Result<()> {
    let tmp = format!("{}.throttle-tmp", path);
    fs::write(&tmp, data)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn window_blocks_then_opens() {
        let last = 1_000_000;
        assert_eq!(retry_after(last, last), Some(WINDOW_MS));
        assert_eq!(retry_after(last, last + 2_999), Some(1));
        assert_eq!(retry_after(last, last + 3_000), None);
        assert_eq!(retry_after(last, last + 10_000), None);
        // A clock that jumped backwards must not extend the lockout forever.
        assert_eq!(retry_after(last, last - 5_000), Some(WINDOW_MS));
    }
}
