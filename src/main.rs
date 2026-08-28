use std::{
    env, fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    process::{Command, exit},
};
use sudo2fa::{base32, qr, token, totp};

const FILE: &str = "/etc/shadow2fa";
// External helpers must never be resolved through PATH: as a setuid binary,
// an attacker-controlled PATH entry would be executed with elevated rights.
const ID: &[&str] = &["/usr/bin/id", "/bin/id"];
const SU: &[&str] = &["/bin/su", "/usr/bin/su"];
fn which(candidates: &[&str]) -> String {
    candidates
        .iter()
        .find(|p| std::path::Path::new(p).exists())
        .unwrap_or(&candidates[0])
        .to_string()
}
fn path() -> String {
    env::var("SUDO2FA_FILE").unwrap_or_else(|_| FILE.into())
}
fn uid() -> u32 {
    // Real UID from /proc (setuid binaries keep the invoking account here,
    // while `id -u` would report the effective UID).
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
        })
        .unwrap_or(65534)
}
// Fail closed: an unresolvable name must never fall back to root's key.
fn named_uid(name: &str) -> Result<u32, String> {
    let out = Command::new(which(ID))
        .args(["-u", name])
        .output()
        .map_err(|e| format!("cannot run id: {}", e))?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.trim()
        .parse()
        .map_err(|_| format!("cannot resolve user {}", name))
}
fn parent_pid() -> u32 {
    fs::read_to_string("/proc/self/stat")
        .ok()
        .and_then(|s| {
            s.rsplit_once(") ")
                .and_then(|(_, v)| v.split_whitespace().nth(1).and_then(|p| p.parse().ok()))
        })
        .unwrap_or(0)
}
fn load() -> Result<Vec<u8>, String> {
    let p = path();
    let meta = fs::metadata(&p).map_err(|_| format!("cannot read {}", p))?;
    if meta.permissions().mode() & 0o777 != 0o600 || meta.uid() != 0 {
        return Err("refusing: /etc/shadow2fa must be root-owned mode 0600".into());
    }
    // sudo preserves the invoking account in SUDO_USER; its key is used even
    // though this process is running with effective UID 0.
    let me = match env::var("SUDO_USER") {
        Ok(name) => named_uid(&name)?.to_string(),
        Err(_) => uid().to_string(),
    };
    for line in fs::read_to_string(p).map_err(|e| e.to_string())?.lines() {
        let mut x = line.splitn(2, ':');
        if x.next() == Some(&me) {
            return base32::decode(x.next().unwrap_or(""));
        }
    }
    Err("no TOTP key for this user".into())
}
fn setup() -> Result<(), String> {
    if uid() != 0 {
        return Err("setup must be run as root".into());
    }
    let secret = totp::new_secret()?;
    let p = path();
    if let Some(parent) = std::path::Path::new(&p).parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?
    }
    let target = match env::var("SUDO_USER") {
        Ok(name) => named_uid(&name)?,
        Err(_) => 0,
    };
    let mut records = fs::read_to_string(&p)
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.starts_with(&format!("{}:", target)))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    records.push(format!("{}:{}", target, base32::encode(&secret)));
    fs::write(&p, records.join("\n") + "\n").map_err(|e| e.to_string())?;
    fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    let uri = format!(
        "otpauth://totp/sudo2fa?secret={}&issuer=sudo2fa",
        base32::encode(&secret)
    );
    let q = env::args().any(|a| a == "-q" || a == "--qrcode");
    println!("TOTP secret: {}", base32::encode(&secret));
    println!("Add this URI to your authenticator: {}", uri);
    if q {
        // Half-block terminal rendering; no secret-bearing file is stored.
        println!("{}", qr::terminal(&qr::encode(&uri)?));
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("sudo2fa: {}", e);
        exit(1)
    }
}
fn run() -> Result<(), String> {
    let mut a = env::args().skip(1);
    let first = a
        .next()
        .ok_or("usage: sudo2fa <code|token> [options] command...")?;
    if first == "setup" {
        return setup();
    }
    let secret = load()?;
    let mut token_mode = false;
    let mut login = false;
    let mut cross = false;
    let mut user = None;
    let mut seconds = 120u64;
    let mut command = Vec::new();
    let mut flags_done = false;
    while let Some(x) = a.next() {
        if flags_done {
            command.push(x.into());
            continue;
        }
        match x.as_str() {
            "--" => flags_done = true,
            "-t" | "--token" => token_mode = true,
            "-i" => login = true,
            "-c" | "--cross-process" => cross = true,
            "-u" | "--user" => user = a.next(),
            "-q" | "--qrcode" => {}
            x if token_mode && command.is_empty() && x.parse::<u64>().is_ok() => {
                seconds = x.parse().unwrap()
            }
            x => command.push(x.into()),
        }
    }
    if !totp::verify(&secret, &first) {
        token::verify(&secret, &first, parent_pid())?
    }
    if token_mode {
        if seconds < 20 || seconds > 1800 {
            return Err("token lifetime must be between 20 and 1800 seconds".into());
        }
        println!(
            "{}",
            // Bind to the issuing process's parent (typically the shell) so
            // reuse stays inside that session; 0 disables the binding.
            token::issue(&secret, seconds, if cross { 0 } else { parent_pid() })
        );
        return Ok(());
    }
    if login {
        command = vec![env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into())];
    }
    if command.is_empty() {
        return Err("no command specified".into());
    }
    let mut c = Command::new(&command[0]);
    c.args(&command[1..]);
    if let Some(u) = user {
        c = Command::new(which(SU));
        c.args(["-s", "/bin/sh", "-c", &command.join(" "), &u]);
    }
    let status = c.status().map_err(|e| e.to_string())?;
    exit(status.code().unwrap_or(1))
}
