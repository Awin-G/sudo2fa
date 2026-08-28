use std::{
    env, fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    process::{Command, exit},
};
use sudo2fa::{base32, qr, token, totp};

const FILE: &str = "/etc/shadow2fa";
fn path() -> String {
    env::var("SUDO2FA_FILE").unwrap_or_else(|_| FILE.into())
}
fn uid() -> u32 {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(65534)
}
fn named_uid(name: &str) -> u32 {
    Command::new("id")
        .args(["-u", name])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
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
    let me = env::var("SUDO_USER")
        .map(|name| named_uid(&name).to_string())
        .unwrap_or_else(|_| uid().to_string());
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
    let secret = totp::new_secret();
    let p = path();
    if let Some(parent) = std::path::Path::new(&p).parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?
    }
    let target = env::var("SUDO_USER")
        .ok()
        .map(|s| named_uid(&s))
        .unwrap_or(0);
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
        let svg = qr::svg(&uri)?;
        fs::write("sudo2fa-qrcode.svg", svg).map_err(|e| e.to_string())?;
        println!("QR code written to sudo2fa-qrcode.svg");
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
    while let Some(x) = a.next() {
        match x.as_str() {
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
            token::issue(&secret, seconds, if cross { 0 } else { std::process::id() })
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
        c = Command::new("su");
        c.args(["-s", "/bin/sh", "-c", &command.join(" "), &u]);
    }
    let status = c.status().map_err(|e| e.to_string())?;
    exit(status.code().unwrap_or(1))
}
