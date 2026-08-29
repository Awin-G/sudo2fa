# sudo2fa

A dependency-free, setuid-aware TOTP authorization helper for Linux.
Grant one-off or time-bounded root authority to a process — an AI agent,
a cron job, a remote shell — without ever handing out a password.

## Why

Classic privilege elevation breaks in non-interactive, headless contexts:

- **`sudo`** reads a password from the controlling TTY. Run under most
  agent frameworks (OpenAI, Claude, etc.), the agent's `bash` tool has no
  TTY, so `sudo` hangs the tool until it times out.
- **`pkexec`** requires a graphical Polkit agent on the *same* display.
  It cannot work on a headless box, under a systemd service, or over SSH.
- **Granting the agent the root password** exposes a long-lived credential
  to an autonomous, externally-controllable process.

sudo2fa inverts the model: the *human* authenticates, then the *agent*
executes. You (or the agent) trade a 6-digit TOTP code for a short-lived,
signed, process-bound token, and use that token — not a password — for the
elevated command.

```text
You:      sudo2fa setup --qrcode            # scan into your authenticator
Agent:    sudo2fa 123456 -- apt update      # one code = one command
Agent:    TOKEN=$(sudo2fa 123456 -t 300)    # or mint a reusable token
Agent:    sudo2fa "$TOKEN" -- systemctl restart nginx
```

The TOTP secret never leaves `/etc/shadow2fa`; nothing the agent can do
recovers it.

## Install

```sh
cargo build --release
install -o root -g root -m 4755 target/release/sudo2fa /usr/local/sbin/sudo2fa
sudo /usr/local/sbin/sudo2fa setup --qrcode
```

The binary is installed setuid root. The QR code is rendered directly in
your terminal (`--qrcode`); no secret-bearing file is written to disk.

`/etc/shadow2fa` is root-owned, mode `0600`, one record per line in
`UID:BASE32_SECRET` form. `setup` replaces only the invoking administrator's
record (via `SUDO_USER` when run through sudo), preserving others'.

## Usage

```text
sudo2fa <code|token> command [args...]      execute as root
sudo2fa <code|token> --token [seconds]      mint a token (default 120s, 20–1800s)
sudo2fa <code|token> --token --cross-process [seconds]
sudo2fa <code|token> --user <name> command  execute as another user
sudo2fa <code|token> -i                     start a login shell
sudo2fa setup [-q|--qrcode]                 (re)init the invoking admin's key
```

Everything after `--` belongs to the command, so it may use flags that would
otherwise be parsed by sudo2fa:

```text
sudo2fa <code> -- ls -l /root
```

A fresh TOTP code works once per 30-second window. Tokens are HMAC-SHA1
signed, expire automatically, and — unless `--cross-process` — bind to the
issuer's parent process, so they cannot be lifted out of the session that
minted them. This makes token reuse safe enough for an agent loop that runs
several privileged commands over a short task.

## Security model

- Secrets live only in `/etc/shadow2fa` (0600, root-owned); the binary
  refuses to run otherwise.
- The real UID is read from `/proc` (never `id -u`, which reports the
  effective UID under setuid). `SUDO_USER` selects the key in sudo contexts.
- External helpers are invoked by absolute path — never through `PATH` — to
  resist hijacking of a setuid process.
- Tokens are 36 bytes: 8-byte expiry, 8-byte bound parent pid (0 = unbound),
  and a 20-byte HMAC-SHA1 over the header, compared in constant time.
- TOTP follows RFC 6238 with a ±1 window (current, two past, one future).

## Limitations

- The whole pipeline is TOTP, so the 30-second code window bounds one-shot
  authorizations; long-running agent tasks should mint a token.
- Token binding is best-effort under shell `exec` optimization
  (see `docs/DESIGN.md` §4); use `timeout`/`setsid` wrappers when testing it.
- QR output targets Version 5-L (106-byte payload); it renders to the
  terminal, not to a file.

## Development

```sh
cargo test --release
bash scripts/docker_verify.sh   # full end-to-end suite in an archlinux container
```

The suite decodes the rendered QR with a real decoder (OpenCV) and
cross-checks TOTP codes against `pyotp`. See `docs/DESIGN.md` for the full
design.
