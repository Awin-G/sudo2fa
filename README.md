# sudo2fa

Dependency-free Linux TOTP authorization helper written in Rust.

## Build and install

```sh
cargo build --release
install -o root -g root -m 0755 target/release/sudo2fa /usr/local/sbin/sudo2fa
sudo /usr/local/sbin/sudo2fa setup --qrcode
```

`/etc/shadow2fa` is root-owned and mode `0600`. Each record is `UID:BASE32_SECRET`.
Running setup again replaces only the invoking administrator's record. With `sudo`,
the `SUDO_USER` account receives the record.

```text
sudo2fa <code> command [args...]
sudo2fa <code> --token [seconds]
sudo2fa <code> --token --cross-process [seconds]
sudo2fa <code> --user alice command [args...]
sudo2fa <code> -i
```

Tokens are HMAC-SHA1 signed, expire automatically, and normally bind to the issuing
process. `--cross-process` disables that binding.
