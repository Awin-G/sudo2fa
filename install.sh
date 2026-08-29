#!/usr/bin/env bash
# Build and install sudo2fa as a setuid-root binary, then bootstrap the TOTP
# key for the invoking administrator. Safe to re-run: setup only replaces the
# calling admin's record and preserves other admins' keys.
set -euo pipefail
cd "$(dirname "$0")"

PREFIX="${PREFIX:-/usr/local}"
BINDIR="$PREFIX/bin"
KEYFILE="${SUDO2FA_FILE:-/etc/shadow2fa}"
INSTALL_BIN="$BINDIR/sudo2fa"

usage() {
    cat <<'EOF'
Usage: ./install.sh [--no-setup]

  --no-setup   install the binary only; skip the interactive TOTP setup.
               (Useful in scripts/containers; run `sudo sudo2fa setup --qrcode`
                later when you can scan the QR code.)

Environment:
  PREFIX=<dir>      install prefix (default: /usr/local)
  SUDO2FA_FILE=<p>  key file path override (default: /etc/shadow2fa)
EOF
}

need_root() {
    [ "$(id -u)" -eq 0 ] || { echo "error: run as root (e.g. sudo ./install.sh)" >&2; exit 1; }
}

no_setup=0
for a in "$@"; do
    case "$a" in
        --no-setup) no_setup=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown argument: $a" >&2; usage; exit 1 ;;
    esac
done

echo "== building (release) =="
cargo build --release

need_root

echo "== installing to $BINDIR (setuid root) =="
install -o root -g root -m 4755 -D target/release/sudo2fa "$INSTALL_BIN"
echo "installed: $INSTALL_BIN ($(ls -l "$INSTALL_BIN" | awk '{print $1, $3":"$4}'))"

if [ "$no_setup" -eq 1 ]; then
    echo "== skipping setup (--no-setup); run: sudo $INSTALL_BIN setup --qrcode =="
    exit 0
fi

echo "== TOTP setup for invoking admin =="
if [ -t 0 ] && [ -t 1 ]; then
    # Interactive terminal: render the QR inline so it can be scanned.
    "$INSTALL_BIN" setup --qrcode
else
    echo "warning: not a TTY; printing secret and URI only (no QR)."
    "$INSTALL_BIN" setup
fi

echo
echo "== done =="
echo "Key file: $KEYFILE (root:root 0600)"
echo "Authorize one-off:  sudo2fa <code> -- <command>"
echo "Mint a token:       sudo2fa <code> -t [seconds]"
