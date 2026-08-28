#!/usr/bin/env bash
# Full usage-flow verification of sudo2fa inside an archlinux container.
# The host-built binary is copied into the container (no in-container build).
# TOTP codes and QR decoding are produced with Python (scripts/verify_qr.py).
set -u
cd "$(dirname "$0")/.."

PY=${PY:-/home/awinx/dev/venv/bin/python}
BIN=/usr/local/bin/sudo2fa
CT=sudo2fa-test
pass=0
fail=0

ok() { echo "PASS: $1"; pass=$((pass + 1)); }
no() { echo "FAIL: $1"; fail=$((fail + 1)); }
expect_fail() { # desc, then command...
    local desc=$1
    shift
    if "$@" >/dev/null 2>&1; then no "$desc"; else ok "$desc"; fi
}
expect_ok() {
    local desc=$1
    shift
    if out=$("$@" 2>&1); then ok "$desc (-> $out)"; else no "$desc ($out)"; fi
}

cleanup() { docker rm -f "$CT" >/dev/null 2>&1; rm -f .s2fa_qr_terminal; }
trap cleanup EXIT
cleanup

cargo build --release || exit 1

docker run -d --name "$CT" -v "$PWD":/work -w /work archlinux:latest sleep infinity >/dev/null || exit 1
run() { docker exec "$CT" "$@"; }

echo "== stage 1: setup, key file, QR =="
run install -m 4755 /work/target/release/sudo2fa "$BIN" || exit 1
out=$(run "$BIN" setup --qrcode) || { no "setup"; exit 1; }
SECRET=$(printf '%s\n' "$out" | sed -n 's/^TOTP secret: //p')
[ -n "$SECRET" ] || { no "setup printed no secret"; exit 1; }
ok "setup generated secret (QR rendered in terminal, no file stored)"
printf '%s\n' "$out" > .s2fa_qr_terminal

mode_owner=$(run stat -c '%a %u' /etc/shadow2fa)
[ "$mode_owner" = "600 0" ] && ok "key file is 0600 root-owned" || no "key file perms: $mode_owner"
run grep -qx "0:$SECRET" /etc/shadow2fa && ok "root record stored" || no "root record missing"

run chmod 644 /etc/shadow2fa
expect_fail "wrong file permissions refused" run "$BIN" 000000 true
run chmod 600 /etc/shadow2fa

CODE=$("$PY" scripts/verify_qr.py --totp "$SECRET") || exit 1
echo "-- host python: TOTP code $CODE (pyotp)"
"$PY" scripts/verify_qr.py .s2fa_qr_terminal "$SECRET" && ok "QR decodes to otpauth URI" || no "QR verification"

echo "== stage 2: token lifecycle (single shell session) =="
if docker exec -i -e CODE="$CODE" "$CT" bash -s <<'EOF'
pass=0; fail=0
ok() { echo "PASS: $1"; pass=$((pass+1)); }
no() { echo "FAIL: $1"; fail=$((fail+1)); }

T=$(sudo2fa "$CODE" -t 25) && ok "token issued" || no "token issue"
[ "$(sudo2fa "$T" -- id -u)" = "0" ] && ok "token authorizes in same session" || no "token same-session"
# NB: `timeout` forks sudo2fa, so the verifier's parent really is a DIFFERENT
# process than the issuer, and timeout propagates the exit status. A bare
# `sh -c "cmd"` is exec'd (sudo2fa inherits this shell's parent -> false pass),
# and `sh -c "cmd; :"` masks sudo2fa's exit status behind ':' -> false pass.
if timeout 5 sudo2fa "$T" -- id -u >/dev/null 2>&1; then no "foreign parent token refused"; else ok "foreign parent token refused"; fi

T2=$(sudo2fa "$CODE" -t 25 -c) && ok "cross-process token issued" || no "cross token issue"
[ "$(sh -c "sudo2fa $T2 -- id -u")" = "0" ] && ok "cross-process token works from child shell" || no "cross token failed"

T3=$(sudo2fa "$CODE" -t 20)
sleep 21
if sudo2fa "$T3" -- id -u >/dev/null 2>&1; then no "expired token refused"; else ok "expired token refused"; fi

c=${T2:0:1}; d=0; [ "$c" = "0" ] && d=1
if sudo2fa "${d}${T2:1}" -- id -u >/dev/null 2>&1; then no "tampered token refused"; else ok "tampered token refused"; fi

echo "STAGE2: pass=$pass fail=$fail"
[ "$fail" = 0 ]
EOF
then pass=$((pass+7)); else fail=$((fail+1)); no "token lifecycle"; fi

echo "== stage 3: command, login, user switching =="
expect_ok "authorized command executes as root" run "$BIN" "$CODE" -- id -u
expect_fail "wrong code refused" run "$BIN" 000000 -- id -u
expect_fail "garbage code refused" run "$BIN" zzzz -- id -u
expect_ok "login shell (-i) runs" bash -c "echo 'id -u; exit' | docker exec -i $CT $BIN '$CODE' -i"
run useradd -m tester
expect_ok "-u runs command as tester" run "$BIN" "$CODE" -u tester -- id -u
expect_ok "-u tester whoami" run "$BIN" "$CODE" -u tester -- whoami

echo "== stage 4: setuid privilege escalation =="
S2=$(run env SUDO_USER=nobody "$BIN" setup) || { no "second setup"; exit 1; }
SECRET2=$(printf '%s\n' "$S2" | sed -n 's/^TOTP secret: //p')
[ -n "$SECRET2" ] && ok "second setup for admin nobody" || no "second setup"
run grep -qx "65534:$SECRET2" /etc/shadow2fa && ok "nobody record added" || no "nobody record missing"
run grep -qx "0:$SECRET" /etc/shadow2fa && ok "root record preserved" || no "root record clobbered"
CODE2=$("$PY" scripts/verify_qr.py --totp "$SECRET2") || exit 1
expect_ok "setuid: nobody escalates with own code" \
    run setpriv --reuid=65534 --regid=65534 --clear-groups "$BIN" "$CODE2" -- id -u
expect_fail "setuid: nobody wrong code refused" \
    run setpriv --reuid=65534 --regid=65534 --clear-groups "$BIN" 000000 -- id -u
run install -m 755 /work/target/release/sudo2fa /tmp/s2fa-nosuid
expect_fail "no setuid: non-root cannot read key file" \
    run setpriv --reuid=65534 --regid=65534 --clear-groups /tmp/s2fa-nosuid "$CODE2" -- id -u

echo "== key file records =="
run cat /etc/shadow2fa | sed 's/:.*/:<redacted>/'

echo
echo "RESULT: pass=$pass fail=$fail"
[ "$fail" = 0 ]
