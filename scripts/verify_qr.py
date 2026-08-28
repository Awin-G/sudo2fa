#!/usr/bin/env python
"""QR/TOTP verification helper for sudo2fa.

The terminal-rendered QR half/full block output is parsed back into a
module matrix, rendered to an image and decoded with a real QR decoder
(OpenCV) across several module scales and mild lens blur, the way a phone
camera would sample it. The decoded payload must match the expected
otpauth URI. TOTP codes are generated independently with pyotp. Nothing
here inspects module patterns as text.

Usage:
    verify_qr.py --totp SECRET            print a pyotp TOTP code
    verify_qr.py TERMINAL_FILE SECRET     decode terminal QR and assert URI
"""
import re
import sys

import numpy as np
from PIL import Image

try:
    from pyzbar.pyzbar import decode as zbar_decode
except Exception:
    zbar_decode = None
import cv2
import pyotp

ANSI = re.compile(r"\x1b\[[0-9;]*m")
# fg=black / bg=white scheme: which halves are dark modules
CHARS = {"█": (1, 1), " ": (0, 0), "▀": (1, 0), "▄": (0, 1)}


def load_matrix(terminal_path):
    text = open(terminal_path, encoding="utf-8").read()
    grid = []
    for line in text.splitlines():
        stripped = ANSI.sub("", line)
        if not stripped or not all(c in CHARS for c in stripped):
            continue  # non-QR output lines (secret, URI, messages)
        top, bot = [], []
        for ch in stripped:
            a, b = CHARS.get(ch, (None, None))
            assert a is not None, f"unexpected QR char {ch!r}"
            top.append(a)
            bot.append(b)
        grid.append(top)
        grid.append(bot)
    assert grid, "no QR rows"
    width = len(grid[0])
    assert all(len(r) == width for r in grid), "ragged QR rows"
    n = width - 8  # 4-module border per side
    assert n > 0 and len(grid) >= n + 8, "bad QR dimensions"  # odd heights get one pad row
    return [[bool(grid[y + 4][x + 4]) for x in range(n)] for y in range(n)]


def render(matrix, scale, blur, border=4):
    n = len(matrix)
    size = (n + 2 * border) * scale
    img = np.full((size, size), 255, dtype=np.uint8)
    for y in range(n):
        for x in range(n):
            if matrix[y][x]:
                y0 = (y + border) * scale
                x0 = (x + border) * scale
                img[y0:y0 + scale, x0:x0 + scale] = 0
    if blur:
        img = cv2.GaussianBlur(img, (blur, blur), 0)
    return img


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    if sys.argv[1] == "--totp":
        print(pyotp.TOTP(sys.argv[2]).now())
        return
    qr_path, secret = sys.argv[1], sys.argv[2]
    matrix = load_matrix(qr_path)
    expected = f"otpauth://totp/sudo2fa?secret={secret}&issuer=sudo2fa"

    detector = cv2.QRCodeDetector()
    matched = None
    for blur in (0, 3, 5):
        for scale in (6, 8, 10, 12, 16, 20):
            img = render(matrix, scale, blur)
            decoded, _, _ = detector.detectAndDecode(img)
            if decoded == expected:
                matched = (blur, scale)
                break
            if zbar_decode is not None:
                results = zbar_decode(Image.fromarray(img))
                if results and results[0].data.decode() == expected:
                    matched = (blur, scale, "pyzbar")
                    break
        if matched:
            break
    assert matched, "no decoder produced the expected URI at any scale/blur"

    code = pyotp.TOTP(secret).now()
    assert re.fullmatch(r"\d{6}", code), f"pyotp produced odd code {code!r}"
    print(f"QR-DECODE-OK (decoded via blur={matched[0]} scale={matched[1]}): "
          f"URI matches secret")


if __name__ == "__main__":
    main()
