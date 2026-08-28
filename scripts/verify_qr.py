#!/usr/bin/env python
"""QR/TOTP verification helper for sudo2fa.

The QR code SVG is parsed, rendered to an image and decoded with a real
QR decoder (OpenCV) across several module scales and mild lens blur, the
way a phone camera would sample it. The decoded payload must match the
expected otpauth URI. TOTP codes are generated independently with pyotp.
Nothing here inspects module patterns as text.

Usage:
    verify_qr.py --totp SECRET            print a pyotp TOTP code
    verify_qr.py SVGFILE SECRET           decode SVG and assert URI
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


def load_matrix(svg_path):
    data = open(svg_path, encoding="utf-8").read()
    path = re.search(r'<path fill="black" d="([^"]+)"', data)
    assert path, "no QR path found in SVG"
    modules = set()
    for m in re.finditer(r"M(\d+) (\d+)h1v1H(\d+)z", path.group(1)):
        x, y, hx = int(m.group(1)), int(m.group(2)), int(m.group(3))
        assert x == hx, "unexpected path form"
        modules.add((x, y))
    assert modules, "empty QR path"
    max_x = max(p[0] for p in modules)
    max_y = max(p[1] for p in modules)
    assert max_x == max_y, "non-square QR"
    n = max_x - 3  # modules are offset by a 4-module border
    matrix = [[False] * n for _ in range(n)]
    for x, y in modules:
        matrix[y - 4][x - 4] = True
    return matrix


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
    svg_path, secret = sys.argv[1], sys.argv[2]
    matrix = load_matrix(svg_path)
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
