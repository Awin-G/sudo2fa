//! Small QR encoder for otpauth URIs. It emits QR Version 5-L (37x37),
//! sufficient for normal TOTP labels, without a third-party dependency.

fn gf_mul(mut x: u8, mut y: u8) -> u8 {
    let mut r = 0;
    while y != 0 {
        if y & 1 != 0 {
            r ^= x;
        }
        x = if x & 0x80 != 0 {
            (x << 1) ^ 0x1d
        } else {
            x << 1
        };
        y >>= 1;
    }
    r
}
fn ec_codewords(data: &[u8]) -> Vec<u8> {
    let degree = 26;
    let mut generator = vec![1u8];
    let mut root = 1u8;
    for _ in 0..degree {
        let mut next = vec![0; generator.len() + 1];
        for (i, &v) in generator.iter().enumerate() {
            next[i] ^= v;
            next[i + 1] ^= gf_mul(v, root);
        }
        generator = next;
        root = gf_mul(root, 2);
    }
    let mut rem = vec![0u8; degree];
    for &v in data {
        let factor = v ^ rem[0];
        rem.rotate_left(1);
        *rem.last_mut().unwrap() = 0;
        for i in 0..degree {
            rem[i] ^= gf_mul(generator[i + 1], factor);
        }
    }
    rem
}
fn bch(v: u16, poly: u16) -> u16 {
    let top = poly as u32;
    let mut x = v as u32;
    while (32 - x.leading_zeros()) >= (32 - top.leading_zeros()) {
        x ^= top << ((32 - x.leading_zeros()) - (32 - top.leading_zeros()));
    }
    x as u16
}
fn reserved(size: usize) -> Vec<Vec<bool>> {
    let mut r = vec![vec![false; size]; size];
    let mark_finder = |r: &mut Vec<Vec<bool>>, x: usize, y: usize| {
        for dy in 0..=8 {
            for dx in 0..=8 {
                if x + dx < size && y + dy < size {
                    r[y + dy][x + dx] = true;
                }
            }
        }
    };
    mark_finder(&mut r, 0, 0);
    mark_finder(&mut r, size - 7, 0);
    mark_finder(&mut r, 0, size - 7);
    for i in 0..size {
        r[6][i] = true;
        r[i][6] = true;
    }
    for y in [6usize, 30] {
        for x in [6usize, 30] {
            if !(x == 6 && y == 6) && x < size && y < size {
                for dy in 0..=4 {
                    for dx in 0..=4 {
                        r[y - 2 + dy][x - 2 + dx] = true;
                    }
                }
            }
        }
    }
    for i in 0..9 {
        r[8][i] = true;
        r[i][8] = true;
        r[8][size - 1 - i] = true;
        r[size - 1 - i][8] = true;
    }
    r[size - 8][8] = true;
    r
}
fn finder(m: &mut [Vec<bool>], x: usize, y: usize) {
    for dy in 0..7 {
        for dx in 0..7 {
            m[y + dy][x + dx] = dx == 0
                || dx == 6
                || dy == 0
                || dy == 6
                || (dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4);
        }
    }
}
pub fn encode(text: &str) -> Result<Vec<Vec<bool>>, String> {
    let bytes = text.as_bytes();
    if bytes.len() > 106 {
        return Err("otpauth URI is too long for QR Version 5-L".into());
    }
    let mut data = Vec::with_capacity(108);
    data.push(0x40); // byte mode, followed by the 8-bit length field
    data.push(bytes.len() as u8);
    data.extend_from_slice(bytes);
    while data.len() < 108 {
        data.push(if data.len() % 2 == 0 { 0xec } else { 0x11 });
    }
    let ec = ec_codewords(&data);
    data.extend_from_slice(&ec);
    let size = 37;
    let mut m = vec![vec![false; size]; size];
    let r = reserved(size);
    finder(&mut m, 0, 0);
    finder(&mut m, size - 7, 0);
    finder(&mut m, 0, size - 7);
    for i in 8..size - 8 {
        m[6][i] = i % 2 == 0;
        m[i][6] = i % 2 == 0;
    }
    for y in [30usize] {
        for x in [30usize] {
            for dy in 0..5 {
                for dx in 0..5 {
                    m[y - 2 + dy][x - 2 + dx] =
                        dx == 0 || dx == 4 || dy == 0 || dy == 4 || (dx == 2 && dy == 2);
                }
            }
        }
    }
    m[size - 8][8] = true;
    let mut bits = Vec::new();
    for b in data {
        for n in (0..8).rev() {
            bits.push((b >> n) & 1 != 0);
        }
    }
    let mut at = 0usize;
    let mut x = size as isize - 1;
    let mut upward = true;
    while x > 0 {
        if x == 6 {
            x -= 1;
        }
        for yi in 0..size {
            let y = if upward { size - 1 - yi } else { yi };
            for xx in [x, x - 1] {
                if !r[y][xx as usize] {
                    let bit = if at < bits.len() { bits[at] } else { false };
                    at += 1;
                    m[y][xx as usize] = bit ^ ((y + xx as usize) % 2 == 0);
                }
            }
        }
        upward = !upward;
        x -= 2;
    }
    let format = ((1u16 << 3) | bch(1u16 << 3, 0x537)) ^ 0x5412; // level L, mask 0
    let mut p = 0;
    for i in 0..=5 {
        m[8][i] = ((format >> p) & 1) != 0;
        p += 1;
    }
    m[8][7] = ((format >> p) & 1) != 0;
    p += 1;
    m[8][8] = ((format >> p) & 1) != 0;
    p += 1;
    m[7][8] = ((format >> p) & 1) != 0;
    p += 1;
    for i in (0..=5).rev() {
        m[i][8] = ((format >> p) & 1) != 0;
        p += 1;
    }
    p = 0;
    for i in (size - 1 - 7..size).rev() {
        m[8][i] = ((format >> p) & 1) != 0;
        p += 1;
    }
    for i in size - 8..size {
        m[i][8] = ((format >> p) & 1) != 0;
        p += 1;
    }
    Ok(m)
}
pub fn svg(text: &str) -> Result<String, String> {
    let m = encode(text)?;
    let n = m.len();
    let mut s = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {} {}\" shape-rendering=\"crispEdges\"><rect width=\"100%\" height=\"100%\" fill=\"white\"/><path fill=\"black\" d=\"",
        n + 8,
        n + 8
    );
    for y in 0..n {
        for x in 0..n {
            if m[y][x] {
                s.push_str(&format!("M{} {}h1v1H{}z", x + 4, y + 4, x + 4));
            }
        }
    }
    s.push_str("\"/></svg>");
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn totp_uri_fits() {
        let m = encode("otpauth://totp/sudo2fa?secret=JBSWY3DPEHPK3PXP&issuer=sudo2fa").unwrap();
        assert_eq!(m.len(), 37);
        assert!(
            svg("otpauth://totp/sudo2fa?secret=JBSWY3DPEHPK3PXP&issuer=sudo2fa")
                .unwrap()
                .starts_with("<svg")
        );
    }
}
