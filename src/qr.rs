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
fn format_bits() -> u16 {
    // EC level L (01), mask 0; BCH(15,5) remainder over 0x537, then XOR 0x5412.
    let data = 1u32 << 3;
    let mut v = data << 10;
    for i in (10..=14).rev() {
        if (v >> i) & 1 == 1 {
            v ^= 0x537u32 << (i - 10);
        }
    }
    (((data << 10) | (v & 0x3ff)) as u16) ^ 0x5412
}
fn reserved(size: usize) -> Vec<Vec<bool>> {
    let mut r = vec![vec![false; size]; size];
    let block = |r: &mut Vec<Vec<bool>>, y0: usize, x0: usize| {
        for dy in 0..8 {
            for dx in 0..8 {
                r[y0 + dy][x0 + dx] = true;
            }
        }
    };
    block(&mut r, 0, 0);
    block(&mut r, 0, size - 8);
    block(&mut r, size - 8, 0);
    for i in 0..size {
        r[6][i] = true;
        r[i][6] = true;
    }
    // Version 5 has a single alignment pattern centered at (30, 30); the
    // other center combinations would overlap finders and are omitted.
    for dy in 0..5 {
        for dx in 0..5 {
            r[28 + dy][28 + dx] = true;
        }
    }
    for i in 0..=8 {
        r[8][i] = true;
        r[i][8] = true;
    }
    for i in 0..8 {
        r[8][size - 1 - i] = true;
        r[size - 1 - i][8] = true;
    }
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
    // Bit-level stream: 4-bit byte-mode indicator, 8-bit count, payload,
    // terminator (up to 4 bits), byte alignment, alternating pad codewords.
    let mut bits: Vec<bool> = vec![false, true, false, false];
    for i in (0..8).rev() {
        bits.push((bytes.len() >> i) & 1 == 1);
    }
    for &b in bytes {
        for i in (0..8).rev() {
            bits.push((b >> i) & 1 == 1);
        }
    }
    let cap = 108 * 8;
    for _ in 0..4.min(cap - bits.len()) {
        bits.push(false);
    }
    while bits.len() % 8 != 0 {
        bits.push(false);
    }
    let mut data: Vec<u8> = bits
        .chunks(8)
        .map(|c| c.iter().fold(0u8, |acc, &b| (acc << 1) | b as u8))
        .collect();
    let mut pad = 0xecu8;
    while data.len() < 108 {
        data.push(pad);
        pad = if pad == 0xec { 0x11 } else { 0xec };
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
    let format = format_bits();
    // First copy (ISO placement, Nayuki coordinate convention resolved to
    // [row][col]): bits 0-5 run down column 8, bits 9-14 run along row 8.
    let mut p = 0;
    for i in 0..=5 {
        m[i][8] = ((format >> p) & 1) != 0;
        p += 1;
    }
    m[7][8] = ((format >> p) & 1) != 0;
    p += 1;
    m[8][8] = ((format >> p) & 1) != 0;
    p += 1;
    m[8][7] = ((format >> p) & 1) != 0;
    p += 1;
    for i in (0..=5).rev() {
        m[8][i] = ((format >> p) & 1) != 0;
        p += 1;
    }
    p = 0;
    for i in (size - 8..size).rev() {
        m[8][i] = ((format >> p) & 1) != 0;
        p += 1;
    }
    for i in size - 7..size {
        m[i][8] = ((format >> p) & 1) != 0;
        p += 1;
    }
    m[size - 8][8] = true; // dark module, never part of format data
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
