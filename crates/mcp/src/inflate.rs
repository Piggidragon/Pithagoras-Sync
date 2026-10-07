//! DEFLATE (RFC 1951) decoding, for the deflated entries of a zip file. The
//! output is bounded by the size the archive's directory names, so a small
//! entry cannot expand without limit.

struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    bit: u32,
    nbits: u32,
}

impl Bits<'_> {
    fn need(&mut self, n: u32) -> Result<(), String> {
        while self.nbits < n {
            let b = *self
                .data
                .get(self.pos)
                .ok_or("the compressed data ends early")?;
            self.pos += 1;
            self.bit |= u32::from(b) << self.nbits;
            self.nbits += 8;
        }
        Ok(())
    }

    fn take(&mut self, n: u32) -> Result<u32, String> {
        if n == 0 {
            return Ok(0);
        }
        self.need(n)?;
        let v = self.bit & ((1u32 << n) - 1);
        self.bit >>= n;
        self.nbits -= n;
        Ok(v)
    }

    fn align(&mut self) {
        self.bit = 0;
        self.nbits = 0;
    }
}

/// A canonical Huffman code: how many codes of each length, and the symbols
/// in code order.
struct Huffman {
    counts: [u16; 16],
    symbols: Vec<u16>,
}

impl Huffman {
    fn new(lengths: &[u8]) -> Result<Huffman, String> {
        let mut counts = [0u16; 16];
        for &l in lengths {
            counts[l as usize] += 1;
        }
        counts[0] = 0;
        let mut left = 1i32;
        for &c in &counts[1..] {
            left = left * 2 - i32::from(c);
            if left < 0 {
                return Err("an over-subscribed Huffman code".into());
            }
        }
        let mut offs = [0u16; 16];
        for i in 1..15 {
            offs[i + 1] = offs[i] + counts[i];
        }
        let mut symbols = vec![0u16; lengths.len()];
        for (s, &l) in lengths.iter().enumerate() {
            if l != 0 {
                symbols[offs[l as usize] as usize] = s as u16;
                offs[l as usize] += 1;
            }
        }
        Ok(Huffman { counts, symbols })
    }

    fn decode(&self, b: &mut Bits) -> Result<u16, String> {
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..16 {
            code |= b.take(1)? as i32;
            let count = i32::from(self.counts[len]);
            if code - count < first {
                return self
                    .symbols
                    .get((index + code - first) as usize)
                    .copied()
                    .ok_or_else(|| "a bad Huffman code".to_string());
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        Err("a bad Huffman code".into())
    }
}

const LEN_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEN_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

/// Decodes raw DEFLATE data that must come out at exactly `size` bytes; more
/// is refused as soon as it shows.
pub fn inflate(data: &[u8], size: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(size.min(64 << 20));
    let mut b = Bits {
        data,
        pos: 0,
        bit: 0,
        nbits: 0,
    };
    loop {
        let last = b.take(1)?;
        match b.take(2)? {
            0 => {
                b.align();
                let at = b.pos;
                let head = data
                    .get(at..at + 4)
                    .ok_or("the compressed data ends early")?;
                let len = u16::from_le_bytes([head[0], head[1]]);
                let nlen = u16::from_le_bytes([head[2], head[3]]);
                if len != !nlen {
                    return Err("a stored block with a bad length".into());
                }
                let block = data
                    .get(at + 4..at + 4 + len as usize)
                    .ok_or("the compressed data ends early")?;
                if out.len() + block.len() > size {
                    return Err("more data than the archive says".into());
                }
                out.extend_from_slice(block);
                b.pos = at + 4 + len as usize;
            }
            1 => {
                let mut lengths = [0u8; 288];
                lengths[..144].fill(8);
                lengths[144..256].fill(9);
                lengths[256..280].fill(7);
                lengths[280..].fill(8);
                let lit = Huffman::new(&lengths)?;
                let dist = Huffman::new(&[5u8; 30])?;
                codes(&mut b, &mut out, &lit, &dist, size)?;
            }
            2 => {
                let (lit, dist) = dynamic(&mut b)?;
                codes(&mut b, &mut out, &lit, &dist, size)?;
            }
            _ => return Err("a block of an unknown type".into()),
        }
        if last == 1 {
            break;
        }
    }
    Ok(out)
}

fn dynamic(b: &mut Bits) -> Result<(Huffman, Huffman), String> {
    const ORDER: [usize; 19] = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];
    let nlen = b.take(5)? as usize + 257;
    let ndist = b.take(5)? as usize + 1;
    let ncode = b.take(4)? as usize + 4;
    if nlen > 286 || ndist > 30 {
        return Err("a bad dynamic block".into());
    }
    let mut cl = [0u8; 19];
    for &i in &ORDER[..ncode] {
        cl[i] = b.take(3)? as u8;
    }
    let clh = Huffman::new(&cl)?;
    let mut lengths = vec![0u8; nlen + ndist];
    let mut i = 0;
    while i < nlen + ndist {
        let sym = clh.decode(b)?;
        let (value, repeat) = match sym {
            0..=15 => (sym as u8, 1),
            16 => {
                let prev = *lengths
                    .get(i.wrapping_sub(1))
                    .filter(|_| i > 0)
                    .ok_or("a repeat with nothing before it")?;
                (prev, 3 + b.take(2)? as usize)
            }
            17 => (0, 3 + b.take(3)? as usize),
            18 => (0, 11 + b.take(7)? as usize),
            _ => return Err("a bad code length".into()),
        };
        if i + repeat > nlen + ndist {
            return Err("too many code lengths".into());
        }
        lengths[i..i + repeat].fill(value);
        i += repeat;
    }
    if lengths[256] == 0 {
        return Err("a block without an end code".into());
    }
    Ok((
        Huffman::new(&lengths[..nlen])?,
        Huffman::new(&lengths[nlen..])?,
    ))
}

fn codes(
    b: &mut Bits,
    out: &mut Vec<u8>,
    lit: &Huffman,
    dist: &Huffman,
    size: usize,
) -> Result<(), String> {
    loop {
        let sym = lit.decode(b)? as usize;
        match sym {
            0..=255 => {
                if out.len() >= size {
                    return Err("more data than the archive says".into());
                }
                out.push(sym as u8);
            }
            256 => return Ok(()),
            257..=285 => {
                let i = sym - 257;
                let len = LEN_BASE[i] as usize + b.take(u32::from(LEN_EXTRA[i]))? as usize;
                let d = dist.decode(b)? as usize;
                if d >= 30 {
                    return Err("a bad distance code".into());
                }
                let back = DIST_BASE[d] as usize + b.take(u32::from(DIST_EXTRA[d]))? as usize;
                if back > out.len() {
                    return Err("a distance before the start".into());
                }
                if out.len() + len > size {
                    return Err("more data than the archive says".into());
                }
                let start = out.len() - back;
                for k in 0..len {
                    let c = out[start + k];
                    out.push(c);
                }
            }
            _ => return Err("a bad length code".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_what_zlib_wrote_at_every_level() {
        let want = include_bytes!("../tests/data/random.bin");
        for data in [
            &include_bytes!("../tests/data/random.l0.deflate")[..],
            &include_bytes!("../tests/data/random.l1.deflate")[..],
            &include_bytes!("../tests/data/random.l9.deflate")[..],
        ] {
            assert_eq!(inflate(data, want.len()).unwrap(), want);
            // Bounded: one byte less than it holds is refused.
            assert!(inflate(data, want.len() - 1).is_err());
            assert!(inflate(&data[..data.len() / 2], want.len()).is_err());
        }
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        for seed in 0u32..200 {
            let mut x = seed.wrapping_mul(2_654_435_761);
            let junk: Vec<u8> = (0..64)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    x as u8
                })
                .collect();
            let _ = inflate(&junk, 4096);
        }
    }
}
