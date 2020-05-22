extern crate base64;
extern crate byteorder;
extern crate hex;

use byteorder::{BigEndian, WriteBytesExt};
use std::num::Wrapping;

macro_rules! wrapping_arr {
    ($($value:expr),*) => {
        [$(Wrapping($value)),*]
    }
}

// Initialize array of round constants
// (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
static ROUND_CONSTANTS: [Wrapping<u32>; 64] = wrapping_arr![
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

fn print_bytes(bytes: &[u8], new_line: bool) {
    for byte in bytes {
        print!("{:08b} ", byte);
    }
    if new_line {
        println!();
    }
}

fn init_hash() -> [Wrapping<u32>; 8] {
    wrapping_arr![
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19
    ]
}

fn choice(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

fn sha256(message: &[u8]) -> Vec<u8> {
    // Initialize hash values
    // (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19)
    let mut hashes = init_hash();

    let l = message.len() * 8;
    let mut k = 0;
    while (l + k + 64) % 512 != 0 {
        k += 1;
        if k > 1000000 {
            panic!("value for k is too large!");
        }
    }

    let mut padding_bytes: Vec<u8> = vec![0; k / 8];

    // Append '1' bit after message
    padding_bytes[0] = 1 << 7;

    // Append message length as big-endian u64 after padding bits
    padding_bytes.append(&mut (l as u64).to_be_bytes().to_vec());

    let mut padded_message = message.to_vec();
    padded_message.append(&mut padding_bytes);

    assert!(padded_message.len() * 8 % 512 == 0);

    for chunk_index in 0..padded_message.len() / 64 {
        let chunk = &padded_message[chunk_index * 64..chunk_index * 64 + 64];
        let mut w: [Wrapping<u32>; 64] = [Wrapping(0); 64];

        // Copy chunk into message schedule arra
        for i in 0..16 {
            for b in 0..4 {
                let byte = chunk[i * 4 + b];
                w[i] = w[i] << 8;
                w[i] = Wrapping(w[i].0 | byte as u32);
            }
        }

        for i in 16..64 {
            let s0: u32 =
                w[i - 15].0.rotate_right(7) ^ w[i - 15].0.rotate_right(18) ^ w[i - 15].0 >> 3;
            let s1: u32 =
                w[i - 2].0.rotate_right(17) ^ w[i - 2].0.rotate_right(19) ^ w[i - 2].0 >> 10;

            w[i] = w[i - 16] + Wrapping(s0) + w[i - 7] + Wrapping(s1);
        }

        let mut a = hashes[0];
        let mut b = hashes[1];
        let mut c = hashes[2];
        let mut d = hashes[3];
        let mut e = hashes[4];
        let mut f = hashes[5];
        let mut g = hashes[6];
        let mut h = hashes[7];

        for i in 0..64 {
            let s1 = e.0.rotate_right(6) ^ e.0.rotate_right(11) ^ e.0.rotate_right(25);
            // let ch = (e & f) ^ (!e & g);
            let ch = Wrapping(choice(e.0, f.0, g.0));
            let temp1 = h + Wrapping(s1) + ch + ROUND_CONSTANTS[i] + w[i];
            let s0 = a.0.rotate_right(2) ^ a.0.rotate_right(13) ^ a.0.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = Wrapping(s0) + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        hashes[0] += a;
        hashes[1] += b;
        hashes[2] += c;
        hashes[3] += d;
        hashes[4] += e;
        hashes[5] += f;
        hashes[6] += g;
        hashes[7] += h;
    }

    let mut result: Vec<u8> = vec![];

    result.write_u32::<BigEndian>(hashes[0].0).unwrap();
    result.write_u32::<BigEndian>(hashes[1].0).unwrap();
    result.write_u32::<BigEndian>(hashes[2].0).unwrap();
    result.write_u32::<BigEndian>(hashes[3].0).unwrap();
    result.write_u32::<BigEndian>(hashes[4].0).unwrap();
    result.write_u32::<BigEndian>(hashes[5].0).unwrap();
    result.write_u32::<BigEndian>(hashes[6].0).unwrap();
    result.write_u32::<BigEndian>(hashes[7].0).unwrap();

    result
}

// fn gen_hmac(key: u64, message: String) -> u32 {
//     let pad: u64 = 0;
// }

fn main() {
    println!("{}", hex::encode(sha256(b"My message")));

    assert!(
        hex::encode(sha256(b"abc"))
            == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
}
