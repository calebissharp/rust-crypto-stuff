extern crate base64;
extern crate byteorder;
extern crate hex;

use byteorder::{BigEndian, WriteBytesExt};

// Initialize array of round constants
// (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
static ROUND_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn print_bytes(bytes: &[u8], new_line: bool) {
    for byte in bytes {
        print!("{:08b} ", byte);
    }
    if new_line {
        println!();
    }
}

fn init_hash() -> [u32; 8] {
    [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ]
}

fn convert_chunk_to_words(chunk: &[u8]) -> [u32; 16] {
    let mut w: [u32; 16] = [0; 16];

    for i in 0..16 {
        for b in 0..4 {
            let byte = chunk[i * 4 + b];
            w[i] = w[i] << 8;
            w[i] = w[i] | byte as u32;
        }
    }

    w
}

fn choice(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn usigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

fn usigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

fn sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ x >> 3
}

fn sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ x >> 10
}

fn pad_message(message: &[u8]) -> Vec<u8> {
    let l = message.len() * 8;
    let mut k = 0;
    while (l + k + 64) % 512 != 0 {
        k += 1;
    }

    let mut message_vec = message.to_vec();
    let mut padding_bytes: Vec<u8> = vec![0; k / 8];

    // Append '1' bit after message
    padding_bytes[0] = 1 << 7;
    // Append message length as big-endian u64 after padding bits
    padding_bytes.append(&mut (l as u64).to_be_bytes().to_vec());

    message_vec.append(&mut padding_bytes);

    assert!(message_vec.len() * 8 % 512 == 0);

    message_vec
}

fn into_chunks(slice: &[u8]) -> Vec<&[u8]> {
    let mut chunks: Vec<&[u8]> = vec![];

    for i in 0..slice.len() / 64 {
        chunks.push(&slice[i * 64..i * 64 + 64]);
    }

    chunks
}

fn process_chunk(chunk: &[u8], prev_hashes: &[u32; 8]) -> [u32; 8] {
    let mut w: [u32; 64] = [0; 64];

    // Copy chunk into message schedule array
    let chunk_words = convert_chunk_to_words(chunk);
    for i in 0..chunk_words.len() {
        w[i] = chunk_words[i];
    }

    for i in 16..64 {
        w[i] = w[i - 16]
            .wrapping_add(sigma0(w[i - 15]))
            .wrapping_add(w[i - 7])
            .wrapping_add(sigma1(w[i - 2]));
    }

    let mut a = prev_hashes[0];
    let mut b = prev_hashes[1];
    let mut c = prev_hashes[2];
    let mut d = prev_hashes[3];
    let mut e = prev_hashes[4];
    let mut f = prev_hashes[5];
    let mut g = prev_hashes[6];
    let mut h = prev_hashes[7];

    for i in 0..64 {
        let temp1 = h
            .wrapping_add(usigma1(e))
            .wrapping_add(choice(e, f, g))
            .wrapping_add(ROUND_CONSTANTS[i])
            .wrapping_add(w[i]);
        let temp2 = usigma0(a).wrapping_add(maj(a, b, c));

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    [
        prev_hashes[0].wrapping_add(a),
        prev_hashes[1].wrapping_add(b),
        prev_hashes[2].wrapping_add(c),
        prev_hashes[3].wrapping_add(d),
        prev_hashes[4].wrapping_add(e),
        prev_hashes[5].wrapping_add(f),
        prev_hashes[6].wrapping_add(g),
        prev_hashes[7].wrapping_add(h),
    ]
}

fn sha256(message: &[u8]) -> Vec<u8> {
    // Initialize hash values
    // (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19)
    let mut hashes = init_hash();

    let padded_message = pad_message(message);

    let chunks = into_chunks(&padded_message);
    for chunk in chunks.into_iter() {
        hashes = process_chunk(&chunk, &hashes);
    }

    let mut result: Vec<u8> = vec![];

    for i in 0..hashes.len() {
        result.write_u32::<BigEndian>(hashes[i]).unwrap();
    }

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
