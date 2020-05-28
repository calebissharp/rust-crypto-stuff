extern crate base64;
extern crate byteorder;
extern crate hex;

mod sha256;

use sha256::sha256;

fn pad_with_zero_bytes(arr: &[u8], target_len: usize) -> Vec<u8> {
    let bytes_needed = target_len - arr.len();

    let mut padding: Vec<u8> = vec![0; bytes_needed];
    let mut padded_message = arr.clone().to_vec();
    padded_message.append(&mut padding);

    padded_message
}

fn gen_key_pad(key: &Vec<u8>, pad: &Vec<u8>) -> Vec<u8> {
    key.iter()
        .zip(pad.iter())
        .map(|(&byte, &opad)| byte ^ opad)
        .collect()
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let block_size = 64;
    let mut processed_key = key.to_vec();

    if key.len() > block_size {
        processed_key = sha256(key).to_vec();
    }

    if key.len() < block_size {
        processed_key = pad_with_zero_bytes(key, block_size);
    }

    let outer_pad = vec![0x5c; block_size];
    let inner_pad = vec![0x36; block_size];

    let outer_key_pad = gen_key_pad(&processed_key, &outer_pad);
    let inner_key_pad = gen_key_pad(&processed_key, &inner_pad);

    let hash_sum_1 = sha256(&[inner_key_pad, message.to_vec()].concat());
    let hash_sum_2 = sha256(&[outer_key_pad, hash_sum_1.to_vec()].concat());

    hash_sum_2
}

const HKDF_HASH_LENGTH: usize = 32;

fn hkdf(length: usize, ikm: &[u8], salt: &[u8], ctx: &[u8]) -> Vec<u8> {
    let salt = salt.clone();
    // if salt.len() == 0 {
    //     salt = [0u8; 32];
    // };

    let prk = hmac_sha256(salt, ikm);

    // Ceiling division
    let t = (length + HKDF_HASH_LENGTH - 1) / HKDF_HASH_LENGTH;

    let mut okm: Vec<u8> = vec![];
    let mut prev: Vec<u8> = vec![];

    for i in 0..t {
        prev.append(&mut ctx.clone().to_vec());
        prev.push(1 + i as u8);

        okm.append(&mut hmac_sha256(&prk, &prev).to_vec());
    }

    okm[0..length].to_vec()
}

fn main() {
    println!("{}", hex::encode(sha256(b"My message")));

    assert!(
        hex::encode(sha256(b"abc"))
            == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert!(
        hex::encode(hmac_sha256(
            b"key",
            b"The quick brown fox jumps over the lazy dog",
        )) == "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
    );

    let key = hkdf(
        16,
        b"hello",
        &hex::decode("8e94ef805b93e683ff18").unwrap(),
        b"",
    );

    assert_eq!(hex::encode(key), "13485067e21af17c0900f70d885f0259");
}
