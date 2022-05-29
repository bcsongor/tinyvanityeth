use criterion::{black_box, criterion_group, criterion_main, Criterion};
use tiny_keccak::{Hasher, Keccak};

const ADDRESS_HEX_LENGTH: usize = 40;
const KECCAK256_HASH_BYTES_LENGTH: usize = 32;
const KECCAK256_HASH_HEX_LENGTH: usize = KECCAK256_HASH_BYTES_LENGTH * 2;

fn to_hex(bytes: &[u8], capacity: usize) -> String {
    let mut hex = String::with_capacity(capacity);
    for byte in bytes {
        hex.push(char::from_digit((*byte as u32 >> 4) & 0xf, 16).unwrap());
        hex.push(char::from_digit(*byte as u32 & 0xf, 16).unwrap());
    }
    hex
}

const HEX_CHARS_LOWER: &[u8; 16] = b"0123456789abcdef";
fn to_hex_noalloc<'a>(bytes: &[u8], buf: &'a mut [u8]) -> &'a str {
    for i in 0..bytes.len() {
        buf[i * 2] = HEX_CHARS_LOWER[(bytes[i] >> 4) as usize];
        buf[i * 2 + 1] = HEX_CHARS_LOWER[(bytes[i] & 0xf) as usize];
    }

    std::str::from_utf8(buf).expect("Failed to convert byte array to hex string")
}

fn get_checksum_address_zip_noalloc<'a>(
    addr: &str,
    addr_hex_buf: &'a mut [u8; ADDRESS_HEX_LENGTH],
) -> &'a str {
    let addr_bytes = addr.as_bytes();
    let mut hash = [0u8; KECCAK256_HASH_BYTES_LENGTH];
    let mut hasher = Keccak::v256();
    hasher.update(&addr_bytes);
    hasher.finalize(&mut hash);

    let mut addr_hash_hex_buf = [0u8; KECCAK256_HASH_HEX_LENGTH];
    let addr_hash = to_hex_noalloc(&hash, &mut addr_hash_hex_buf);
    let addr_hash_bytes = addr_hash.as_bytes();

    for i in 0..addr_bytes.len() {
        let byte = addr_bytes[i];
        addr_hex_buf[i] = if addr_hash_bytes[i] >= 56 {
            byte.to_ascii_uppercase()
        } else {
            byte
        }
    }

    std::str::from_utf8(addr_hex_buf).expect("Failed to convert byte array to hex string")
}

fn get_checksum_address_zip(addr: &str) -> String {
    let addr_bytes = addr.as_bytes();
    let mut hash = [0u8; KECCAK256_HASH_BYTES_LENGTH];
    let mut hasher = Keccak::v256();
    hasher.update(&addr_bytes);
    hasher.finalize(&mut hash);

    let addr_hash = to_hex(&hash, KECCAK256_HASH_HEX_LENGTH);

    addr_bytes.iter().zip(addr_hash.as_bytes()).fold(
        String::with_capacity(ADDRESS_HEX_LENGTH),
        |mut checksum_addr, (addr_byte, hash_byte)| {
            checksum_addr.push(if *hash_byte >= 56 {
                addr_byte.to_ascii_uppercase() as char
            } else {
                addr_byte.to_ascii_lowercase() as char
            });
            checksum_addr
        },
    )
}

fn get_checksum_address_char_indices(addr: &str) -> String {
    let mut hash = [0u8; KECCAK256_HASH_BYTES_LENGTH];
    let mut hasher = Keccak::v256();
    hasher.update(&addr.as_bytes());
    hasher.finalize(&mut hash);

    let addr_hash = to_hex(&hash, KECCAK256_HASH_HEX_LENGTH);

    addr.char_indices().fold(
        String::with_capacity(ADDRESS_HEX_LENGTH),
        |mut checksum_addr, (idx, addr_chr)| {
            let n = u16::from_str_radix(&addr_hash[idx..idx + 1], 16).unwrap();

            checksum_addr.push(if n > 7 {
                addr_chr.to_ascii_uppercase()
            } else {
                addr_chr
            });

            checksum_addr
        },
    )
}

fn criterion_benchmark(c: &mut Criterion) {
    let addr = "00000000219ab540356cbb839cbe05303d7705fa";

    c.bench_function("get_checksum_address_zip_noalloc", |b| {
        let mut addr_hex_buf = [0u8; ADDRESS_HEX_LENGTH];
        b.iter(|| {
            let _ = get_checksum_address_zip_noalloc(black_box(addr), &mut addr_hex_buf);
        })
    });
    c.bench_function("get_checksum_address_zip", |b| {
        b.iter(|| get_checksum_address_zip(black_box(addr)))
    });
    c.bench_function("get_checksum_address_char_indices", |b| {
        b.iter(|| get_checksum_address_char_indices(black_box(addr)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
