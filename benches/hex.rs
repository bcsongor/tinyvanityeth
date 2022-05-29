use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::fmt::Write;

const KECCAK256_HASH_BYTES_LENGTH: usize = 32;
const KECCAK256_HASH_HEX_LENGTH: usize = KECCAK256_HASH_BYTES_LENGTH * 2;
const HEX_CHARS_LOWER: &[u8; 16] = b"0123456789abcdef";

fn hex_noalloc<'a>(bytes: &[u8], buf: &'a mut [u8]) -> &'a str {
    for i in 0..bytes.len() {
        buf[i * 2] = HEX_CHARS_LOWER[(bytes[i] >> 4) as usize];
        buf[i * 2 + 1] = HEX_CHARS_LOWER[(bytes[i] & 0xf) as usize];
    }

    std::str::from_utf8(buf).expect("Failed to convert byte array to hex string")
}

fn hex_optimised(bytes: &[u8], capacity: usize) -> String {
    let mut hex = String::with_capacity(capacity);
    for byte in bytes {
        hex.push(char::from_digit((*byte as u32 >> 4) & 0xf, 16).unwrap());
        hex.push(char::from_digit(*byte as u32 & 0xf, 16).unwrap());
    }
    hex
}

fn hex_naive(bytes: &[u8], capacity: usize) -> String {
    let mut hex = String::with_capacity(capacity);
    for byte in bytes {
        write!(&mut hex, "{:02x}", byte).expect("Failed to format byte");
    }
    hex
}

fn criterion_benchmark(c: &mut Criterion) {
    let bytes = &[
        42u8, 17, 54, 151, 185, 7, 94, 96, 232, 181, 157, 78, 186, 48, 147, 40, 49, 74, 83, 244,
        101, 148, 214, 97, 15, 153, 68, 22, 31, 14, 9, 106,
    ];

    c.bench_function("hex_noalloc", |b| {
        let mut hex = [0u8; KECCAK256_HASH_HEX_LENGTH];
        b.iter(|| {
            hex_noalloc(black_box(bytes), &mut hex);
        })
    });
    c.bench_function("hex_optimised", |b| {
        b.iter(|| hex_optimised(black_box(bytes), KECCAK256_HASH_HEX_LENGTH))
    });
    c.bench_function("hex_naive", |b| {
        b.iter(|| hex_naive(black_box(bytes), KECCAK256_HASH_HEX_LENGTH))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
