use rand::{RngCore};
use rand_core::OsRng;

pub fn generate(format: &str) -> String {
    let (len_str, cfg_str) = format.split_once(':').unwrap();

    let len = usize::from_str_radix(len_str, 10).unwrap();

    let mut pool = Vec::<char>::new();

    if cfg_str.contains('l') {
        pool.extend(LOWERCASE_LETTERS_POOL.chars());
    }

    if cfg_str.contains('u') {
        pool.extend(UPPERCASE_LETTERS_POOL.chars());
    }

    if cfg_str.contains('d') {
        pool.extend(DIGITS_POOL.chars());
    }

    if cfg_str.contains('s') {
        pool.extend(SYMBOLS_POOL.chars());
    }

    let mut dest = vec![0u8; len];
    OsRng.fill_bytes(&mut dest);

    let mut result = String::with_capacity(len);

    let mut acc = 0usize;
    for i in 0..len {
        let index = (acc + dest[i] as usize) % pool.len();
        acc += dest[i] as usize - index;

        result.push(pool[index]);
    }

    result
}

const LOWERCASE_LETTERS_POOL: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPERCASE_LETTERS_POOL: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS_POOL: &str = "0123456789";
const SYMBOLS_POOL: &str = "~`!@#$%^&*()_+-=,.<>/?[]{}\\|";