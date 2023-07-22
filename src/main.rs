use getopts::{Matches, Options};
use regex::{Regex, RegexBuilder};
use rust_decimal::{Decimal, MathematicalOps};
use secp256k1::generate_keypair;
use secp256k1::rand::thread_rng;
use std::process::exit;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{env, thread};
use tiny_keccak::{Hasher, Keccak};

/// Stores both the original case and lowercase address part to be matched.
#[derive(Debug, Clone)]
struct AddressPart {
    /// Original case address part.
    part: String,
    /// Lowercase address part.
    part_lower: String,
}

impl From<String> for AddressPart {
    fn from(part: String) -> Self {
        let part_lower = part.to_lowercase();
        Self { part_lower, part }
    }
}

impl From<&str> for AddressPart {
    fn from(part: &str) -> Self {
        let part_lower = part.to_lowercase();
        let part = part.to_owned();
        Self { part_lower, part }
    }
}

/// Search rules to evaluate a generated against.
#[derive(Debug, Clone)]
struct Rules {
    /// Controls if the search is case-sensitive and thus against a checksum address.
    is_case_sensitive: bool,
    /// Address prefix to match.
    prefix: Option<AddressPart>,
    /// Address suffix to match.
    suffix: Option<AddressPart>,
    /// Regular expression to match.
    regexp: Option<Regex>,
}

/// Application configuration.
#[derive(Debug, Clone)]
struct Configuration {
    /// Number of seconds between displaying statistics.
    stats_interval_sec: u64,
    /// Number of threads to use for address generation and matching.
    thread_count: usize,
    /// Address search rules.
    rules: Rules,
}

impl TryFrom<Matches> for Configuration {
    type Error = &'static str;

    fn try_from(matches: Matches) -> Result<Self, Self::Error> {
        if (!matches.opt_present("p") && !matches.opt_present("s")) && !matches.opt_present("r") {
            return Err("prefix and/or suffix or a regexp must be present");
        }

        if (matches.opt_defined("p") || matches.opt_present("s")) && matches.opt_present("r") {
            return Err("suffix or prefix and regexp rules are mutually exclusive");
        }

        let prefix = matches.opt_str("p").map(AddressPart::from);
        if !prefix
            .as_ref()
            .map_or(true, |p| is_lower_hex(&p.part_lower))
        {
            return Err("prefix must be hexadecimal string");
        }

        let suffix = matches.opt_str("s").map(AddressPart::from);
        if !suffix
            .as_ref()
            .map_or(true, |s| is_lower_hex(&s.part_lower))
        {
            return Err("suffix must be hexadecimal string");
        }

        let is_case_sensitive = matches.opt_present("c");

        let regexp = matches.opt_str("r").as_ref().map(|rs| {
            RegexBuilder::new(rs)
                .case_insensitive(!is_case_sensitive)
                .build()
                .expect("regexp must be a valid regular expression")
        });

        let thread_count: usize = matches
            .opt_get("t")
            .map_err(|_| "failed to parse thread count")?
            .unwrap_or_else(|| num_cpus::get());

        let stats_interval_sec = matches
            .opt_get("i")
            .map_err(|_| "failed to parse interval")?
            .unwrap_or(10u64);

        Ok(Self {
            stats_interval_sec,
            thread_count,
            rules: Rules {
                is_case_sensitive,
                prefix,
                suffix,
                regexp,
            },
        })
    }
}

const ADDRESS_HEX_LENGTH: usize = 40;
const ADDRESS_BYTES_LENGTH: usize = ADDRESS_HEX_LENGTH / 2;
const KECCAK256_HASH_BYTES_LENGTH: usize = 32;
const KECCAK256_HASH_HEX_LENGTH: usize = KECCAK256_HASH_BYTES_LENGTH * 2;

const PUBLIC_KEY_BYTES_START_INDEX: usize = 1;
const ADDRESS_BYTES_START_INDEX: usize = KECCAK256_HASH_BYTES_LENGTH - ADDRESS_BYTES_LENGTH;

const HEX_CHARS_LOWER: &[u8; 16] = b"0123456789abcdef";

/// Converts the given byte array `bytes` using the `buf` buffer to a hex string.
/// This function performs no allocations on the heap.
fn to_hex<'a>(bytes: &[u8], buf: &'a mut [u8]) -> &'a str {
    if buf.len() < bytes.len() * 2 {
        panic!("to_hex: buffer overflow");
    }

    for i in 0..bytes.len() {
        buf[i * 2] = HEX_CHARS_LOWER[(bytes[i] >> 4) as usize];
        buf[i * 2 + 1] = HEX_CHARS_LOWER[(bytes[i] & 0xf) as usize];
    }

    std::str::from_utf8(&buf[0..bytes.len() * 2])
        .expect("to_hex: failed to convert byte array to hex string")
}

/// Checks if the given string `text` is a lowercase hex string.
fn is_lower_hex(text: &str) -> bool {
    for c in text.as_bytes() {
        if (*c < b'0' || *c > b'9') && (*c < b'a' || *c > b'f') {
            return false;
        }
    }
    true
}

/// Checksums the given un-prefixed Ethereum address.
/// See [EIP-55](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md) for the official algorithm.
/// Requires `addr` to be a hex-encoded, unprefixed, lowercase Ethereum address.
fn to_checksum_address<'a>(addr: &str, checksum_addr_hex_buf: &'a mut [u8]) -> &'a str {
    if addr.len() != ADDRESS_HEX_LENGTH {
        panic!("to_checksum_address: invalid address");
    }

    if checksum_addr_hex_buf.len() < ADDRESS_BYTES_LENGTH {
        panic!("to_checksum_address: buffer overflow");
    }

    let addr_bytes = addr.as_bytes();

    let mut hash = [0u8; KECCAK256_HASH_BYTES_LENGTH];
    let mut hasher = Keccak::v256();
    hasher.update(&addr_bytes);
    hasher.finalize(&mut hash);

    let mut buf = [0u8; KECCAK256_HASH_HEX_LENGTH];
    let addr_hash = to_hex(&hash, &mut buf);
    let addr_hash_bytes = addr_hash.as_bytes();

    for i in 0..addr_bytes.len() {
        let byte = addr_bytes[i];
        checksum_addr_hex_buf[i] = if addr_hash_bytes[i] >= 56 {
            byte.to_ascii_uppercase()
        } else {
            byte // Already lowercase.
        }
    }

    std::str::from_utf8(&checksum_addr_hex_buf[0..addr.len()])
        .expect("to_checksum_address: failed to convert byte array to hex string")
}

/// Calculates the difficulty of finding an address given `rules`.
fn calc_difficulty(rules: &Rules) -> Option<u128> {
    // Ignore difficulty calculation if a regexp rule is present.
    if rules.regexp.is_some() {
        return None;
    }

    const HEX_CHAR_COUNT: u128 = 16u128;

    let prefix = rules.prefix.as_ref().map_or("", |p| &p.part);
    let suffix = rules.suffix.as_ref().map_or("", |s| &s.part);

    let base_difficulty = HEX_CHAR_COUNT.pow((prefix.len() + suffix.len()) as u32);
    // If case sensitive lookup is enabled, take into account the difference between lower
    // and upper case hex letters (e.g. F vs f).
    if rules.is_case_sensitive {
        const UPPER_LOWER_LETTER_COUNT: u128 = 2u128;

        let letter_count = [prefix, suffix]
            .concat()
            .as_bytes()
            .iter()
            .filter(|&c| *c < b'0' || *c > b'9')
            .count();

        Some(base_difficulty * UPPER_LOWER_LETTER_COUNT.pow(letter_count as u32))
    } else {
        Some(base_difficulty)
    }
}

/// Calculates the probability of finding an address by specifying the `difficulty` of finding
/// an address with the given prefix and the total number of addresses `generated` so far.
fn calc_probability(difficulty: u128, generated: u128) -> Decimal {
    Decimal::ONE
        - (Decimal::ONE - Decimal::ONE / Decimal::from(difficulty)).powd(Decimal::from(generated))
}

/// Prints the usage of the program.
fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

/// Checks if an address `addr` matches the `rules`.
fn is_addr_matching(rules: &Rules, addr: &str) -> bool {
    match rules.regexp.as_ref() {
        Some(regexp) => regexp.is_match(addr),
        None => {
            let prefix = rules.prefix.as_ref();
            let suffix = rules.suffix.as_ref();

            prefix.map_or(true, |p| addr.starts_with(&p.part_lower))
                && suffix.map_or(true, |s| addr.ends_with(&s.part_lower))
        }
    }
}

/// Checks if a checksum address `checksum_addr` matches the given `rules`.
fn is_checksum_addr_matching(rules: &Rules, checksum_addr: &str) -> bool {
    match rules.regexp.as_ref() {
        Some(regexp) => regexp.is_match(checksum_addr),
        None => {
            let prefix = rules.prefix.as_ref();
            let suffix = rules.suffix.as_ref();

            prefix.map_or(true, |p| checksum_addr.starts_with(&p.part))
                && suffix.map_or(true, |s| checksum_addr.ends_with(&s.part))
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = &args[0];

    let mut opts = Options::new();
    opts.optflag("c", "case-sensitive", "enables case-sensitive search");
    opts.optopt("p", "prefix", "address prefix to search for", "PREFIX");
    opts.optopt("s", "suffix", "address suffix to search for", "SUFFIX");
    opts.optopt("r", "regexp", "regular expression to search for", "REGEXP");
    opts.optopt("t", "threads", "number of threads to use", "COUNT");
    opts.optopt("i", "interval", "statistics print interval", "SECONDS");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: failed to parse arguments: {}", e.to_string());
            print_usage(program, opts);
            exit(1);
        }
    };

    let cfg = Configuration::try_from(matches).unwrap_or_else(|err| {
        eprintln!("error: {}\n", err);
        print_usage(program, opts);
        exit(2);
    });
    let rules = cfg.rules;

    let found = Arc::new(AtomicBool::new(false));
    let generated = Arc::new(AtomicU64::new(0));

    let mut threads = Vec::with_capacity(cfg.thread_count);

    for _ in 0..cfg.thread_count {
        let rules = rules.clone();
        let found = found.clone();
        let generated = generated.clone();

        threads.push(thread::spawn(move || {
            let mut hash = [0u8; KECCAK256_HASH_BYTES_LENGTH];
            let mut addr_hex_buf = [0u8; ADDRESS_HEX_LENGTH];
            let mut checksum_addr_hex_buf = [0u8; ADDRESS_HEX_LENGTH];

            while !found.load(Ordering::Acquire) {
                let (sk, pk) = generate_keypair(&mut thread_rng());

                // The uncompressed public key is prefixed with a constant 0x04 byte meaning it has
                // both X and Y coordinates. Let's get rid of it!
                let pk_bytes = &pk.serialize_uncompressed()[PUBLIC_KEY_BYTES_START_INDEX..];

                let mut hasher = Keccak::v256();
                hasher.update(&pk_bytes);
                hasher.finalize(&mut hash);

                // Address is the last 20 bytes of the hash of the uncompressed public key.
                let addr_bytes = &hash[ADDRESS_BYTES_START_INDEX..];
                let addr = to_hex(addr_bytes, &mut addr_hex_buf);

                generated.fetch_add(1, Ordering::Relaxed);

                // Match non-checksummed address against rules.
                // If there's a regexp rule & case sensitivity is enabled proceed to
                // match the checksum address instead.
                if (rules.regexp.is_some() && rules.is_case_sensitive)
                    || is_addr_matching(&rules, addr)
                {
                    let checksum_addr = to_checksum_address(&addr, &mut checksum_addr_hex_buf);

                    // Lowercase address matched, if case sensitivity is enabled,
                    // check if rules match the checksum address.
                    if rules.is_case_sensitive && !is_checksum_addr_matching(&rules, checksum_addr)
                    {
                        continue;
                    }

                    found.store(true, Ordering::Release);

                    println!(
                        "========================\n\
                    Private key: {}\n\
                    Address: 0x{}\n\
                    ========================",
                        sk.display_secret(),
                        checksum_addr
                    );
                }
            }
        }));
    }

    thread::spawn(move || {
        let interval = Duration::from_secs(cfg.stats_interval_sec);
        let mut total_generated = 0u128;

        let difficulty = calc_difficulty(&rules);
        let mut last_loop: Option<Instant> = None;

        while !found.load(Ordering::Acquire) {
            let now = Instant::now();
            let delta_ms =
                last_loop.map_or(0u128, |last_loop| now.duration_since(last_loop).as_millis());
            last_loop = Some(now);

            if delta_ms > 0 {
                let curr_generated = generated.swap(0, Ordering::Relaxed);
                let addr_per_sec = (Decimal::from(curr_generated) / Decimal::from(delta_ms)
                    * Decimal::ONE_THOUSAND)
                    .round();
                total_generated += curr_generated as u128;

                // If difficulty is not available (e.g. because of a regexp rule) print basic metrics only.
                match difficulty {
                    Some(difficulty) => {
                        let probability = calc_probability(difficulty, total_generated);
                        let probability_pct = (probability * Decimal::ONE_HUNDRED).round_dp(3);

                        println!(
                            "Status ({} threads)\n  \
                              Difficulty:  {}\n  \
                              Generated:   {} addresses\n  \
                              Speed:       {} addr/s\n  \
                              Probability: {}%",
                            cfg.thread_count,
                            difficulty,
                            total_generated,
                            addr_per_sec,
                            probability_pct
                        );
                    }
                    None => {
                        println!(
                            "Status ({} threads)\n  \
                              Generated:   {} addresses\n  \
                              Speed:       {} addr/s",
                            cfg.thread_count, total_generated, addr_per_sec,
                        );
                    }
                }
            }

            thread::sleep(interval);
        }
    });

    for thread in threads {
        thread.join().unwrap();
    }
}

#[rustfmt::skip]
#[cfg(test)]
mod tests {
    use crate::{
        calc_difficulty, calc_probability, is_addr_matching, is_lower_hex, to_checksum_address,
        to_hex, AddressPart, Rules, ADDRESS_HEX_LENGTH,
    };
    use regex::RegexBuilder;
    use rust_decimal::Decimal;

    fn get_rules(prefix: Option<&str>, suffix: Option<&str>, regexp: Option<&str>, is_case_sensitive: bool) -> Rules {
        Rules {
            prefix: prefix.map(AddressPart::from),
            suffix: suffix.map(AddressPart::from),
            regexp: regexp.map(|rs| RegexBuilder::new(rs)
                .case_insensitive(!is_case_sensitive)
                .build()
                .unwrap()),
            is_case_sensitive,
        }
    }

    #[test]
    fn it_should_hex_bytes() {
        let mut hex_buf = [0u8; ADDRESS_HEX_LENGTH];

        let bytes = &[
            0x00, 0x00, 0x00, 0x00, 0x21, 0x9a, 0xb5, 0x40, 0x35, 0x6c, 0xbb, 0x83, 0x9c, 0xbe,
            0x05, 0x30, 0x3d, 0x77, 0x05, 0xfa,
        ];
        assert_eq!(to_hex(bytes, &mut hex_buf), "00000000219ab540356cbb839cbe05303d7705fa");

        let bytes = &[0x00, 0xff];
        assert_eq!(to_hex(bytes, &mut hex_buf), "00ff");

        let bytes = &[];
        assert_eq!(to_hex(bytes, &mut hex_buf), "");
    }

    #[test]
    #[should_panic(expected = "to_hex: buffer overflow")]
    fn it_should_fail_to_hex_on_buffer_overflow() {
        let mut hex_buf = [0u8; 2];
        let bytes = &[0xff, 0xff];
        to_hex(bytes, &mut hex_buf);
    }

    #[test]
    fn it_should_checksum_address() {
        let addr = "00000000219ab540356cbb839cbe05303d7705fa";
        let mut checksum_addr_buf = [0u8; ADDRESS_HEX_LENGTH];
        assert_eq!(
            to_checksum_address(addr, &mut checksum_addr_buf),
            "00000000219ab540356cBB839Cbe05303d7705Fa"
        );

        let mut checksum_addr_buf = [0u8; ADDRESS_HEX_LENGTH * 2];
        assert_eq!(
            to_checksum_address(addr, &mut checksum_addr_buf),
            "00000000219ab540356cBB839Cbe05303d7705Fa"
        );
    }

    #[test]
    #[should_panic(expected = "to_checksum_address: invalid address")]
    fn it_should_fail_to_checksum_on_invalid_address() {
        let addr = "00";
        let mut checksum_addr_buf = [0u8; ADDRESS_HEX_LENGTH];
        to_checksum_address(addr, &mut checksum_addr_buf);
    }

    #[test]
    #[should_panic(expected = "to_checksum_address: buffer overflow")]
    fn it_should_fail_to_checksum_on_buffer_overflow() {
        let addr = "00000000219ab540356cbb839cbe05303d7705fa";
        let mut checksum_addr_buf = [0u8; 2];
        to_checksum_address(addr, &mut checksum_addr_buf);
    }

    #[test]
    fn it_should_calculate_difficulty() {
        assert_eq!(calc_difficulty(&get_rules(Some(""), None, None, false)), Some(1));
        assert_eq!(calc_difficulty(&get_rules(Some(""), None, None, true)), Some(1));
        assert_eq!(calc_difficulty(&get_rules(Some("0000"), None, None, false)), Some(65_536));
        assert_eq!(calc_difficulty(&get_rules(Some("0000"), None, None, true)), Some(65_536));
        assert_eq!(calc_difficulty(&get_rules(Some("5eaf00d"), None, None, false)), Some(268_435_456));
        assert_eq!(calc_difficulty(&get_rules(Some("5eaf00d"), None, None, true)), Some(4_294_967_296));
        assert_eq!(calc_difficulty(&get_rules(None, Some("5eaf00d"), None, false)), Some(268_435_456));
        assert_eq!(calc_difficulty(&get_rules(None, Some("5eaf00d"), None, true)), Some(4_294_967_296));
        assert_eq!(calc_difficulty(&get_rules(Some("00"), Some("11"), None, false)), Some(65_536));
        assert_eq!(calc_difficulty(&get_rules(Some("00"), Some("11"), None, true)), Some(65_536));
        assert_eq!(calc_difficulty(&get_rules(None, None, Some(""), false)), None);
        assert_eq!(calc_difficulty(&get_rules(None, None, Some("0{7}"), false)), None);
        assert_eq!(calc_difficulty(&get_rules(None, None, Some("0{7}"), true)), None);
    }

    #[test]
    fn it_should_calculate_probability() {
        assert_eq!(
            calc_probability(65_536, 65_536 / 2).round_dp(4),
            Decimal::from_str_exact("0.3935").unwrap()
        );
    }

    #[test]
    fn it_should_is_lower_hex() {
        assert_eq!(is_lower_hex("00ff"), true);
        assert_eq!(is_lower_hex("00"), true);
        assert_eq!(is_lower_hex("00000000219ab540356cbb839cbe05303d7705fa"), true);
        assert_eq!(is_lower_hex(""), true);
        assert_eq!(is_lower_hex("z"), false);
        assert_eq!(is_lower_hex("-1"), false);
        assert_eq!(is_lower_hex("FF"), false);
    }

    #[test]
    fn it_should_match_addr() {
        let rules = get_rules(Some("0000"), None, None, false);
        assert_eq!(is_addr_matching(&rules, "00000000219ab540356cbb839cbe05303d7705fa"), true);
        assert_eq!(is_addr_matching(&rules, "ff000000219ab540356cbb839cbe05303d7705fa"), false);
        assert_eq!(is_addr_matching(&rules, "ff000000219ab540356cbb839cbe05303d770000"), false);

        let rules = get_rules(None, Some("0000"), None, false);
        assert_eq!(is_addr_matching(&rules, "ff000000219ab540356cbb839cbe05303d770000"), true);
        assert_eq!(is_addr_matching(&rules, "ff000000219ab540356cbb839cbe05303d7705fa"), false);
        assert_eq!(is_addr_matching(&rules, "00000000219ab540356cbb839cbe05303d7705fa"), false);

        let rules = get_rules(None, None, Some("^0{4}"), false);
        assert_eq!(is_addr_matching(&rules, "00000000219ab540356cbb839cbe05303d7705fa"), true);
        assert_eq!(is_addr_matching(&rules, "ff000000219ab540356cbb839cbe05303d7705fa"), false);
        assert_eq!(is_addr_matching(&rules, "ff000000219ab540356cbb839cbe05303d770000"), false);

        let rules = get_rules(None, None, Some("0{4}$"), false);
        assert_eq!(is_addr_matching(&rules, "ff000000219ab540356cbb839cbe05303d770000"), true);
        assert_eq!(is_addr_matching(&rules, "ff000000219ab540356cbb839cbe05303d7705fa"), false);
        assert_eq!(is_addr_matching(&rules, "00000000219ab540356cbb839cbe05303d7705fa"), false);

        let rules = get_rules(None, None, Some("^abcd{2}"), false);
        assert_eq!(is_addr_matching(&rules, "abcdd000219ab540356cbb839cbe05303d770000"), true);
        assert_eq!(is_addr_matching(&rules, "ABcDD000219ab540356cbb839cbe05303d770000"), true);
        assert_eq!(is_addr_matching(&rules, "ff000000219ab540356cbb839cbe05303d7705fa"), false);
        assert_eq!(is_addr_matching(&rules, "00000000219ab540356cbb839cbe05303d7705fa"), false);

        let rules = get_rules(None, None, Some("^A{3}"), true);
        assert_eq!(is_addr_matching(&rules, "AAADD000219ab540356cbb839cbe05303d770000"), true);
        assert_eq!(is_addr_matching(&rules, "aaaDD000219ab540356cbb839cbe05303d770000"), false);
    }
}
