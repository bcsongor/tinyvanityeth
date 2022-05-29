# tinyvanityeth ✨ [![Build](https://github.com/bcsongor/tinyvanityeth/actions/workflows/build.yml/badge.svg)](https://github.com/bcsongor/tinyvanityeth/actions/workflows/build.yml)

Tiny and _fast_ command line tool to find vanity Ethereum addresses that match a given prefix.

<p align="center">
    <img src="https://user-images.githubusercontent.com/8850110/170898547-1f5e7e6d-2a7e-43cf-94a9-4d7c66ce6fe7.png" alt="tinyvanityeth screenshot" />
</p>


## 📦 Install

### Prerequisites

- Rust (1.60+)
- Cargo

On macOS, use Homebrew to install Rust & Cargo via `brew install rustup`.

For other platforms, please see the [official installation guide](https://doc.rust-lang.org/cargo/getting-started/installation.html). 

### Installing _tinyvanityeth_

After Cargo and Rust is installed, run the command below which installs the latest version of _tinyvanityeth_.

```shell
cargo install --git https://github.com/bcsongor/tinyvanityeth
```

## 💪 Usage

```
Usage: tinyvanityeth [options]

Options:
    -c, --case-sensitive    enables case-sensitive search
    -p, --prefix PREFIX     address prefix to search for
    -t, --threads COUNT     number of threads to use (default num_cpus)
    -i, --interval SECONDS  statistics print interval (default 10)
```

### Examples

#### Find an address that start with `5eaf00d`
```bash
tinyvanityeth -p 5eaf00d
```

#### Find a checksum address that starts with `5EAF00D`, print statistics every minute.
```bash
tinyvanityeth -c -p 5EAF00D -s 60
```

## 🚀 Performance

_tinyvanityeth_ achieves optimal speed by avoiding expensive heap allocations in the critical path and by using
high-performance libraries for EC key generation and hashing,
like [secp256k1](https://github.com/rust-bitcoin/rust-secp256k1/) and
[tiny_keccak](https://github.com/debris/tiny-keccak).

### Benchmarks

Case-insensitive search for an address with the prefix `5eaf00d`. 🍣

**Apple M1 Max** (`stable-aarch64-apple-darwin - rustc 1.61.0`)

| Platform                                |             Speed |
|:----------------------------------------|------------------:|
| tinyvanityeth                           | ~488,247 addr/sec |
| [vanity-eth.tk](https://vanity-eth.tk/) |  ~19,047 addr/sec |

**Intel Xeon E5-1620v2** (`stable-x86_64-pc-windows-msvc - rustc 1.61.0`)

| Platform                                |            Speed |
|:----------------------------------------|-----------------:|
| tinyvanityeth                           | ~77,084 addr/sec |
| [vanity-eth.tk](https://vanity-eth.tk/) |  ~4,889 addr/sec |

## 🧑‍💻 Development

### Build

Please note, _release_ builds contain optimisations which can positively affect performance. 
It is not recommended to use _debug_ builds for searching addresses.

```shell
# Debug
cargo build

# Release
cargo build --release
```

### Run unit tests

```shell 
cargo test
```
