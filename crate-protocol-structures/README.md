# nagara Network's Protocol Structures Library

A `#![no_std]` & `alloc` shared types library, unless `std` feature is enabled.

## Features

Either:

- `opt-aarch64` which enables [blake3](https://crates.io/crates/blake3)'s feature `blake3/neon`
- `std` which enables `std` feature for all dependencies
- `wasmn32` which enables `blake3/pure`
