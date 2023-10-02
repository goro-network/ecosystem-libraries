#![no_std]
#![forbid(unsafe_code)]
#![allow(clippy::large_enum_variant)]
//#![deny(warnings)]

pub mod errors;
pub mod mnemonic;
pub mod private;
pub mod public;

pub type Result<T> = core::result::Result<T, errors::Error>;

pub const LEN_SHARED_KEY: usize = 64;
pub const LEN_SIGNATURE: usize = 64;
pub const SIGNING_CONTEXT_SR25519: &[u8] = b"substrate";
