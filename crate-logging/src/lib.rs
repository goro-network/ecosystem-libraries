#![forbid(unsafe_code)]
#![deny(warnings)]

#[cfg(all(feature = "default", feature = "wasm32"))]
compile_error!("Feature \"default\" can't be combined with \"wasm32\".");

pub use log::{debug, error, info, warn};

const ENVKEY_RUST_LOG: &str = "RUST_LOG";

pub fn init() {
    if std::env::var(ENVKEY_RUST_LOG).is_err() {
        #[cfg(debug_assertions)]
        std::env::set_var(ENVKEY_RUST_LOG, "debug");
        #[cfg(not(debug_assertions))]
        std::env::set_var(ENVKEY_RUST_LOG, "info");
    }

    #[cfg(feature = "default")]
    env_logger::builder()
        .default_format()
        .format_timestamp_micros()
        .format_indent(Some(2))
        .parse_env(ENVKEY_RUST_LOG)
        .init();
    #[cfg(feature = "wasm32")]
    console_log::init().unwrap();
}
