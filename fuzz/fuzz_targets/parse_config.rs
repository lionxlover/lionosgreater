//! libFuzzer target for the config parser (the TOML subset in
//! `config.rs`).
//!
//! Run with network access + cargo-fuzz installed:
//!
//! ```sh
//! cargo +stable install cargo-fuzz
//! cargo fuzz run parse_config          # fresh run
//! cargo fuzz run parse_config fuzz/corpus/parse_config  # with corpus
//! ```
//!
//! Offline environments (including the deterministic CI harness in
//! `tests/fuzz_harness.rs`) get the same invariant set with a fixed
//! seed: no panic, whole-file reject on syntax errors, individually
//! valid fields on acceptance. This target exists so the corpus can
//! *grow* on fuzzing infrastructure that has the libFuzzer runtime.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Model the read_to_string boundary: invalid UTF-8 becomes lossy
    // text exactly like the file reader would produce.
    let text = String::from_utf8_lossy(data);
    if let Ok(cfg) = lion_greeter::config::parse(&text) {
        // Accepted configs must carry only plausible field values.
        if let Some(u) = cfg.autologin.user.as_deref() {
            assert!(u.len() <= 31);
            assert!(u
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.'));
        }
        if let Some(s) = cfg.session.default.as_deref() {
            assert!(s.len() <= 64);
        }
    }
    // A rejected parse (Err) is the other fully-correct outcome.
});
