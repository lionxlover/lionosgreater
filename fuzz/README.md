# Fuzzing lion-greeter

Two layers, same invariants:

1. **Deterministic harness (always on, zero setup)** —
   `tests/fuzz_harness.rs` runs in `cargo test` and in CI on every
   push. A fixed-seed xorshift engine mutates a corpus of ~26 seed
   shapes through 6 damage classes (byte flip, truncate, insert,
   duplicate, delete, structural replace) — ~5,000 mutated inputs per
   run, every one asserted to parse without panicking and to yield
   only valid-on-acceptance results.

2. **libFuzzer target (corpus-growing, needs network once)** —
   `fuzz/fuzz_targets/parse_config.rs`. Install cargo-fuzz, then:

       cargo +stable install cargo-fuzz
       cargo fuzz run parse_config fuzz/corpus/parse_config -s none

   Interesting inputs land in `fuzz/artifacts/` and get promoted into
   `fuzz/corpus/parse_config/` as regression seeds.

## Invariants (shared by both layers)

* No panic on any byte sequence (the parsers are total functions).
* `config::parse` either rejects the *whole* file (`Err(line)`) or
  returns a `Config` with individually valid fields: plausible
  username (<=31 chars, POSIX charset), bounded delay_ms, plausible
  session id. Half-applied files are a design impossibility, and the
  fuzzers check it stays that way.
* Session `.desktop` parsing never yields an entry whose id violates
  `sessions::is_plausible_id`.
* Verdicts are deterministic: same input, same result, twice.

## Coverage of the two parsers vs the rest

The FFI layer (pam_ffi.rs) is deliberately not fuzzed here: its input
comes from libpam (a C library with its own constraints) and from the
bus policy, not from files. Its discipline (panic-to-EINVAL, unknown
style refusal) is enforced by unit tests + the live D-Bus suite
instead.
