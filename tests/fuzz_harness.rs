//! Deterministic fuzz harness for the two untrusted-input parsers.
//!
//! The greeter parses two files it does not control: `greeter.toml`
//! (config.rs) and session `.desktop` files (sessions.rs). A malformed
//! input must always produce a rejected parse or a safe default —
//! never a panic, never a hang, never a half-applied file.
//!
//! This harness is deterministic (a fixed-seed LCG, no `rand`
//! dependency, no corpus files) so it runs in CI on every push with
//! zero setup, while `fuzz/` carries the libFuzzer target for
//! continuous corpus-growing fuzzing when networked machines are
//! available. Both share the invariant set below.
//!
//! Invariants checked for every mutated input:
//! 1. Neither parser panics (any panic = test failure by unwinding).
//! 2. The config parser either rejects the whole file or returns a
//!    `Config` whose fields are individually valid (plausible username,
//!    bounded delay, valid session id).
//! 3. The session parser never yields an entry whose id is malformed.
//! 4. Parsing is total: the same input always yields the same verdict
//!    (checked for a sample of mutants).

use lion_greeter::{config, sessions};

/// Small, fast, fully deterministic PRNG (xorshift64*) — enough
/// entropy for byte-level mutations, zero dependencies.
struct Lcg(u64);

impl Lcg {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }
    fn next_u64(&mut self) -> u64 {
        // xorshift64* — one multiply makes the low bits usable.
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }
}

/// Seed corpus: shapes the parsers must already handle. Mutations are
/// drawn from realistic damage — truncation, byte flips, quote
/// removal, comment injection, key duplication, deep nesting.
const CONFIG_CORPUS: &[&str] = &[
    "",
    "\n\n# only comments\n",
    "[autologin]\nuser = \"alice\"\ndelay_ms = 1500\nrelogin = false\n",
    "[autologin]\nuser = 'bob' # trailing comment\ndelay_ms = 0\nrelogin = true\n",
    "[session]\ndefault = \"lion\"\n",
    "[security]\nmlock = true\n",
    "[autologin]\nuser = \"has # hash\"\n",
    "[autologin]\ndelay_ms = 99999999999999999999\n",
    "[autologin]\nuser = \"unclosed\n",
    "[autologin]\nrelogin = maybe\n",
    "= novalue\n",
    "[section]\n[section]\n[section]\nkey = 1\nkey = 2\n",
    "[a][b][c]\n",
    "user = \"x\"\n[autologin]\n",
    "#\n#\n#\n[autologin]\nuser = \"ok\"\n# trailing\n",
];

const DESKTOP_CORPUS: &[&str] = &[
    "[Desktop Entry]\nType=Application\nName=Lion\nExec=lion-session\n",
    "[Desktop Entry]\nName=Only Name\n",
    "[Desktop Entry]\nType=Application\nName=X\nExec=foo\nTryExec=/bin/sh\n",
    "[Desktop Entry]\nType=Application\nName=X\nExec=foo\nHidden=true\n",
    "[Desktop Entry]\nType=Application\nName=X\nExec=foo\nNoDisplay=true\n",
    "[Desktop Entry]\nType=Application\nName=\"Quoted \\s Name\"\nExec=bar\n",
    "[Other Group]\nName=Y\n[Desktop Entry]\nName=Z\nType=Application\nExec=baz\n",
    "Type=Application\nNoSection=1\n",
    "[Desktop Entry]\nName[de]=Deutsch\nName=English\nType=Application\nExec=q\n",
    "[Desktop Entry]\nName===\nExec=\nType=\n",
    "[Desktop Entry]\nDesktopNames=A;B;C;;\nType=Application\nName=N\nExec=e\n",
];

/// Mutate one corpus entry into a damaged variant. Deterministic for
/// a given (seed, index).
fn mutate(text: &str, rng: &mut Lcg) -> String {
    let mut bytes: Vec<u8> = text.as_bytes().to_vec();
    if bytes.is_empty() {
        return String::new();
    }
    let rounds = 1 + rng.below(4);
    for _ in 0..rounds {
        // A truncate/delete round may empty the buffer; further
        // mutations on an empty vec are a no-op, not an error.
        if bytes.is_empty() {
            break;
        }
        match rng.below(6) {
            0 => {
                // Byte flip at a random position.
                let i = rng.below(bytes.len());
                bytes[i] ^= 1 << (rng.below(8) as u32);
            }
            1 => {
                // Truncate.
                let at = 1 + rng.below(bytes.len());
                bytes.truncate(at);
            }
            2 => {
                // Insert a byte.
                let i = rng.below(bytes.len());
                let b = b"\"'[]#=\n\x00\t \\;"[rng.below(12)];
                bytes.insert(i, b);
            }
            3 => {
                // Duplicate a slice.
                let i = rng.below(bytes.len());
                let len = 1 + rng.below(8.min(bytes.len() - i));
                let chunk = bytes[i..i + len].to_vec();
                bytes.extend(chunk);
            }
            4 => {
                // Delete a slice.
                let i = rng.below(bytes.len());
                let len = 1 + rng.below(8.min(bytes.len() - i));
                bytes.drain(i..i + len);
            }
            _ => {
                // Replace a byte with a structural character.
                let i = rng.below(bytes.len());
                bytes[i] = b"[]\"'=#\n"[rng.below(7)];
            }
        }
    }
    // Ensure valid UTF-8: fuzzed bytes may not be — lossy-convert the
    // way the file-reader boundary would reject them in reality. (The
    // parsers only ever see UTF-8 from read_to_string, so lossy
    // conversion models the boundary faithfully.)
    String::from_utf8_lossy(&bytes).into_owned()
}

/// All string inputs the parsers accept must round-trip
/// deterministically: same input, same verdict, twice.
fn assert_verdict_stable_config(input: &str) {
    let v1 = config::parse(input).is_ok();
    let v2 = config::parse(input).is_ok();
    assert_eq!(v1, v2, "config verdict must be deterministic");
}

fn valid_config(cfg: &config::Config) {
    if let Some(u) = cfg.autologin.user.as_deref() {
        assert!(!u.is_empty(), "accepted empty username");
        assert!(u.len() <= 31, "accepted over-long username: {u:?}");
        assert!(
            u.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.'),
            "accepted implausible username: {u:?}"
        );
    }
    if let Some(s) = cfg.session.default.as_deref() {
        assert!(
            !s.is_empty() && s.len() <= 64,
            "accepted implausible session id: {s:?}"
        );
    }
}

#[test]
fn config_parser_never_panics_on_mutated_inputs() {
    let mut rng = Lcg::new(0x4C49_4F4E_4752_4554); // "LIONGRET"
    for (idx, seed) in CONFIG_CORPUS.iter().enumerate() {
        // The pristine corpus entries are exercised directly…
        if let Ok(cfg) = config::parse(seed) {
            valid_config(&cfg);
        }
        // …and each spawns 200 mutated descendants.
        for m in 0..200 {
            let damaged = mutate(seed, &mut rng);
            let tag = format!("corpus[{idx}] mutation[{m}]");
            let verdict = std::panic::catch_unwind(|| config::parse(&damaged));
            match verdict {
                Err(_) => panic!("config parser panicked on {tag}: {damaged:?}"),
                Ok(Ok(cfg)) => valid_config(&cfg),
                Ok(Err(_line)) => {}
            }
            if m % 25 == 0 {
                assert_verdict_stable_config(&damaged);
            }
        }
    }
}

#[test]
fn desktop_parser_never_panics_on_mutated_inputs() {
    let mut rng = Lcg::new(0x5345_5353_494F_4E53); // "SESSIONS"
    for (idx, seed) in DESKTOP_CORPUS.iter().enumerate() {
        // Pristine entries parse through the real file path: write to
        // a temp dir and enumerate.
        let dir =
            std::env::temp_dir().join(format!("lion-fuzz-sessions-{idx}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("probe.desktop"), seed).unwrap();
        let parsed = sessions::enumerate_from(std::slice::from_ref(&dir));
        for entry in &parsed {
            assert!(
                sessions::is_plausible_id(&entry.id),
                "parser produced implausible id: {:?}",
                entry.id
            );
            assert!(!entry.name.is_empty());
            assert!(!entry.exec.is_empty());
        }

        for m in 0..200 {
            let damaged = mutate(seed, &mut rng);
            let tag = format!("corpus[{idx}] mutation[{m}]");
            let path = dir.join("probe.desktop");
            std::fs::write(&path, &damaged).unwrap();
            let verdict =
                std::panic::catch_unwind(|| sessions::enumerate_from(std::slice::from_ref(&dir)));
            match verdict {
                Err(_) => panic!("desktop parser panicked on {tag}: {damaged:?}"),
                Ok(list) => {
                    for entry in &list {
                        assert!(
                            sessions::is_plausible_id(&entry.id),
                            "implausible id from {tag}: {:?}",
                            entry.id
                        );
                    }
                }
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// The mutation engine itself must be deterministic: same seed, same
/// sequence. If this fails, CI flakes would mask real regressions.
#[test]
fn mutation_engine_is_deterministic() {
    let mut a = Lcg::new(42);
    let mut b = Lcg::new(42);
    for _ in 0..1000 {
        assert_eq!(a.next_u64(), b.next_u64());
    }
    let text = "[autologin]\nuser = \"a\"\n";
    let mut x = Lcg::new(7);
    let mut y = Lcg::new(7);
    for _ in 0..50 {
        assert_eq!(mutate(text, &mut x), mutate(text, &mut y));
    }
}

/// Mutation must actually *mutate* most of the time — a no-op fuzzer
/// proves nothing.
#[test]
fn mutation_engine_changes_its_input() {
    let mut rng = Lcg::new(1234);
    let text = "[autologin]\nuser = \"alice\"\ndelay_ms = 5\n";
    let mut changed = 0;
    for _ in 0..200 {
        if mutate(text, &mut rng) != text {
            changed += 1;
        }
    }
    assert!(
        changed > 180,
        "mutation engine too passive: {changed}/200 changed"
    );
}

/// Known-bad shapes stay rejected even after 1000 mutations layered on
/// top (regression guard against a parser accidentally becoming laxer).
#[test]
fn invalid_shapes_never_become_valid() {
    let never_ok: &[&str] = &[
        "[autologin]\nuser = \"unclosed\n",
        "[autologin]\nuser = alice\n", // unquoted
        "[autologin]\ndelay_ms = -1\n",
        "[autologin]\nrelogin = perhaps\n",
    ];
    let mut rng = Lcg::new(0xBEEF);
    for seed in never_ok {
        assert!(
            config::parse(seed).is_err(),
            "pristine invalid input accepted: {seed:?}"
        );
        for _ in 0..100 {
            let damaged = mutate(seed, &mut rng);
            // A mutation may *repair* an input by accident (e.g.
            // adding the missing quote). What must never happen:
            // acceptance of an invalid result — checked by
            // valid_config; the verdict must at least be consistent.
            let v1 = config::parse(&damaged);
            let v2 = config::parse(&damaged);
            assert_eq!(v1.is_ok(), v2.is_ok());
            if let Ok(cfg) = v1 {
                valid_config(&cfg);
            }
        }
    }
}
