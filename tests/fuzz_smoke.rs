#![forbid(unsafe_code)]
//! Fuzz smoke (spec 01 §10): the corpus plus pseudo-random mutations run
//! through the protocol decoder in normal `cargo test`, so the "short
//! fuzz pass" CI gate does not need nightly. The full libFuzzer target
//! lives in `fuzz/fuzz_targets/protocol.rs`.

use lion_greeter::proto::decode_request;

const CORPUS: &[&str] = &[
    "{\"proto\":1,\"id\":1,\"op\":\"ListUsers\"}",
    "{\"proto\":1,\"id\":2,\"op\":\"StartAuth\",\"user\":\"alice\"}",
    "{\"proto\":1,\"id\":3,\"op\":\"AnswerPrompt\",\"text\":\"pw\"}",
    "{\"proto\":1,\"id\":4,\"op\":\"Launch\",\"session\":\"lion\"}",
    "{\"proto\":1,\"id\":5,\"op\":\"Power\",\"action\":\"reboot\"}",
    "{\"proto\":2,\"id\":6,\"op\":\"ListUsers\"}",
    "{\"proto\":1,\"id\":7,\"op\":\"Nope\"}",
    "garbage",
    "",
    "{\"proto\":1,\"id\":8,\"op\":\"AnswerPrompt\",\"text\":\"\"}",
    "{\"proto\":1,\"id\":9,\"op\":\"StartAuth\",\"user\":\"..\\u002f..\"}",
    "{\"proto\":1,\"id\":10,\"op\":\"Power\",\"action\":\"halt\"}",
];

/// xorshift PRNG — deterministic, no external crates.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

#[test]
fn corpus_decodes_without_panic() {
    for case in CORPUS {
        // Any outcome is fine — the requirement is: never panic, never
        // allocate unboundedly, never echo huge input back.
        if let Err(e) = decode_request(case) {
            assert!(e.message.len() < 4096, "error message unbounded");
        }
    }
}

#[test]
fn random_mutations_never_panic() {
    let mut rng = Rng(0x4c49_4f4e_5350_4543); // "LIONSPEC"
    for case in CORPUS {
        let bytes = case.as_bytes();
        for _ in 0..2000 {
            let mut mutated = bytes.to_vec();
            let flips = (rng.next() % 8) as usize + 1;
            for _ in 0..flips {
                if mutated.is_empty() {
                    break;
                }
                let pos = (rng.next() as usize) % mutated.len();
                mutated[pos] = (rng.next() % 256) as u8;
            }
            // insert random length extension (bounds check)
            if rng.next() % 4 == 0 {
                mutated.resize(mutated.len() + 512, b'x');
            }
            if let Ok(s) = String::from_utf8(mutated) {
                if let Err(e) = decode_request(&s) {
                    assert!(e.message.len() < 4096);
                }
            }
        }
    }
}

#[test]
fn pure_random_bytes_never_panic() {
    let mut rng = Rng(42);
    let mut buf = vec![0u8; 512];
    for _ in 0..5000 {
        for b in buf.iter_mut() {
            *b = (rng.next() % 256) as u8;
        }
        if let Ok(s) = std::str::from_utf8(&buf) {
            let _ = decode_request(s);
        }
        // Also feed the frame level: every byte must survive the codec's
        // UTF-8 validation path without panic.
        let _ = decode_request(&String::from_utf8_lossy(&buf));
    }
}
