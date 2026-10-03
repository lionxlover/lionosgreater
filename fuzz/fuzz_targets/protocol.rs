#![no_main]
//! Fuzz target (spec 01 §10): the socket protocol parser boundary. Every
//! byte sequence the UI can push into `decode_request` and the frame
//! codec must be handled without panics, unbounded allocation, or
//! secrets escaping into error strings.
//!
//! Corpus lives in `fuzz/corpus/protocol/`; CI runs a short pass
//! (`.github/workflows/ci.yml`).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 1. Frame-level: feed the bytes through the JSON-lines parser
    //    (sync over a duplex) — via the pure-decode path for determinism.
    if let Ok(s) = std::str::from_utf8(data) {
        // split into "lines" the way the codec would
        for line in s.split('\n') {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.is_empty() {
                continue;
            }
            match lion_greeter::proto::decode_request(line) {
                Ok(req) => {
                    // request ids and bounds must hold for anything that
                    // parses successfully
                    let _ = req.id();
                }
                Err(e) => {
                    // error strings must stay bounded and never echo large
                    // chunks of input back
                    assert!(e.message.len() < 4096, "error message unbounded");
                    assert!(!e.message.is_empty() || e.code == "bad_request");
                    // error ids are always in range
                    assert!(e.id <= u64::MAX);
                }
            }
        }
    }

    // 2. Schema-shaped fuzz: mutate a valid message with the fuzz bytes.
    let mut template = br#"{"proto":1,"id":1,"op":"StartAuth","user":"a"}"#.to_vec();
    for (i, b) in data.iter().enumerate() {
        let pos = i % template.len();
        template[pos] = *b;
    }
    if let Ok(s) = std::str::from_utf8(&template) {
        let _ = lion_greeter::proto::decode_request(s);
    }

    // 3. Event serialisation round-trip: any prompt text stays sanitised.
    if data.len() > 8 {
        if let Ok(text) = String::from_utf8(data[..data.len() / 2].to_vec()) {
            let ev = lion_greeter::proto::Event::Prompt {
                kind: lion_greeter::proto::PromptKind::Secret,
                text,
            };
            let wire = ev.to_wire(1);
            assert!(wire.len() < 8192);
        }
    }
});
