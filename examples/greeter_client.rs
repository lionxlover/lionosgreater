//! `greeter_client` — a minimal reference client for the lion-greeter
//! JSON-lines protocol (proto 1). Exercises every request so the daemon
//! can be driven by hand:
//!
//! ```text
//! greeter_client list      [SOCKET]
//! greeter_client sessions  [SOCKET]
//! greeter_client auth USER [SOCKET]        # password read from stdin
//! greeter_client launch SESSION [SOCKET]   # after a successful auth
//! greeter_client power ACTION [SOCKET]     # reboot|poweroff|suspend
//! greeter_client demo [SOCKET]             # full scripted flow
//! ```
//!
//! Not a UI: it prints every event/response as it arrives.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

const DEFAULT_SOCKET: &str = "/run/lion-greeter/ui.sock";

struct Client {
    tx: UnixStream,
    rx: BufReader<UnixStream>,
    next_id: u64,
}

impl Client {
    fn connect(path: &str) -> std::io::Result<Client> {
        let stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(Duration::from_secs(60)))?;
        let rx = BufReader::new(stream.try_clone()?);
        Ok(Client {
            tx: stream,
            rx,
            next_id: 0,
        })
    }

    fn send(&mut self, op: &str, extra: Value) -> u64 {
        self.next_id += 1;
        let mut msg = json!({ "proto": 1, "id": self.next_id, "op": op });
        if let (Some(dst), Some(src)) = (msg.as_object_mut(), extra.as_object()) {
            for (k, v) in src {
                dst.insert(k.clone(), v.clone());
            }
        }
        let line = msg.to_string();
        self.tx.write_all(line.as_bytes()).unwrap();
        self.tx.write_all(b"\n").unwrap();
        self.tx.flush().unwrap();
        self.next_id
    }

    /// Read one line, pretty-print it, return the parsed value.
    fn recv(&mut self) -> Option<Value> {
        let mut line = String::new();
        match self.rx.read_line(&mut line) {
            Ok(0) => {
                println!("— daemon closed the connection —");
                return None;
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!("read error: {e}");
                return None;
            }
        }
        let v: Value = serde_json::from_str(line.trim()).ok()?;
        println!("← {}", serde_json::to_string_pretty(&v).unwrap());
        Some(v)
    }

    /// Read frames until the response for `id` arrives; returns it.
    /// Prompts are answered from stdin (secrets hidden by the terminal if
    /// run interactively with `stty -echo`; this is a test client).
    fn roundtrip(&mut self, id: u64, answer_prompts: bool) -> Option<Value> {
        loop {
            let v = self.recv()?;
            if v.get("event").and_then(Value::as_str) == Some("Prompt")
                && answer_prompts
                && v.get("kind").and_then(Value::as_str) != Some("info")
                && v.get("kind").and_then(Value::as_str) != Some("error")
            {
                let text = v.get("text").and_then(Value::as_str).unwrap_or("");
                let secret = v.get("kind").and_then(Value::as_str) == Some("secret");
                if secret {
                    eprint!("{text}");
                    std::io::stderr().flush().unwrap();
                } else {
                    print!("{text}");
                    std::io::stdout().flush().unwrap();
                }
                let mut answer = String::new();
                if std::io::stdin().read_line(&mut answer).unwrap() == 0 {
                    eprintln!("(stdin closed — cancelling)");
                    let _ = self.send("CancelAuth", json!({}));
                    continue;
                }
                let answer = answer.trim_end_matches(['\n', '\r']);
                self.send("AnswerPrompt", json!({ "text": answer }));
                continue;
            }
            if v.get("id").and_then(Value::as_u64) == Some(id) && v.get("ok").is_some() {
                return Some(v);
            }
            // events (Prompt/Throttle/AuthResult) keep flowing; loop on
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");
    let rest: Vec<&String> = args.iter().skip(1).collect();
    let socket = rest
        .iter()
        .find(|a| a.starts_with('/') || a.contains('/'))
        .map(|s| s.as_str())
        .unwrap_or(DEFAULT_SOCKET);

    match cmd {
        "list" => {
            let mut c = Client::connect(socket).unwrap_or_else(|e| die(socket, e));
            let id = c.send("ListUsers", json!({}));
            c.roundtrip(id, false);
        }
        "sessions" => {
            let mut c = Client::connect(socket).unwrap_or_else(|e| die(socket, e));
            let id = c.send("ListSessions", json!({}));
            c.roundtrip(id, false);
        }
        "auth" => {
            let user = rest
                .iter()
                .find(|a| !a.contains('/'))
                .map(|s| s.as_str())
                .unwrap_or_else(|| usage());
            let mut c = Client::connect(socket).unwrap_or_else(|e| die(socket, e));
            let id = c.send("StartAuth", json!({ "user": user }));
            c.roundtrip(id, true);
        }
        "launch" => {
            let session = rest
                .iter()
                .find(|a| !a.contains('/'))
                .map(|s| s.as_str())
                .unwrap_or("lion");
            let mut c = Client::connect(socket).unwrap_or_else(|e| die(socket, e));
            let id = c.send("Launch", json!({ "session": session }));
            c.roundtrip(id, false);
        }
        "power" => {
            let action = rest
                .iter()
                .find(|a| !a.contains('/'))
                .map(|s| s.as_str())
                .unwrap_or_else(|| usage());
            let mut c = Client::connect(socket).unwrap_or_else(|e| die(socket, e));
            let id = c.send("Power", json!({ "action": action }));
            c.roundtrip(id, false);
        }
        "demo" => {
            let mut c = Client::connect(socket).unwrap_or_else(|e| die(socket, e));
            println!("== ListUsers ==");
            let id = c.send("ListUsers", json!({}));
            c.roundtrip(id, false);
            println!("== ListSessions ==");
            let id = c.send("ListSessions", json!({}));
            c.roundtrip(id, false);
            println!("== StartAuth (answers from stdin) ==");
            let id = c.send("StartAuth", json!({ "user": "alice" }));
            let _ = c.roundtrip(id, true);
            println!("== CancelAuth ==");
            let id = c.send("CancelAuth", json!({}));
            c.roundtrip(id, false);
        }
        _ => usage(),
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: greeter_client <list|sessions|auth USER|launch SESSION|power ACTION|demo> [SOCKET]\n\
         default socket: {DEFAULT_SOCKET}"
    );
    std::process::exit(2);
}

fn die(socket: &str, e: std::io::Error) -> ! {
    eprintln!("cannot connect to {socket}: {e}");
    std::process::exit(1);
}
