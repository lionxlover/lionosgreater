#!/usr/bin/env python3
"""Bench regression gate (spec 01 §7): fail if any budget regresses > 10%.

Consumes the JSON-lines output of `cargo bench -- --json` (see
benches/lion_bench.rs) and compares against the reference budgets:

  startup_us      50000   (daemon ready < 50 ms, reference machine)
  auth_us         20000   (PAM round trip adds < 20 ms over PAM's own time)
  rss_kb           8192   (idle RSS < 8 MB)

The low-end reference machine is allowed 2x the budget (spec §7).
"""

import json
import sys

BUDGETS = {
    "startup_us": 50_000,
    "auth_roundtrip_us": 20_000,
    "idle_rss_kb": 8_192,
}
TOLERANCE = 1.10  # 10% regression budget


def main(path: str) -> int:
    results = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line.startswith("{"):
                continue
            data = json.loads(line)
            if data.get("bench") == "lion-greeter":
                for key in BUDGETS:
                    if key in data:
                        results[key] = data[key]
    if not results:
        print("FAIL: no bench results found in", path)
        return 1

    failed = False
    for key, budget in BUDGETS.items():
        got = results.get(key)
        if got is None:
            print(f"WARN: {key} missing from results")
            continue
        limit = int(budget * TOLERANCE)
        status = "OK " if got <= limit else "FAIL"
        if got > limit:
            failed = True
        print(f"{status} {key:20s} {got:>10} (budget {budget}, limit {limit})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "bench.json"))
