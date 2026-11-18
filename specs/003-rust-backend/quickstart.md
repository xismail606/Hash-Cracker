# Quickstart: Rust Backend (Phase 11) — end-to-end validation

Prerequisites: Python 3.11+ already set up for the existing backend; for the Rust path, the setup script provisions the toolchain. Run everything from the repo root. No git commands anywhere.

## 1. Install each path

```bash
./setup.sh --backend python    # existing behavior, unchanged
./setup.sh --backend rust      # provisions toolchain if missing, builds rust/, installs hashcrack-rs
./setup.sh --backend both      # both coexist
```

Expected: exit 0; after `rust`, `rust/target/release/hashcrack-rs(.exe)` exists and `hashcrack-rs --version` prints; after `both`, both CLIs run from the same shell.

## 2. Rust engine parity via CLI

```bash
hashcrack-rs identify 8743b52063cd84097a65d1633f5c74f5   # → md5, ntlm, md4, lm (ambiguous)
printf 'hashcat\nmonkey\ndragon\n' > /tmp/wl.txt
hashcrack-rs audit --mode dictionary --algorithm md5 \
  --hash 8743b52063cd84097a65d1633f5c74f5 --wordlist /tmp/wl.txt --yes
```

Expected: `Status    : MATCH`, `Attempts  : 1`-consistent accounting, `Plaintext : hashcat`. Repeat the audit with the Python CLI (`hashcrack`) — identical sections and values.

## 3. Server backend switch

```bash
./serve.sh --backend rust        # no prompt; binds 127.0.0.1:8765
./serve.sh --backend python      # same dashboard, Flask
./serve.sh 9000 --backend rust   # combined port + backend
```

Expected: open [http://127.0.0.1:8765](http://127.0.0.1:8765) — the dashboard loads identically; identify/audit/pause/resume/history/export all work against either backend; `/api/session` sets `pa_csrf`.

## 4. Cross-backend history

1. Run an audit via the Rust CLI (`--encrypt --passphrase test1234 --yes`).
2. Start the Python server, unlock history with `test1234` in the dashboard — plaintext displays.
3. `GET /api/history` shows `"backend"`: runs show `python` or `rust` correctly; export CSV contains the `backend` column between `plaintext_withheld` and `target_count`.

## 5. Pause/resume across a restart

1. Start a long dictionary audit in the dashboard (Rust backend), pause it, stop the server (Ctrl+C).
2. Restart with either backend — the job reappears paused; resume completes with consistent attempt accounting.

## 6. Test suites

```bash
cargo test                          # in rust/ — all crates green
pytest                              # existing suite stays green
pytest tests/test_rust_parity.py    # skips with a clear message if hashcrack-rs isn't built
```

## 7. Benchmark sanity

```bash
hashcrack-rs benchmark --seconds 1.0
```

Expected: per-algorithm lines ending with a `Fastest:` line; fast-hash rates at or above the Python CLI's on the same machine (informational).

Measured (SC-007, same machine, 1.0 s slices, release build 2026-11-18, all 12 fast formats):

| Algorithm | Rust candidates/s | Python candidates/s | Ratio |
|---|---|---|---|
| md5 | 3,271,753 | 909,651 | 3.6x |
| sha256 | 3,336,572 | 881,828 | 3.8x |
| ntlm | 1,502,928 | 17,883 | 84.0x |
| sha1 | 3,942,394 | 894,291 | 4.4x |
| sha224 | 3,455,327 | 912,790 | 3.8x |
| sha384 | 1,917,195 | 706,337 | 2.7x |
| sha512 | 1,738,106 | 711,882 | 2.4x |
| md4 | 3,754,739 | 37,500 | 100.1x |
| lm | 962,839 | 9,075 | 106.1x |
| sha512_224 | 1,950,105 | 647,557 | 3.0x |
| sha512_256 | 1,945,068 | 634,824 | 3.1x |
| ripemd160 | 2,238,019 | 7,723 | 289.8x |

The Rust backend meets SC-007: throughput is at or above the Python backend on every fast-hash format. The extreme ratios (ntlm, md4, lm, ripemd160) reflect the Python side falling back to pure-Python digest implementations on this OpenSSL 3 machine.
