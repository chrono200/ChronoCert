# ChronoCert

> A TLS certificate toolkit: expiry checks, security audits, change detection.
> Part of the **CHRONO SUITE**. Dev: **Chrono**.

Single Python file, built for Termux (no root), works anywhere with Python 3.8+. Reads expired, self-signed and even weak certificates, so a broken cert never hides its details.

## Commands

| Command | What it does |
|---|---|
| `check` | Expiry table for many hosts, threaded. Optional change detection with `--baseline` |
| `audit` | Full report with a grade: key, signature, names, fingerprint, TLS versions, chain, findings |
| `inspect` | Same analysis on a certificate **file** (PEM/DER), offline, with hostname check |

`chronocert example.com` is shorthand for `chronocert check example.com`.

## Setup (Termux)

~~~bash
pkg update -y && pkg install -y python git
pip install rich
git clone https://github.com/yourname/chronocert.git
cd chronocert
python chronocert.py
~~~

## Usage

~~~bash
python chronocert.py example.com github.com:443 -w 45 -c 10
python chronocert.py -f hosts.txt
python chronocert.py audit example.com
python chronocert.py inspect fullchain.pem --host example.com
python chronocert.py intranet.local -k          # self-signed: judge by expiry only
python chronocert.py example.com --json
~~~

### check

| Option | Description |
|---|---|
| `hosts` | `host`, `host:port` or `https://host/path` |
| `-f FILE` | One host per line, `#` for comments |
| `-p`, `-t` | Default port (443), timeout in seconds (5) |
| `-w`, `-c` | Warning (30) and critical (7) day thresholds |
| `-k` | Don't fail on untrusted/self-signed certs |
| `--baseline FILE` | Compare fingerprints with a saved baseline |
| `--save-baseline FILE` | Save current fingerprints |
| `--json` | JSON output |

### audit

Everything `check` offers (except files and baselines), plus `--no-protocols` to skip the TLS version probe.

### inspect

`--host NAME` checks the certificate covers that hostname (wildcards match one label). A PEM bundle shows the whole chain.

## Statuses

| Status | Meaning |
|---|---|
| OK | More than `--warn` days left |
| WARNING / CRITICAL | `--warn` / `--crit` days or fewer left |
| EXPIRED | Past its end date |
| INVALID | Not trusted (self-signed, unknown CA, wrong hostname, weak) or not valid yet |
| CHANGED | Fingerprint differs from the baseline and doesn't look like a renewal |
| ERROR | Could not connect (DNS, timeout, refused, not TLS) |

A new certificate with a **newer start date and the same issuer** counts as a renewal. Anything else is flagged CHANGED.

## Audit findings and grade

| Severity | Examples |
|---|---|
| CRIT | expired or expiring, untrusted, RSA under 2048 bits, SHA-1/MD5 signature, hostname not covered, no TLS 1.2/1.3, expiring intermediate |
| WARN | TLS 1.0/1.1 still enabled, no SAN, self-signed, validity over 398 days, CA flag on a leaf |
| INFO | wildcard certificate, TLS 1.3 missing |

**Grade:** any CRIT is **F**, two or more WARN is **C**, one WARN is **B**, otherwise **A**.

The chain view needs Python 3.13 or newer. On older versions the rest of the audit still works.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | `check`: all hosts OK. `audit`/`inspect`: no grade F |
| 1 | Something is not OK |
| 2 | Usage error |
| 130 | Interrupted |

## Tests

~~~bash
pkg install openssl-tool
python -m unittest discover -s tests -v
~~~

Tests use local TLS servers and certificates made with the openssl CLI, so they never touch the internet.

## How it works

ChronoCert contains its own small ASN.1/DER parser, so key sizes, signature algorithms, SANs and fingerprints need no third-party crypto library. It was checked against OpenSSL's own output for RSA, ECDSA and Ed25519 certificates.

## Skills demonstrated

ASN.1/DER and X.509 parsing, TLS handshakes and protocol probing, sockets, threading, risk scoring, change detection, `argparse` subcommands, terminal UI with `rich`, unit testing with local servers.

## Disclaimer

For legal, defensive and educational use on hosts you own or are authorized to test. Protocol probing makes a few extra connections per host.

## License

MIT. Copyright (c) 2026 Chrono.
