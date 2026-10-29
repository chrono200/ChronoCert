# Changelog

## [2.0.0] - 2026-10-29
### Added
- `audit`: grade, key and signature analysis, SANs, fingerprints, TLS 1.0-1.3 probe, chain view (Python 3.13+), findings
- `inspect`: offline analysis of PEM/DER files, hostname coverage check
- `check --baseline` / `--save-baseline`: detect swapped certificates
- Built-in X.509/DER parser (no third-party crypto)
- Reads certificates that the device's TLS policy refuses (weak keys, SHA-1)
### Changed
- Commands are now `check`, `audit`, `inspect` (`chronocert HOST` still works). `-d` is replaced by `audit`.

## [1.0.0] - 2026-10-29
### Added
- Threaded TLS certificate expiry checks for many hosts
- Status levels with `--warn` / `--crit` thresholds
- Reads expired and self-signed certificates; `-k` mode for internal hosts
- `--details`, `--json`, host files, URL and `host:port` parsing
- Certificate-and-seal banner, unit tests with a local TLS server
