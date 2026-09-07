# MO3 — Certificate Pinning Analyzer

TLS connection inspector plus fixture-based pinning-presence detection.
Standard-library only.

## What the engine genuinely does

- **TLS connection inspector** — connects to a host with the platform `ssl`
  module, reads the peer certificate chain, computes SHA-256/SHA-1/MD5
  fingerprints, tests verified vs. permissive connections, and inspects cert
  subject/issuer/SAN/validity.
- **Static presence scan** — regex-based detector over source-like fixtures for
  `CertificatePinner`, `X509TrustManager`, `TrustManager[] {}`, `sha256/` pins,
  `HostnameVerifier`, iOS `SecTrust` calls, and weakening patterns
  (`TrustAllCerts`, empty `checkServerTrusted`, ALLOW_ALL_TRUST).
- **Verdict classification** — each fixture becomes `PINNED`, `WEAK_TRUST`, or
  `NO_PINNING`.
- **Trust store / proxy tooling** — add/remove trusted certs, build custom SSL
  contexts, generate proxy guidance.
- **CertificateValidator** — weak-signature, self-signed, expiry checks.

## Quick start

```bash
# Offline demo (scans fixtures/, writes reports/, exit 0)
python3 cert_pin_analyzer.py

# Scan source fixtures for pinning presence
python3 cert_pin_analyzer.py scan-fixture fixtures/*.java --json

# TLS section inspection (lab host you own)
python3 cert_pin_analyzer.py tls api.lab.example.com --port 443
python3 cert_pin_analyzer.py cert-info api.lab.example.com

# Rebuild fixtures
python3 cert_pin_analyzer.py --make-fixture

# Tests
python3 -m unittest discover -s tests
```

## CLI

```
python3 cert_pin_analyzer.py [-h] [--json] [--report-dir REPORT_DIR]
                             [--make-fixture]
                             {scan-fixture,tls,cert-info,demo} ...
```

- `scan-fixture <paths...>` — static pinning-presence scan over fixtures.
- `tls <host> [--port]` — live TLS inspection.
- `cert-info <host> [--port]` — live certificate detail dump.
- `demo` — offline fixture corpus scan (default when no command given).
- `--json` — write JSON to `reports/`.
- `--make-fixture` — regenerate `fixtures/`.

Exit codes: `0` success (incl. demo), `2` usage/input error.

## Live Lab Test Plan

Prerequisites: an endpoint you own (or the offline fixtures). For live checks use
your lab host, never third-party infrastructure without authorization.

1. **Baseline**: `python3 cert_pin_analyzer.py demo` — confirm 4 fixtures classify
   as PINNED / WEAK_TRUST / NO_PINNING deterministically.
2. **Static recall**: decompile an app you're authorized to assess (jadx/apktool)
   and run `scan-fixture` over the produced sources. Confirm pinning indicators
   match a manual grep for `CertificatePinner` / `X509TrustManager`.
3. **Live inspection**: stand up a lab TLS server (self-signed is fine) and run
   `tls <lab-host>`; verify fingerprints against `openssl x509 -fingerprint`.
4. **Negative test**: confirm `clean_crypto.java` stays `NO_PINNING` to bound
   false positives.
5. **Regression**: re-run `python3 -m unittest discover -s tests`.

## Metrics

| Metric                         | Value |
|--------------------------------|-------|
| Standard-library only          | Yes   |
| Third-party deps               | none  |
| Deterministic offline tests    | 9     |
| Static pinning indicators      | 13 + 5 weak tokens |
| Offline demo exit              | 0     |
| Report output                  | `reports/*.json` (gitignored) |
| Live mode                      | `tls` / `cert-info` on lab hosts |

## IMPORTANT: Read before use.

Educational, authorization-required tooling. See `LICENSE` for the full shield —
Authorization, CFAA / computer-crime statutes, Acceptable Use, Prohibited Use,
No Warranty, and Responsible Disclosure. Only test TLS endpoints you own or are
explicitly authorized to assess.

## License

MIT — full legal shield in `LICENSE`.