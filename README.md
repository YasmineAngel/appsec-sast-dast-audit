# OWASP Juice Shop — SAST & DAST Security Audit

A hands-on application security audit of [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) 20.2.0,
combining static analysis (SAST), dynamic analysis (DAST), manual triage, and remediation.

## What this project demonstrates

- Running **SAST** (Semgrep) and **DAST** (OWASP ZAP) against a real target
- **Triaging** every finding by hand: separating true positives from false positives and out-of-scope noise
- Mapping confirmed issues to the **OWASP Top 10 (2025)**
- **Cross-validating** the two methods against each other
- **Fixing** vulnerabilities and proving the fixes with before/after evidence

## Results at a glance

| | Raw findings | Confirmed (true positive) | False positives removed |
|---|---|---|---|
| SAST (Semgrep) | 92 | 25 | 32 |
| DAST (OWASP ZAP) | 80 alert types | 4 | 7 |

- **3 vulnerabilities confirmed by both SAST and DAST** (SQL injection in search, open redirect, wildcard CORS)
- **2 vulnerabilities found by manual review** that neither tool detected (a race condition and stack-trace disclosure)
- **3 vulnerabilities fixed and verified** with live before/after testing

## Highlights

- SQL injection in login: the email `' OR 1=1--` logs in as administrator with no password
- SQL injection in search: a UNION payload dumps all 24 user accounts and their password hashes
- Open redirect: an allowlist bypass that ZAP exploited to reach an external domain

## Repository structure

| Folder | Contents |
|---|---|
| `docs/` | Final report and SAST/DAST/remediation methodology |
| `reports/sast/` | Semgrep triage sheet and raw output |
| `reports/dast/` | ZAP triage sheet and raw reports |
| `reports/remediation/` | Live attack evidence (before/after) |
| `fixes/` | Before/after source for the three remediations |
| `scripts/` | Helper scripts for summarizing and validating triage |

## Start here

- **[Full report](docs/report.md)** — the complete write-up
- [SAST methodology](docs/sast-methodology.md) · [DAST methodology](docs/dast-methodology.md) · [Remediation testing](docs/remediation-testing.md)

## Tools

Semgrep 1.178.0 · OWASP ZAP 2.17.0 · Docker · OWASP Juice Shop 20.2.0