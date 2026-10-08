# Remediations

Three vulnerabilities from the audit were fixed. Each subfolder contains the
original file (`.before`), the patched file (`.after`), and a README explaining
the vulnerability, the fix and how to verify it.

| Fix | Vulnerability | Finding(s) | OWASP 2025 |
|---|---|---|---|
| 01 | SQL injection in product search | SAST-070, DAST-006 | A05 Injection |
| 02 | Open redirect | SAST-069, DAST-001 | A01 Broken Access Control |
| 03 | SQL injection in login | SAST-063 | A05 Injection |

Fixes 01 and 02 were confirmed by both SAST and DAST, then re-tested after
patching (see `docs/remediation-testing.md`). The target source in `target/` is
git-ignored, so patched files are preserved here rather than in that copy.