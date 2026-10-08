# OWASP Juice Shop — SAST & DAST Security Audit

This report documents a combined static (SAST) and dynamic (DAST) security assessment of OWASP Juice Shop 20.2.0, a deliberately vulnerable web application, carried out in a local Docker environment in October 2026. Semgrep scanned the source code and OWASP ZAP attacked the running application. Semgrep produced 92 findings, of which 25 were confirmed as true vulnerabilities after manual triage; ZAP produced 80 alert types, of which 4 were confirmed against the target. Two further vulnerabilities were found by manual review that neither tool reported. Three confirmed vulnerabilities were remediated and verified: SQL injection in product search, SQL injection in login, and an open redirect. The assessment's central result is that the two methods were complementary rather than redundant: three high-impact issues were confirmed by both tools, while each method also found issues the other missed.

## Scope and methodology

**Target.** OWASP Juice Shop 20.2.0, run from the official `bkimminich/juice-shop` Docker image at http://localhost:3000. The source code was cloned at tag `v20.2.0` so that the code analyzed and the application attacked were the same build.

**In scope.** The Juice Shop application: its server-side routes, its Angular frontend, and its running HTTP endpoints.

**Out of scope.** Third-party dependencies, CI/CD pipeline configuration (GitHub Actions), infrastructure-as-code (Terraform, Dockerfiles), build scripts, and the project's own challenge-scoring framework. Alerts raised on third-party websites that the scanner reached by following outbound links were also excluded.

**Tools.**

| Phase | Tool | Version | What it did |
| --- | --- | --- | --- |
| SAST | Semgrep (Community) | 1.178.0 | Analyzed source code against 5 rulesets (332 rules) |
| DAST | OWASP ZAP | 2.17.0 | Crawled and actively attacked the running application |

Each phase has a dedicated methodology document: `docs/sast-methodology.md` and `docs/dast-methodology.md`. Every finding was triaged manually and recorded with a verdict, an OWASP Top 10 (2025) category, and a reason. The full triage is in `reports/sast/semgrep-triage.csv` and `reports/dast/zap-triage.csv`.

## Results overview

**SAST (Semgrep).** 92 raw findings, triaged as follows:

| Verdict | Count |
| --- | --- |
| True positive | 25 |
| False positive | 32 |
| Out of scope | 28 |
| Duplicate | 3 |
| Informational | 4 |

**DAST (ZAP).** 80 alert types, triaged as follows:

| Verdict | Count |
| --- | --- |
| True positive | 4 |
| False positive | 7 |
| Out of scope | 55 |
| Duplicate | 2 |
| Informational | 12 |

Of the ZAP alerts, 54 concerned third-party sites reached via outbound links and one reflected the local HTTP-only lab setup, leaving 25 alerts about the target.

**Confirmed vulnerabilities by OWASP Top 10 (2025).** Combining both tools and the two manual findings, after removing duplicates and the three issues confirmed by both methods (counted once):

| Category | Count |
| --- | --- |
| A01 Broken Access Control | 13 |
| A05 Injection | 7 |
| A02 Security Misconfiguration | 2 |
| A04 Cryptographic Failures | 2 |
| A07 Authentication Failures | 2 |
| A06 Insecure Design (manual) | 1 |
| A10 Mishandling of Exceptional Conditions (manual) | 1 |

Broken Access Control dominated, driven by unauthenticated file servers, directory listing and insecure direct object references (IDOR).

## Key findings

The most significant confirmed vulnerabilities, ordered by impact.

**1. Server-side code execution via user profile (SAST-074, A05 Injection, CWE-95).** A username matching a template pattern (`#{...}`) is passed to `eval`, allowing arbitrary code execution in the server process. Highest-impact finding; requires an authenticated session, which is why DAST did not reach it.

**2. SQL injection in login (SAST-063, A05, CWE-89).** The login query concatenates the submitted email into raw SQL. The email `' OR 1=1--` returns the first user and logs the attacker in as administrator with no password. Confirmed live and remediated.

**3. SQL injection in product search (SAST-070 / DAST-006, A05, CWE-89).** The search term is concatenated into raw SQL. A UNION payload dumped all 24 user accounts with their email addresses and MD5 password hashes. Confirmed by both tools and remediated.

**4. JavaScript injection in reviews and order tracking (SAST-071, SAST-072, A05, CWE-943).** User input reaches a MarsDB `$where` clause, allowing JavaScript injection (denial of service, or returning other users' orders).

**5. Open redirect (SAST-069 / DAST-001, A01 Broken Access Control, CWE-601).** The redirect allowlist used substring matching, so an allowed URL embedded in an attacker's URL passed the check. ZAP exploited it to reach an external domain. Confirmed by both tools and remediated.

**6. Unauthenticated access to sensitive file servers (SAST-058, 059, 062, 068, A01, CWE-22/CWE-73).** The `/ftp`, `/encryptionkeys` and `/support/logs` endpoints list and serve files without authentication. Confirmed manually in the browser.

**7. Hardcoded JWT signing key and weak password hashing (SAST-042, A07, CWE-798; SAST-040, A04, CWE-327).** The RSA private key that signs JWTs is committed in source, so anyone with the code can forge a token for any user. Passwords are hashed with unsalted MD5.

**8. Wildcard CORS (SAST-080 / DAST-009, A02 Security Misconfiguration, CWE-942).** `Access-Control-Allow-Origin: *` is returned across the API. Confirmed by both tools.

**Manual findings (not reported by either tool).**

- **MAN-001 (A06 Insecure Design, CWE-362).** A race condition in the review "like" feature: the code checks, waits 150 ms, then updates, so concurrent requests bypass the one-like-per-user rule.
- **MAN-002 (A10 Mishandling of Exceptional Conditions, CWE-209).** Error pages return full stack traces exposing internal paths, source file names, libraries and the framework version.

## Cross-validation: SAST vs DAST

The clearest result of this assessment is how little the two methods overlapped, and why that makes using both worthwhile.

**Confirmed by both methods (3 issues).** SQL injection in product search, the open redirect, and wildcard CORS were each found in the code by Semgrep and then proven exploitable against the running app by ZAP. A finding confirmed from two independent angles is the most defensible kind: the code shows the flaw, and the live attack shows it is reachable.

**Found only by SAST.** Server-side code execution, SQL injection in login, JavaScript injection in reviews and order tracking, the hardcoded JWT key, MD5 hashing, and the IDOR issues. These sit behind authentication or in JSON API parameters that an unauthenticated scanner did not exercise.

**Found only by DAST, or confirmed by it.** The live exploitation of the open redirect and the wildcard CORS header were demonstrated dynamically. ZAP also validated the unauthenticated file-server exposure through live requests.

**Found by neither tool.** Both manual findings (the race condition and the stack-trace disclosure) required reading the code and reasoning about behavior; no rule in either tool reported them.

**Where the tools were wrong.** Semgrep reported 15 "NoSQL injection" findings on Sequelize calls that use parameterized queries; manual review reclassified most as false positives and two as IDOR. ZAP reported "Backup File Disclosure", "Bypassing 403" and "Private IP Disclosure" that proved false once the response bodies were inspected (the application returns its HTML shell with a 200 status for unknown paths). ZAP also missed the directory listing that was confirmed by hand, because its rule only recognizes Apache and IIS listing formats.

|  | Found by SAST | Found by DAST |
| --- | --- | --- |
| SQL injection (search) | yes | yes |
| Open redirect | yes | yes |
| Wildcard CORS | yes | yes |
| SQL injection (login) | yes | no |
| Server-side code execution | yes | no |
| JavaScript injection ($where) | yes | no |
| IDOR | yes | no |
| Hardcoded key / MD5 | yes | no |
| Race condition (MAN-001) | no | no |
| Stack-trace disclosure (MAN-002) | no | no |

Neither tool alone, and no tool without manual review, would have produced a complete picture.

## Remediation

Three confirmed vulnerabilities were fixed and verified. Each attack was run live against the application to confirm it worked, then the patched source shows the change that prevents it. Full evidence is in `docs/remediation-testing.md` and `reports/remediation/`; the before/after code is in `fixes/`.

| Fix | Vulnerability | Before | Fix |
| --- | --- | --- | --- |
| 01 | SQL injection in search (SAST-070 / DAST-006) | 24 accounts and password hashes dumped | Parameterized query (`:criteria` + `replacements`) |
| 02 | Open redirect (SAST-069 / DAST-001) | HTTP 302 to an attacker domain | Allowlist check changed from `includes` to `startsWith` |
| 03 | SQL injection in login (SAST-063) | Admin login with no password | Parameterized query (`:email`, `:password`) |

The common root cause of the two injection fixes is the same principle: user input must be passed to the database as bound data, never concatenated into the query text. The redirect fix tightened a validation check that matched too loosely.

The remediation testing was done with live "before" attacks and source-based "after" verification; the application was not rebuilt from patched source. A rebuild would make the "after" tests live as well and is the natural next step for this phase.

## Limitations and next steps

**Limitations.**

- **Unauthenticated DAST.** ZAP was not given a login, so authenticated features (profile, basket, wallet, order history) were not attacked. This is the main reason DAST missed most of the high-impact SAST findings.
- **No rebuild for remediation.** Fixes were verified against source rather than a rebuilt binary (see Remediation).
- **Single-page-application noise.** The app returns its HTML shell with HTTP 200 for unknown paths, which produced several DAST false positives that had to be checked by hand.
- **Spider scope.** The AJAX spider followed outbound links to third-party sites, which produced 54 out-of-scope alerts that had to be filtered out.

**Next steps for a fuller engagement.**

- Run ZAP with an authenticated session and a context limited to the target domain.
- Rebuild the patched application and re-run both scans to confirm the fixes close the findings and introduce no regressions.
- Add dependency scanning (SCA) and secret scanning as separate phases, since SAST is not the right tool for either.
- Remediate the remaining high-impact findings (server-side code execution, the hardcoded JWT key, the `$where` injections).

## Appendix: repository contents

| Path | Contents |
| --- | --- |
| `docs/sast-methodology.md` | How the Semgrep scan was run and triaged |
| `docs/dast-methodology.md` | How the ZAP scans were run and triaged |
| `docs/remediation-testing.md` | Before/after verification of the three fixes |
| `reports/sast/semgrep-triage.csv` | All 92 SAST findings with verdicts and OWASP mapping |
| `reports/sast/semgrep-results.json` / `.sarif` | Raw Semgrep output |
| `reports/dast/zap-triage.csv` | All 80 ZAP alert types with verdicts and OWASP mapping |
| `reports/dast/zap-baseline.*`, `zap-full.*` | Raw ZAP reports (HTML and JSON) |
| `reports/remediation/` | Live attack evidence for each fix |
| `fixes/` | Before/after source for the three remediations |
| `scripts/` | Helper scripts for summarizing and validating the triage |

All findings use stable IDs (SAST-NNN, DAST-NNN, MAN-NNN) that are consistent across the triage sheets, the remediation evidence and this report.
