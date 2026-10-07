# SAST Methodology

## Target

- **Application:** OWASP Juice Shop (deliberately vulnerable web application)
- **Version:** 20.2.0 (confirmed via `/rest/admin/application-version` on the running container)
- **Source code:** cloned from the official repository at tag `v20.2.0`, so the scanned code matches the running application used for DAST
- **Runtime:** Docker image `bkimminich/juice-shop`, served at http://localhost:3000

## Tool

- **Semgrep** (Community Edition), run through the official Docker image `semgrep/semgrep`
- **Semgrep version:** 1.178.0
- **Rulesets:**
  - `p/owasp-top-ten`: rules mapped to OWASP Top 10 categories
  - `p/javascript` and `p/typescript`: language-specific security rules
  - `p/nodejsscan`: Node.js and Express security rules
  - `p/secrets`: hardcoded credentials and keys

## Command

    docker run --rm -v "${PWD}:/src" semgrep/semgrep semgrep scan \
      --config p/owasp-top-ten --config p/javascript --config p/typescript \
      --config p/nodejsscan --config p/secrets \
      --exclude "node_modules" --exclude "test" \
      --exclude "data/static/codefixes" --exclude "frontend/src/assets" \
      --json-output=reports/sast/semgrep-results.json \
      --sarif-output=reports/sast/semgrep-results.sarif \
      target/juice-shop

## Scope and exclusions

| Excluded path | Reason |
|---|---|
| `node_modules` | Third-party dependencies. Dependency risk is a job for SCA tools, not SAST. |
| `test` | Test code, not part of the deployed application. |
| `data/static/codefixes` | Vulnerable code snippets used by Juice Shop's coding challenges. They are not executed by the application and would create duplicate findings. |
| `frontend/src/assets` | Static assets (images, fonts), no application logic. |

During triage, findings in CI/CD workflows (`.github/workflows`), infrastructure code (Terraform, Dockerfiles), build scripts, internal tooling, and frontend unit tests (`*.spec.ts`) were marked **Out of scope**: they are not part of the application's runtime attack surface.

## Scan results

- Rules run: 332
- Files tracked by git: 801
- Files skipped by exclusion patterns: 482
- Files skipped for size (over 1 MB): 1
- Raw findings: 92

## Coverage limitations

Semgrep reported 43 non-fatal errors. 26 were timeouts on translation files (`data/static/i18n/*.json`), which contain only UI strings and no executable logic. One timeout occurred on `lib/config.schema.ts`, a configuration schema; this file was not analyzed. 16 files were only partially parsed: 8 GitHub workflow and Docker files (out of scope for this audit) and 8 Angular component templates. Because Angular template syntax is not fully supported, client-side sinks in these templates (e.g. `[innerHTML]` bindings) may not be detected by SAST. This gap is addressed by the DAST phase, which tests the rendered application.

## Triage approach

Every finding was reviewed manually against the source code and given one verdict:

| Verdict | Meaning |
|---|---|
| True positive (TP) | A real, exploitable weakness in the application |
| False positive (FP) | The rule fired, but the code is not vulnerable |
| Out of scope | Outside the application's runtime attack surface |
| Duplicate | Same issue as another finding (e.g. two rules on the same line) |
| Informational | Not a weakness; often a security control that is present |

Each true positive is mapped to the **OWASP Top 10 (2025)**. Where Semgrep's category was wrong, the finding was reclassified. For example, several "NoSQL injection" findings target Sequelize models, which use parameterized queries; these were assessed for broken access control (IDOR) instead of injection.

Helper scripts in `scripts/` generate the triage sheet (`semgrep_summary.py`), extract code context for review (`show_context.py`), and validate the final sheet (`finalize_triage.py`).

## Triage results

Of 92 raw findings, 25 were confirmed as true positives (27%).

| Verdict | Count |
|---|---|
| True positive | 25 |
| False positive | 32 |
| Out of scope | 28 |
| Duplicate | 3 |
| Informational | 4 |

One additional vulnerability was found by manual code review (MAN-001, a race condition in `likeProductReviews.ts`), which Semgrep did not detect.

True positives by OWASP Top 10 (2025) category:

| Category | Count |
|---|---|
| A01 Broken Access Control | 13 |
| A05 Injection | 7 |
| A04 Cryptographic Failures | 2 |
| A07 Authentication Failures | 2 |
| A02 Security Misconfiguration | 1 |
| A06 Insecure Design (manual) | 1 |

Key observation: 15 findings were reported by Semgrep as NoSQL injection. Manual review showed that most target Sequelize models, which use parameterized queries, so injection was not possible. Three were reclassified: two as broken access control (IDOR) and one confirmed as NoSQL operator injection on a MarsDB collection.