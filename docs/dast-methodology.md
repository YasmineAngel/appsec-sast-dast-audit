# DAST Methodology

## Target

- **Application:** OWASP Juice Shop 20.2.0, the same version analyzed in the SAST phase
- **Runtime:** Docker image `bkimminich/juice-shop`, served at http://localhost:3000
- **Scan address:** `http://host.docker.internal:3000`. ZAP runs in its own container, where `localhost` refers to the container itself; `host.docker.internal` is Docker Desktop's address for the host machine.

## Tool

- **OWASP ZAP**, run through the official Docker image `zaproxy/zap-stable`
- **ZAP version:** 2.17.0

## Scans

Two scans were run, from least to most intrusive.

| Scan | Script | What it does |
|---|---|---|
| Baseline | `zap-baseline.py` | Crawls the application and analyzes responses passively. No attacks are sent. |
| Full | `zap-full-scan.py` | Crawls the application, then actively sends attack payloads (SQL injection, XSS, path traversal, etc.) to every discovered endpoint. |

Both scans used the **AJAX spider** (`-j`). Juice Shop is an Angular single-page application whose pages are rendered by JavaScript, so ZAP's traditional spider cannot discover most of them; the AJAX spider drives a real headless browser instead.

### Commands

Baseline:

    docker run --rm -v "${PWD}/reports/dast:/zap/wrk:rw" -t zaproxy/zap-stable zap-baseline.py \
      -t http://host.docker.internal:3000 -j \
      -r zap-baseline.html -J zap-baseline.json -I

Full scan:

    docker run --rm -v "${PWD}/reports/dast:/zap/wrk:rw" -t zaproxy/zap-stable zap-full-scan.py \
      -t http://host.docker.internal:3000 -j -m 5 \
      -r zap-full.html -J zap-full.json -I

`-m 5` gives the spider up to 5 minutes to explore. `-I` prevents ZAP from returning a failure exit code on warnings.

## Scan results

| Scan | URLs discovered | Warnings | Passed checks | Failures |
|---|---|---|---|---|
| Baseline | 466 | 13 | 54 | 0 |
| Full | 2,373 | 17 | 124 | 0 |

## Cross-validation with SAST

Several DAST alerts independently confirm vulnerabilities identified in the source code:

| ZAP alert | Evidence | Confirms |
|---|---|---|
| SQL Injection | Payload `'(` in `/rest/products/search?q=` caused a 500 Internal Server Error | SAST-070 (`routes/search.ts`) |
| External Redirect | `/redirect` sent the browser to an attacker-controlled domain by embedding an allowed URL in its query string | SAST-069 (`routes/redirect.ts`) |
| CORS Misconfiguration | `Access-Control-Allow-Origin: *` returned on 201 URLs | SAST-080 (`server.ts`) |

ZAP's **Bypassing 403** and **Backup File Disclosure** alerts were investigated manually and found to be false positives. Requests such as `/%2e/ftp/package.json.bak` and `/ftp/quarantine.bak` return 200 OK, but the response body is the application's default HTML page, not the requested file. Note that browsers normalize `/%2e/` before sending the request, so this was verified with `curl --path-as-is`, which sends the path unchanged.

## Coverage limitations

- **Unauthenticated scanning and generic payloads.** ZAP was not logged in, so features that require an account (user profile, basket, wallet) were not tested; this is why the server-side code execution in the profile page (SAST-074) was not found. Other SAST findings are reachable without login, such as the JavaScript injection in product reviews and order tracking (SAST-071, SAST-072), but they use path parameters and database operators that ZAP's generic payloads did not trigger.
- **JSON APIs.** Most of Juice Shop's functionality is exposed through JSON endpoints called by JavaScript. Generic scanners test these less effectively than classic HTML forms.
- **Passive rule false negative.** ZAP's Directory Browsing check passed, although unauthenticated directory listing on `/ftp`, `/encryptionkeys` and `/support/logs` was confirmed manually. ZAP's rule recognizes Apache and IIS listing formats, not the format used by Express's `serve-index`.
- **Application state.** The active scan creates users, reviews and other data. The application was reset before the remediation tests in Step 8.
- **Local HTTP only.** The target runs locally without TLS. Transport-security alerts (e.g. HTTP Only Site) reflect the lab setup, not a production deployment.
- **Single-page application fallback.** The server answers unknown paths with the application's HTML shell and a 200 OK status. Scanner rules that judge success by status code alone (backup file discovery, 403 bypass) therefore produce false positives, and each such alert must be verified by inspecting the response body.
- **Third-party alerts.** The AJAX spider drives a real browser, which followed outbound links (social media, GitHub, OpenSea) and loaded third-party sites. ZAP passively recorded alerts on those sites: 54 of 80 alert types, including a "High" PII Disclosure on Facebook. All were marked Out of scope. Future scans should restrict the spider to the target domain.

These limitations show why DAST and SAST are complementary: each phase found vulnerabilities the other could not.

## Triage approach

DAST alerts were triaged **per alert type** rather than per URL (for example, one row for CORS Misconfiguration instead of 201). Each alert received the same verdicts used in the SAST phase (TP, FP, Out of scope, Duplicate, Informational), an OWASP Top 10 (2025) category for true positives, and, where applicable, the SAST finding it confirms (`sast_match` column).

## Triage results

ZAP reported 80 alert types (one row per alert type and site). 54 concerned third-party sites loaded by the AJAX spider and one reflected the local HTTP-only lab setup, leaving 25 alerts about the target application.

| Verdict | Count |
|---|---|
| True positive | 4 |
| False positive | 7 |
| Duplicate | 2 |
| Informational | 12 |
| Out of scope | 55 |
| **Total** | **80** |

One additional vulnerability was found manually during triage (MAN-002: stack traces in error pages), which ZAP's Application Error Disclosure rule did not detect.

True positives by OWASP Top 10 (2025) category:

| Category | Count |
|---|---|
| A02 Security Misconfiguration | 2 |
| A01 Broken Access Control | 1 |
| A05 Injection | 1 |
| A10 Mishandling of Exceptional Conditions (manual) | 1 |

Key observations:

- **DAST confirmed three SAST findings as exploitable:** the open redirect (SAST-069), SQL injection in product search (SAST-070) and wildcard CORS (SAST-080).
- **Three alerts were disproven by manual verification:** Backup File Disclosure and Bypassing 403 (the single-page-application fallback returns 200 OK for unknown paths) and Private IP Disclosure (the IP is a hardcoded example in the OAuth redirect allowlist, not the server's address).
- **DAST missed most of the high-impact SAST findings** (NoSQL and JavaScript injection, server-side code execution, IDOR) because they sit behind authentication or in JSON APIs. Neither method alone would have produced a complete picture.