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

- **Unauthenticated scanning.** ZAP was not logged in, so features that require an account (user profile, product reviews, order tracking, basket, wallet) were not tested. This explains why ZAP reported no XSS, NoSQL injection or server-side template injection, although SAST confirmed such vulnerabilities in authenticated code paths (e.g. SAST-071, SAST-072, SAST-074).
- **JSON APIs.** Most of Juice Shop's functionality is exposed through JSON endpoints called by JavaScript. Generic scanners test these less effectively than classic HTML forms.
- **Passive rule false negative.** ZAP's Directory Browsing check passed, although unauthenticated directory listing on `/ftp`, `/encryptionkeys` and `/support/logs` was confirmed manually. ZAP's rule recognizes Apache and IIS listing formats, not the format used by Express's `serve-index`.
- **Application state.** The active scan creates users, reviews and other data. The application was reset before the remediation tests in Step 8.
- **Local HTTP only.** The target runs locally without TLS. Transport-security alerts (e.g. HTTP Only Site) reflect the lab setup, not a production deployment.
- **Single-page application fallback.** The server answers unknown paths with the application's HTML shell and a 200 OK status. Scanner rules that judge success by status code alone (backup file discovery, 403 bypass) therefore produce false positives, and each such alert must be verified by inspecting the response body.

These limitations show why DAST and SAST are complementary: each phase found vulnerabilities the other could not.

## Triage approach

DAST alerts were triaged **per alert type** rather than per URL (for example, one row for CORS Misconfiguration instead of 201). Each alert received the same verdicts used in the SAST phase (TP, FP, Out of scope, Duplicate, Informational), an OWASP Top 10 (2025) category for true positives, and, where applicable, the SAST finding it confirms (`sast_match` column).

## Triage results

TODO