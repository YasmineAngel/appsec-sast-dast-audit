import csv
from collections import Counter
from urllib.parse import urlparse

PATH = "reports/dast/zap-triage.csv"
TARGET = "host.docker.internal"
ALLOWED = {"TP", "FP", "Out of scope", "Duplicate", "Informational"}

A01 = "A01:2025 Broken Access Control"
A02 = "A02:2025 Security Misconfiguration"
A05 = "A05:2025 Injection"
A10 = "A10:2025 Mishandling of Exceptional Conditions"
INFO = "Informational"

T = {
    "DAST-001": ("TP", A01, "SAST-069", "Allowlist bypass exploited: redirect to an attacker-controlled domain by embedding an allowed URL in the query string."),
    "DAST-002": (INFO, "", "SAST-069", "Redirect to an allowlisted destination (GitHub) is intended behavior; the exploitable variant is DAST-001."),
    "DAST-006": ("TP", A05, "SAST-070", "Payload '( in the search parameter caused a 500 error: user input breaks the SQL query. Confirms raw SQL concatenation in search.ts."),
    "DAST-007": ("FP", "", "", "Verified with curl: responses are the application's default HTML page (SPA fallback, 200 OK), not backup files."),
    "DAST-008": ("FP", "", "", "Verified with curl --path-as-is: /%2e/ftp/... returns the default HTML page, not the protected file."),
    "DAST-009": ("TP", A02, "SAST-080", "Wildcard CORS (Access-Control-Allow-Origin: *) confirmed on live responses."),
    "DAST-019": ("TP", A02, "", "No Content-Security-Policy header on application pages. Low on its own; increases the impact of any XSS."),
    "DAST-020": ("Duplicate", A02, "SAST-080", "Same root cause as DAST-009 (Access-Control-Allow-Origin: *)."),
    "DAST-021": ("Out of scope", "", "", "Local lab runs over plain HTTP by design; TLS is a deployment concern outside this audit."),
    "DAST-023": ("FP", "", "", "Only socket.io transport responses lack X-Frame-Options; application pages set it (see SAST-083)."),
    "DAST-024": ("FP", "", "", "sid is socket.io's transport session ID, not the user's authentication token."),
    "DAST-040": (INFO, "", "", "Cross-Origin-Embedder-Policy not set: defense-in-depth header, no direct exploit."),
    "DAST-041": (INFO, "", "", "Cross-Origin-Opener-Policy not set: defense-in-depth header, no direct exploit."),
    "DAST-042": (INFO, "", "", "Pattern match on risky functions inside minified frontend bundles; not a finding without source-level review."),
    "DAST-043": (INFO, "", "SAST-085", "Deprecated Feature-Policy header, as noted in SAST-085."),
    "DAST-044": ("FP", "", "", "IP 192.168.99.100 is a hardcoded example entry in the OAuth redirect allowlist (Docker Machine default), not the server's address. No network information disclosed."),
    "DAST-052": ("FP", "", "", "Numbers in CSS/HTML matched the Unix timestamp pattern; no sensitive time data."),
    "DAST-053": ("FP", "", "", "Only socket.io transport responses lack X-Content-Type-Options; application responses set it (see SAST-082)."),
    "DAST-054": ("Duplicate", A02, "SAST-080", "Same root cause as DAST-009, observed on socket.io responses."),
    "DAST-055": (INFO, "", "", "ZAP diagnostic on cookie handling; no vulnerability identified."),
    "DAST-063": (INFO, "", "", "sessionStorage holds the basket item total; not sensitive."),
    "DAST-070": (INFO, "", "", "ZAP notes the site is a JavaScript single-page app; used to choose the AJAX spider."),
    "DAST-071": (INFO, "", "", "Caching behavior note; no vulnerability."),
    "DAST-077": (INFO, "", "", "Caching behavior note; no vulnerability."),
    "DAST-078": (INFO, "", "", "Caching behavior note; no vulnerability."),
    "DAST-079": (INFO, "", "", "Responses did not change with different User-Agent headers; no vulnerability."),
}

with open(PATH, encoding="utf-8-sig", newline="") as f:
    reader = csv.DictReader(f)
    fields = reader.fieldnames
    rows = [r for r in reader if r["id"] != "MAN-002"]

for r in rows:
    host = urlparse(r["example_url"]).hostname or ""
    if host != TARGET:
        r.update(verdict="Out of scope", owasp_2025="", sast_match="",
                 notes=f"Third-party site ({host}) loaded by the AJAX spider via an outbound link; not part of the target.")
    elif r["id"] in T:
        v, o, s, n = T[r["id"]]
        r.update(verdict=v, owasp_2025=o, sast_match=s, notes=n)

man = {k: "" for k in fields}
man.update(id="MAN-002", alert="Stack trace in error pages", risk="Low (manual)", cwe="CWE-209",
           example_url="http://localhost:3000/ftp/package.json.bak", owasp_2025=A10, verdict="TP",
           notes="Found manually during DAST triage. 403 error pages return full stack traces revealing internal paths, "
                 "source files, libraries and the Express version. ZAP's Application Error Disclosure rule passed.")
rows.append(man)

problems = [f"{r['id']}: verdict '{r['verdict']}'" for r in rows if r["verdict"] not in ALLOWED]
problems += [f"{r['id']}: TP without OWASP category" for r in rows if r["verdict"] == "TP" and not r["owasp_2025"]]

with open(PATH, "w", encoding="utf-8-sig", newline="") as f:
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    w.writerows(rows)

print("Verdicts:", dict(Counter(r["verdict"] for r in rows)))
print("TP by OWASP:", dict(Counter(r["owasp_2025"] for r in rows if r["verdict"] == "TP")))
print("PUSH READY" if not problems else "FIX THESE:\n" + "\n".join(problems))