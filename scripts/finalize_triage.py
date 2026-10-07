import csv
from collections import Counter

PATH = "reports/sast/semgrep-triage.csv"
ALLOWED = {"TP", "FP", "Out of scope", "Duplicate", "Informational"}

with open(PATH, encoding="utf-8-sig", newline="") as f:
    reader = csv.DictReader(f)
    fields = [h.strip() for h in reader.fieldnames]
    rows = [{k.strip(): (v or "").strip() for k, v in r.items()} for r in reader]

seed = "Usernames in demo seed data, not credentials the app authenticates with."
listing = "Directory listing enabled via serve-index; unauthenticated listing confirmed in browser."
NOTES = {
    "SAST-017": seed,
    "SAST-018": seed,
    "SAST-022": "Random ID for chatbot conversation storage, not a session or auth token.",
    "SAST-043": "Sequelize model with parameterized where clause; query scoped to the logged-in user's UserId.",
    "SAST-073": "Username rendered into the profile page; stored XSS is a known Juice Shop issue. Confirm in DAST.",
    "SAST-082": "Positive finding: X-Content-Type-Options header is set.",
    "SAST-083": "Positive finding: X-Frame-Options header is set.",
    "SAST-084": "Positive finding: X-Powered-By header is removed.",
    "SAST-085": "Positive finding: Feature-Policy header is set (deprecated; Permissions-Policy replaces it).",
    **{f"SAST-0{n}": listing for n in range(86, 91)},
}
for r in rows:
    if r["id"] in NOTES:
        r["notes"] = NOTES[r["id"]]

problems = []
for r in rows:
    if r["verdict"] not in ALLOWED:
        problems.append(f"{r['id']}: unknown verdict '{r['verdict']}'")
    if r["verdict"] == "TP" and not r["owasp_2025"]:
        problems.append(f"{r['id']}: TP without an OWASP category")

with open(PATH, "w", encoding="utf-8-sig", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)

print("Verdicts:", dict(Counter(r["verdict"] for r in rows)))
print("TP by OWASP:", dict(Counter(r["owasp_2025"] for r in rows if r["verdict"] == "TP")))
print("PUSH READY" if not problems else "FIX THESE:\n" + "\n".join(problems))