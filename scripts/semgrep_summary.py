import csv
import json
from collections import Counter
from pathlib import Path

SRC = Path("reports/sast/semgrep-results.json")
OUT = Path("reports/sast/semgrep-triage.csv")
PREFIX = "target/juice-shop/"

def as_list(v):
    return v if isinstance(v, list) else ([v] if v else [])

data = json.loads(SRC.read_text(encoding="utf-8"))
results = data.get("results", [])

rows, seen = [], set()
for r in results:
    meta = r["extra"].get("metadata", {})
    path = r["path"].replace(PREFIX, "")
    line = r["start"]["line"]
    key = (path, line, r["check_id"].split(".")[-1])
    if key in seen:
        continue
    seen.add(key)
    rows.append({
        "id": f"SAST-{len(rows) + 1:03d}",
        "severity": r["extra"].get("severity", ""),
        "rule": r["check_id"].split(".")[-1],
        "file": path,
        "line": line,
        "owasp": "; ".join(as_list(meta.get("owasp"))),
        "cwe": "; ".join(as_list(meta.get("cwe"))),
        "message": r["extra"].get("message", "").strip().replace("\n", " ")[:300],
        "verdict": "",
        "notes": "",
    })

with OUT.open("w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)

print(f"Raw findings: {len(results)}  |  after dedupe: {len(rows)}")
print(f"Scan errors: {len(data.get('errors', []))}\n")
for label, field in [("By severity", "severity"), ("By OWASP", "owasp"), ("Top files", "file")]:
    print(label)
    for k, n in Counter(r[field] or "(none)" for r in rows).most_common(10):
        print(f"  {n:4}  {k}")
    print()