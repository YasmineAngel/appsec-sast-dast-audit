import csv
import json
from pathlib import Path

SRC = Path("reports/dast/zap-full.json")
OUT = Path("reports/dast/zap-triage.csv")

data = json.loads(SRC.read_text(encoding="utf-8"))
alerts = [a for site in data["site"] for a in site.get("alerts", [])]
order = {"3": 0, "2": 1, "1": 2, "0": 3}
alerts.sort(key=lambda a: (order.get(a["riskcode"], 9), a["name"]))

rows = []
for i, a in enumerate(alerts, 1):
    inst = a.get("instances", [])
    first = inst[0] if inst else {}
    rows.append({
        "id": f"DAST-{i:03d}",
        "zap_rule": a["pluginid"],
        "alert": a["name"],
        "risk": a["riskdesc"],
        "cwe": f"CWE-{a['cweid']}" if a.get("cweid") not in (None, "", "-1", "0") else "",
        "instances": a.get("count", len(inst)),
        "example_url": first.get("uri", ""),
        "param": first.get("param", ""),
        "attack": first.get("attack", ""),
        "owasp_2025": "",
        "verdict": "",
        "sast_match": "",
        "notes": "",
    })

with OUT.open("w", newline="", encoding="utf-8-sig") as f:
    w = csv.DictWriter(f, fieldnames=rows[0].keys())
    w.writeheader()
    w.writerows(rows)

print(f"{len(rows)} alert types written to {OUT}")
for r in rows:
    print(f"  {r['id']}  {r['risk']:<22} {r['alert']}  (x{r['instances']})")