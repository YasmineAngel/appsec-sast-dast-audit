import csv
from pathlib import Path

SRC = Path("target/juice-shop")
OUT = Path("target/needs-review-context.txt")

with open("reports/sast/semgrep-triage.csv", encoding="utf-8-sig") as f:
    rows = [r for r in csv.DictReader(f) if r["verdict"] == "Needs review"]

out = []
for r in rows:
    n = int(r["line"])
    lines = (SRC / r["file"]).read_text(encoding="utf-8").splitlines()
    out.append(f"\n===== {r['id']} | {r['file']}:{n} | {r['rule']} =====")
    for i in range(max(1, n - 6), min(len(lines), n + 4) + 1):
        marker = ">>" if i == n else "  "
        out.append(f"{marker} {i:4}  {lines[i - 1]}")

out.append("\n===== server.ts lines using appendUserId =====")
for i, line in enumerate((SRC / "server.ts").read_text(encoding="utf-8").splitlines(), 1):
    if "appendUserId" in line:
        out.append(f"   {i:4}  {line.strip()}")

OUT.write_text("\n".join(out), encoding="utf-8")
print(f"{len(rows)} findings written to {OUT}")