import json
import re
from dataclasses import dataclass
from tabulate import tabulate
 
TRIVY_MSG_RE = re.compile(r"Package:\s*(\S+)\nInstalled Version:\s*(\S+)")
OSV_MSG_RE = re.compile(r"Package\s+'([^@']+)@([^']+)'")
RUN_PATTERNS = [("trivy", TRIVY_MSG_RE), ("osv", OSV_MSG_RE)]
 
 
@dataclass
class EvaluationResult:
    gate_failed: bool
    console_table: str
 
 
def evaluate(merged_path):
    sarif = json.load(open(merged_path))
    findings = {}
 
    for name, msg_re in RUN_PATTERNS:
        run = next(r for r in sarif["runs"] if name in r["tool"]["driver"]["name"].lower())
        rules = run["tool"]["driver"].get("rules", [])
        scores = {r["id"]: r.get("properties", {}).get("security-severity") for r in rules}
 
        for res in run.get("results", []):
            m = msg_re.search(res["message"]["text"])
            if not m:
                continue
            cve_id, (package, version) = res["ruleId"], m.groups()
            score = scores.get(cve_id)
            score = float(score) if score is not None else None
            findings[(cve_id, package, version)] = (cve_id, score, package, version)
 
    rows = []
    for cve_id, score, package, version in findings.values():
        if score is None or score < 5:
            continue
        flag = "FAIL" if score >= 8 else "WARN"
        rows.append([cve_id, score, package, version, flag])
 
    table = tabulate(rows, headers=["ID", "Score", "Package", "Version", "Flag"], tablefmt="fancy_grid")
    gate_failed = any(r[4] == "FAIL" for r in rows)
 
    return EvaluationResult(gate_failed=gate_failed, console_table=table)

def main():
    result = evaluate("microsoft_merged-SCA-report.sarif")
    print(result.console_table)
    
if __name__ == "__main__":
    main()
 