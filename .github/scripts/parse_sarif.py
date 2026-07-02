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
    gate_warn: bool
    console_table: str


def evaluate(sarif_paths):
    """Accepts a single SARIF path (merged, or one tool alone) or a list of paths."""
    if isinstance(sarif_paths, str):
        sarif_paths = [sarif_paths]

    findings = {}  # (cve_id, package) -> [score, version]

    for path in sarif_paths:
        with open(path) as f:
            sarif = json.load(f, strict=False)

        for run in sarif["runs"]:
            driver_name = run["tool"]["driver"].get("name", "").lower()
            msg_re = next((r for name, r in RUN_PATTERNS if name in driver_name), None)
            if msg_re is None:
                continue  # unrecognized tool in this run, skip, don't crash

            rules = run["tool"]["driver"].get("rules", [])
            scores = {r["id"]: r.get("properties", {}).get("security-severity") for r in rules}

            for res in run.get("results", []):
                m = msg_re.search(res["message"]["text"])
                if not m:
                    continue
                cve_id = res["ruleId"]
                package, version = m.groups()
                score = scores.get(cve_id)
                score = float(score) if score is not None else None

                key = (cve_id, package)
                if key not in findings or (score or 0) > (findings[key][0] or 0):
                    findings[key] = [score, version]

    rows = []
    for (cve_id, package), (score, version) in findings.items():
        if score is None or score < 5:
            continue
        flag = "FAIL" if score >= 8 else "WARN"
        rows.append([cve_id, score, package, version, flag])

    table = tabulate(rows, headers=["ID", "Score", "Package", "Version", "Flag"], tablefmt="fancy_grid")
    gate_failed = any(r[4] == "FAIL" for r in rows)
    gate_warn   = any(r[4] == "WARN" for r in rows)

    return EvaluationResult(gate_failed=gate_failed,gate_warn=gate_warn, console_table=table)
