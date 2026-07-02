import json
import re
from dataclasses import dataclass

TRIVY_MSG_RE = re.compile(r"Package:\s*(\S+)\nInstalled Version:\s*(\S+)")
OSV_MSG_RE = re.compile(r"Package\s+'([^@']+)@([^']+)'")
RUN_PATTERNS = [("trivy", TRIVY_MSG_RE), ("osv", OSV_MSG_RE)]


@dataclass
class EvaluationResult:
    gate_failed: bool
    gate_warn: bool


def evaluate(sarif_paths):
    """Accepts a single SARIF path (merged, or one tool alone) or a list of paths."""
    if isinstance(sarif_paths, str):
        sarif_paths = [sarif_paths]

    findings = {}  # (cve_id, package) -> score

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
                package, _version = m.groups()
                score = scores.get(cve_id)
                score = float(score) if score is not None else None

                key = (cve_id, package)
                if key not in findings or (score or 0) > (findings[key] or 0):
                    findings[key] = score

    return EvaluationResult(
        gate_failed=any(s is not None and s >= 8 for s in findings.values()),
        gate_warn=any(s is not None and 5 <= s < 8 for s in findings.values()),
    )