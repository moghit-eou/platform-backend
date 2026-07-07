import subprocess
import os
import sys
import logging
import json
from parse_sarif import evaluate

GREEN = '\033[92m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
YELLOW = '\033[93m'

logging.basicConfig(
    level=logging.INFO,
    format='%(message)s'  # Clean format to prevent double-timestamps in CI logs
)
logger = logging.getLogger("sca-orchestrator")

# Configurable values, no longer hardcoded below 
SBOM_PATH = os.getenv("SBOM_PATH", "target/bom.json")
TRIVY_IGNOREFILE = os.getenv("TRIVY_IGNOREFILE", ".github/scripts/suppress_trivy.yaml")
OSV_IGNOREFILE = os.getenv("OSV_IGNOREFILE", ".github/scripts/suppress_osv_scanner.toml")
TRIVY_SARIF_OUTPUT = os.getenv("TRIVY_SARIF_OUTPUT", "trivy-app.sarif")
OSV_SARIF_OUTPUT = os.getenv("OSV_SARIF_OUTPUT", "osv-scanner-app.sarif")
MERGED_SARIF_OUTPUT = os.getenv("MERGED_SARIF_OUTPUT", "merged-SCA-platform-backend-app.sarif")


def run_trivy():
    cmd = [
        "trivy", "sbom",
        SBOM_PATH,
        "--format", "sarif",
        "--ignorefile", TRIVY_IGNOREFILE,
        "--output", TRIVY_SARIF_OUTPUT
    ]
    return subprocess.run(cmd).returncode


def run_osv_scanner():
    cmd = [
        "osv-scanner", "scan", "source",
        "--lockfile", SBOM_PATH,
        "--config", OSV_IGNOREFILE,
        "--format", "sarif",
        "--output-file", OSV_SARIF_OUTPUT
    ]
    return subprocess.run(cmd).returncode


def merge_sarifs():
    merged = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [],
    }

    for path in (TRIVY_SARIF_OUTPUT, OSV_SARIF_OUTPUT):
        if not os.path.exists(path):
            logger.warning(f"{path} not found, skipping in merge")
            continue
        with open(path) as f:
            sarif = json.load(f, strict=False)
        merged["runs"].extend(sarif.get("runs", []))

    with open(MERGED_SARIF_OUTPUT, "w") as f:
        json.dump(merged, f)

    logger.info("SARIF files merged successfully.")


def main():
    tools = [run_trivy, run_osv_scanner]

    exit_codes = {}
    for tool in tools:
        exit_codes[tool.__name__] = tool()
        logger.info("-" * 40)

    merge_sarifs()  # combined artifact only, not used for the gate decision

    sarif_files = {"trivy": TRIVY_SARIF_OUTPUT, "osv-scanner": OSV_SARIF_OUTPUT}
    tool_status = {}   # "PASSED" | "WARNING" | "FAILED"
    gate_failed = False

    for name, path in sarif_files.items():
        if not os.path.exists(path):
            logger.error(f"{RED}[!] {name} SARIF file missing, skipping evaluation: {path}{RESET}")
            tool_status[name] = "FAILED, Something is wrong with the tool execution, please check the logs."
            gate_failed = True
            continue

        eval_result = evaluate(path)

        if eval_result.gate_failed:
            tool_status[name] = "FAILED"          # this tool found CVSS >= 8.0
            gate_failed = True
        elif eval_result.gate_warn:
            tool_status[name] = "WARNING"         # this tool found 5.0 <= CVSS < 8.0
        else:
            tool_status[name] = "PASSED"          # this tool found nothing >= 5.0

    logger.info(f"\n{BOLD}========== SCA PIPELINE SUMMARY =========={RESET}")
    for name, status in tool_status.items():
        if status == "PASSED":
            logger.info(f"[{name}]: {GREEN}PASSED{RESET}")
        elif status == "WARNING":
            logger.warning(f"[{name}]: {YELLOW}WARNING (findings between 5.0 and 8.0){RESET}")
        else:
            logger.error(f"[{name}]: {RED}FAILED (CVSS >= 8.0 found){RESET}")
    logger.info(f"{BOLD}=========================================={RESET}\n")

    if gate_failed:
        logger.error(f"{RED}One or more SCA tools failed the gate check.{RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()