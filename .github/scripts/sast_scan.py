import subprocess
import os
import sys
import logging
import shlex

GREEN = '\033[92m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'
YELLOW = '\033[93m'

logging.basicConfig(
    level=logging.INFO,
    format='%(message)s'  # Clean format to prevent double-timestamps in CI logs
)
logger = logging.getLogger("sast-orchestrator")

# --- Configurable values -----------------------------------------------
SEMGREP_CONFIGS = os.getenv("SEMGREP_CONFIGS", "p/security-audit p/owasp-top-ten p/cwe-top-25 p/trailofbits").split()
SEMGREP_EXCLUDE = os.getenv(
    "SEMGREP_EXCLUDE",
    ".github Dockerfile* target/** dist/** build/** node_modules/** .angular/**"
).split()

SEMGREP_SARIF_OUTPUT = os.getenv("SEMGREP_SARIF_OUTPUT", "sast-semgrep-app.sarif")
SAST_SEVERITY = os.getenv("SAST_SEVERITY", "ERROR")  # ERROR | WARNING | INFO
SAST_ENFORCE = os.getenv("SAST_ENFORCE", "false").lower() == "true"


def run_semgrep():
    cmd = ["opengrep", "scan"]

    for config in SEMGREP_CONFIGS:
        cmd += ["--config", config]

    for pattern in SEMGREP_EXCLUDE:
        cmd += ["--exclude", pattern]

    cmd += [f"--severity={SAST_SEVERITY}"]

    if SAST_ENFORCE:
        cmd += ["--error"]  # non-zero exit when blocking-severity findings exist

    cmd += ["--sarif", "--output", SEMGREP_SARIF_OUTPUT]

    logger.info(f"{BOLD}Running:{RESET} {' '.join(shlex.quote(c) for c in cmd)}")
    return subprocess.run(cmd).returncode


def main():
    logger.info(f"{BOLD}Initiating SAST pipeline "
                f"({'ENFORCE' if SAST_ENFORCE else 'AUDIT/non-blocking'} mode){RESET}")

    exit_code = run_semgrep()
    logger.info("-" * 40)

    if exit_code == 0:
        status = "PASSED"
    elif exit_code == 1:
        status = "FAILED"
    else:
        status = "ERROR"

    if not os.path.exists(SEMGREP_SARIF_OUTPUT):
        logger.error(f"{RED}[!] semgrep SARIF missing: {SEMGREP_SARIF_OUTPUT}, tool failed to run{RESET}")
        status = "ERROR"

    logger.info(f"\n{BOLD}========== SAST PIPELINE SUMMARY =========={RESET}")
    if status == "PASSED":
        logger.info(f"[semgrep]: {GREEN}PASSED (exit code 0){RESET}")
    elif status == "FAILED":
        logger.error(f"[semgrep]: {RED}FAILED (exit code 1 - {SAST_SEVERITY}-severity findings){RESET}")
    else:
        logger.error(f"[semgrep]: {RED}ERROR (exit code {exit_code}, tool did not run correctly){RESET}")
    logger.info(f"{BOLD}==========================================={RESET}\n")

    if status == "ERROR":
        sys.exit(1)

    if SAST_ENFORCE and status == "FAILED":
        logger.error(f"{RED}SAST gate failed: blocking-severity findings present.{RESET}")
        sys.exit(1)

    if status == "FAILED":
        logger.warning(f"{YELLOW}Audit mode: findings present but not blocking the pipeline.{RESET}")


if __name__ == "__main__":
    main()