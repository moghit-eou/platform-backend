import subprocess
import os
import sys
import logging
import json 

GREEN = '\033[92m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'

logging.basicConfig(
    level=logging.INFO,
    format='%(message)s' # Clean format to prevent double-timestamps in CI logs
)
logger = logging.getLogger("sca-orchestrator")

def run_trivy():
    cmd = [
        "trivy", "sbom",
        "target/bom.json",
        "--format", "sarif",
        "--output", "trivy.sarif",
      #  "--severity", "CRITICAL,HIGH",
       # "--exit-code", "1"
    ]
    
    return subprocess.run(cmd).returncode

def run_osv_scanner():
    cmd = [
        "osv-scanner", "scan", "source",
        "--lockfile", "target/bom.json",
        #"--config", ".github/scripts/osv-scanner.toml",
        "--format", "sarif",
        "--output-file", "osv-scanner.sarif",
    ]
    
    return subprocess.run(cmd).returncode

def merge_sarifs_microsoft():
    cmd = [
        "npx", "@microsoft/sarif-multitool", "merge",
        "osv-scanner.sarif", "trivy.sarif",
        "--output-file", "microsoft_merged-SCA-report.sarif"
    ]
    
    result = subprocess.run(cmd)
    
    if result.returncode != 0:
        logger.warning("Failed to merge SARIF files, continuing pipeline.")
    else:
        logger.info("SARIF files merged successfully.")

def merge_sarifs():
    sarif_files = ["trivy.sarif", "osv-scanner.sarif"]
    runs = []

    for file in sarif_files:
        with open(file) as f:
            runs.extend(json.load(f).get("runs", []))

    with open("merged-SCA-report.sarif", "w") as f:
        json.dump({"version": "2.1.0", "runs": runs}, f)

    logger.info("SARIF files merged successfully.")

def main():
    
    tools = [run_trivy, run_osv_scanner]

    failed_ci = False

    results = {}

    for tool in tools:
        code = tool()
        results[tool.__name__] = code

        if code and code != 0:
            logger.error(f"{RED}[!] Tool {tool.__name__} failed with exit code {code}{RESET}")
            failed_ci = True
        logger.info("-" * 40)


    merge_sarifs()
    merge_sarifs_microsoft()

    logger.info(f"\n{BOLD}========== SCA PIPELINE SUMMARY =========={RESET}")
    for tool_name, code in results.items():
        if code == 0:
            logger.info(f"[{tool_name}]: {GREEN}PASSED{RESET}")
        else:
            logger.error(f"[{tool_name}]: {RED}FAILED (Exit Code {code}){RESET}")
    logger.info(f"{BOLD}=========================================={RESET}\n")

    if failed_ci:
        logger.error(f"{RED}Pipeline blocked due to security findings.{RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()
 