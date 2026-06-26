import subprocess
import os
import sys


# TODO: Add structured logging 



def run_trivy():
    cmd = [
        "trivy", "fs", ".", 
        "--format", "sarif", 
        "--output", "trivy.sarif", 
        "--exit-code", "1", 
        "--severity", "CRITICAL,HIGH"] 
    
    result = subprocess.run(cmd)
    
    # TODO: Handle the result of the Trivy scan, check for vulnerabilities.

    return result.returncode

def run_osv_scanner():
    # TODO: Implement OSV scanning logic here
    pass

def run_dependency_check():
    nvd_api_key = os.getenv("NVD_API_KEY")

    if not nvd_api_key:
            print(" == NVD_API_KEY is empty or missing")
            return 1

    cmd = [
        "mvn", "org.owasp:dependency-check-maven:12.2.2:check",
        "-DnvdDatafeedUrl=https://dependency-check.github.io/DependencyCheck_Builder/nvd_cache/",
        "-Dformat=SARIF",
        "-DfailBuildOnCVSS=7",
        "-DoutputDirectory=.",
    ]

    result = subprocess.run(cmd)
    return result.returncode

def main():
    
    tools = [run_trivy, run_osv_scanner, run_dependency_check]

    failed_ci = False

    for tool in tools:
        code = tool()

        if code and code != 0:
            failed_ci = True
    
    if failed_ci:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()
 