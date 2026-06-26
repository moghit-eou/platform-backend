import subprocess
import os
import sys


# TODO: Add structured logging 



def run_trivy():
    cmd = [
        "trivy", "fs", ".", 
        "--format", "sarif", 
        "--output", "trivy.sarif"
        #"--exit-code", "1", 
        #"--severity", "CRITICAL,HIGH"
        ] 
    
    result = subprocess.run(cmd)
    
    # TODO: Handle the result of the Trivy scan, check for vulnerabilities.

    return result.returncode

def run_osv_scanner():
    # TODO: Implement OSV scanning logic here
    pass

def run_dependency_check():

    cmd = [
        "mvn", "org.owasp:dependency-check-maven:12.2.2:check",
        "-DnvdDatafeedUrl=https://dependency-check.github.io/DependencyCheck_Builder/nvd_cache/",
        "-Dformat=SARIF",
        "-DfailBuildOnCVSS=11",
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
            print(f"Tool {tool.__name__} failed with exit code {code}")
            failed_ci = True
    
    if failed_ci:
        print("One or more tools failed. Exiting with code 1.")
        sys.exit(1)
    else:
        print ("All tools completed successfully.")
        sys.exit(0)

if __name__ == "__main__":
    main()
 