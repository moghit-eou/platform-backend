#!/bin/bash
set -e

# Install Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.71.1

# Install OSV Scanner
curl -L https://github.com/google/osv-scanner/releases/download/v2.4.0/osv-scanner_linux_amd64 -o /usr/local/bin/osv-scanner
chmod +x /usr/local/bin/osv-scanner
