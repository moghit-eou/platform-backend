## SCA Pipeline

Security scanning is automated via GitHub Actions on every pull request.

### Tools
- **Trivy** - filesystem and container scanning
- **OWASP Dependency Check** - Maven dependency scanning against NVD
- **OSV Scanner** - coming soon

- The tools should exist with either [ 0 , 1 ] in other code , Tools is not working 
check the link of osv-scanner https://google.github.io/osv-scanner/output/#return-codes