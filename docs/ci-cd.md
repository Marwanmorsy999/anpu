# CI/CD Integration

ANPU is designed to be a frictionless addition to your CI/CD pipelines. Because it runs locally and doesn't rely on a cloud backend, you can integrate it easily into GitHub Actions, GitLab CI, or any other runner.

## Configuring for CI Environments

When running ANPU in a CI environment, consider the following flags:
- `--profile standard`: Uses a broader set of checks (including Nuclei templates if available).
- `--fail-on <severity>`: Instructs ANPU to exit with a non-zero status code if vulnerabilities of the specified severity (or higher) are found, breaking the build.
- `--sarif`: Generates a SARIF report, which is the standard format for importing results into platforms like GitHub Code Scanning.

## GitHub Actions Example

Below is a complete, copy-pasteable GitHub Actions workflow. It runs an ANPU scan against a target, fails the build if any `high` or `critical` vulnerabilities are discovered, and uploads the SARIF report for integration into the GitHub Security tab.

### `.github/workflows/scan.yml`

```yaml
name: "ANPU Security Scan"

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]
  schedule:
    - cron: '0 2 * * *' # Daily at 2am

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.22'
          
      - name: Install Nuclei (Optional)
        run: |
          go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
          echo "$HOME/go/bin" >> $GITHUB_PATH
          
      - name: Build ANPU
        run: go build -o anpu ./cmd/anpu
        
      - name: Run ANPU Scan
        # Replace the target URL with your staging or local testing environment
        run: |
          ./anpu scan https://example.com \
            --profile standard \
            --fail-on high \
            --sarif \
            --output ./reports/

      - name: Upload SARIF Report
        if: always() # Upload report even if the scan failed (found vulnerabilities)
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ./reports/anpu-report.sarif
          category: anpu-scan
```

### Graceful Degradation (Nuclei)
Notice that the workflow above installs Nuclei before running ANPU. 
If the Nuclei installation step fails or is removed, ANPU will **not** fail the scan. It gracefully degrades, logs a warning that Nuclei is missing, and proceeds to execute its own internal passive analyzers. This ensures your CI pipeline remains robust even if external dependencies are temporarily unavailable.
