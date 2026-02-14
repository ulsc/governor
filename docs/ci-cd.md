# CI/CD Integration

Governor is designed for automated pipelines. In non-interactive environments (CI runners, piped shells), it automatically disables the TUI and outputs plain progress logs to stderr.

## Quick Reference

| Flag | Purpose |
|------|---------|
| `--fail-on <severity>` | Exit non-zero when findings meet/exceed severity |
| `--baseline <path>` | Compare against a previous `audit.json` for diff |
| `--no-tui` | Force plain output (auto-detected in CI) |
| `--out <dir>` | Custom output directory for artifacts |
| `--no-custom-checks` | Run built-in checks only |
| `--only-check <id>` | Run only specific check IDs (repeatable) |
| `--skip-check <id>` | Skip specific check IDs (repeatable) |
| `--workers <1-3>` | Concurrent worker count (default 3) |

## Exit Codes

Governor exits `0` on success. When `--fail-on` is set, it exits non-zero if any finding meets or exceeds the given severity threshold.

```bash
# Fail the pipeline on high or critical findings
governor audit ./app --fail-on high

# Fail on any finding at all
governor audit ./app --fail-on info
```

Severity levels from most to least severe: `critical`, `high`, `medium`, `low`, `info`.

## GitHub Actions

### Basic Audit Workflow

```yaml
name: Security Audit

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  audit:
    name: Governor Audit
    runs-on: ubuntu-24.04

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.22'
          cache: true

      - name: Install Governor
        run: go install github.com/your-org/governor@latest

      - name: Run audit
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          governor audit . \
            --ai-profile openai \
            --ai-auth-mode api-key \
            --fail-on high \
            --out .governor/runs/ci

      - name: Upload audit artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: governor-audit-${{ github.sha }}
          path: .governor/runs/ci/
          retention-days: 30
```

### PR Diff with Baseline Comparison

Use `--baseline` to compare the current audit against a previous run. This is useful for tracking regressions in pull requests -- only new findings cause failures.

```yaml
name: Security Audit (PR Diff)

on:
  pull_request:

permissions:
  contents: read

jobs:
  audit:
    name: Governor PR Audit
    runs-on: ubuntu-24.04

    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.22'
          cache: true

      - name: Install Governor
        run: go install github.com/your-org/governor@latest

      - name: Run baseline audit on main
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          git checkout origin/main -- . 2>/dev/null || true
          governor audit . \
            --ai-profile openai \
            --ai-auth-mode api-key \
            --out .governor/runs/baseline
          git checkout - -- . 2>/dev/null || true

      - name: Run PR audit with diff
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          governor audit . \
            --ai-profile openai \
            --ai-auth-mode api-key \
            --baseline .governor/runs/baseline/audit.json \
            --fail-on high \
            --out .governor/runs/pr

      - name: Upload audit artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: governor-audit-diff-${{ github.sha }}
          path: .governor/runs/pr/
          retention-days: 30
```

The diff report is written to `audit-diff.json` in the output directory and contains `new`, `fixed`, and `unchanged` finding arrays with a `summary` object.

### SARIF Upload for GitHub Code Scanning

Governor automatically generates a SARIF v2.1.0 file (`audit.sarif`) with every audit run. Upload it to GitHub Code Scanning to see findings as annotations on PRs and in the Security tab.

```yaml
name: Security Audit (SARIF)

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  audit:
    name: Governor Audit + SARIF
    runs-on: ubuntu-24.04

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.22'
          cache: true

      - name: Install Governor
        run: go install github.com/your-org/governor@latest

      - name: Run audit
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          governor audit . \
            --ai-profile openai \
            --ai-auth-mode api-key \
            --out .governor/runs/ci

      - name: Upload SARIF to GitHub
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: .governor/runs/ci/audit.sarif

      - name: Upload audit artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: governor-audit-${{ github.sha }}
          path: .governor/runs/ci/
          retention-days: 30
```

The SARIF upload requires `security-events: write` permission. Findings appear as code scanning alerts in the repository's Security tab and as PR annotations.

### Rule-Only Audit (No AI Key Required)

If you only need deterministic rule checks (no AI calls), you can run without an API key:

```yaml
      - name: Run rule-only audit
        run: |
          governor audit . \
            --only-check prompt-injection-local \
            --fail-on high \
            --out .governor/runs/ci
```

Rule-engine checks (`engine: rule`) execute locally with no network or model calls.

## GitLab CI

```yaml
security-audit:
  stage: test
  image: golang:1.22
  variables:
    OPENAI_API_KEY: $OPENAI_API_KEY
  script:
    - go install github.com/your-org/governor@latest
    - governor audit .
        --ai-profile openai
        --ai-auth-mode api-key
        --fail-on high
        --out .governor/runs/ci
  artifacts:
    paths:
      - .governor/runs/ci/
    expire_in: 30 days
    when: always
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == "main"'
```

For SARIF integration with GitLab, export `audit.sarif` as an artifact and consume it in your security dashboard or upload via the GitLab SAST report format.

## Config File for CI Defaults

Instead of passing many flags, create `.governor/config.yaml` in your repo:

```yaml
ai_profile: openai
ai_auth_mode: api-key
fail_on: high
workers: 2
execution_mode: host
```

Governor loads config from two layers (repo-local takes precedence):
1. `~/.governor/config.yaml` (global)
2. `./.governor/config.yaml` (repo-local)

CLI flags always override config file values.

## Custom Checks in CI

Commit your custom checks to `.governor/checks/` in the repository. They are automatically loaded by Governor during audits.

```bash
# Validate checks before running the audit
governor checks validate
governor checks doctor --strict

# Run the audit (picks up repo-local custom checks)
governor audit .
```

Use `--no-custom-checks` to run only built-in checks, or `--only-check <id>` to target specific checks.

## Isolated Runs in CI

For maximum isolation, run Governor inside a disposable container:

```yaml
      - name: Build isolation image
        run: make build-isolation-image IMAGE=governor-runner:local

      - name: Run isolated audit
        run: |
          governor isolate audit . \
            --runtime docker \
            --network unrestricted \
            --pull never \
            --image governor-runner:local \
            --fail-on high \
            --out .governor/runs/ci
```

The container mounts your source read-only and writes output to the host output directory. See the main README for full isolated run documentation.

## Artifact Management

Every audit run produces artifacts in the output directory (default `.governor/runs/<timestamp>/`):

| File | Purpose |
|------|---------|
| `audit.json` | Machine-readable full report |
| `audit.md` | Human-readable markdown report |
| `audit.html` | Standalone HTML report |
| `audit.sarif` | SARIF v2.1.0 for code scanning tools |
| `audit-diff.json` | Baseline comparison (when `--baseline` is used) |
| `manifest.json` | Input file manifest |
| `worker-<id>.log` | Per-check worker logs |
| `worker-<id>-output.json` | Per-check raw output |

In CI, always upload the entire output directory as an artifact with `if: always()` so you can inspect results even on failure. Keep `.governor/.gitignore` tracked so `runs/` artifacts stay out of version control.
