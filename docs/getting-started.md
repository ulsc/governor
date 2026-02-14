# Getting Started with Governor

Governor is a CLI tool for security-auditing AI-generated applications. It runs a mix of AI-powered and deterministic rule-based checks against your source code, then produces detailed reports in Markdown, JSON, and HTML.

This guide walks you through installation, your first audit, and understanding the output.

## Prerequisites

- **An AI provider** configured (for AI-powered checks) -- see [Configuration](./configuration.md) for details
- `codex` CLI in your `PATH` if using the default `codex-cli` provider

> Rule-based checks (hardcoded credentials, command injection patterns, etc.) run without any AI provider and work fully offline.

## Installation

### Install script (recommended)

The fastest way to install Governor is with the install script:

```bash
curl -fsSL https://governor.sh/install.sh | bash
```

This detects your platform, downloads the latest release, verifies the checksum, and installs the binary. You can override the install directory:

```bash
INSTALL_DIR=/opt/bin curl -fsSL https://governor.sh/install.sh | bash
```

Supported platforms: Linux (amd64, arm64), macOS (amd64, arm64), Windows (amd64 via WSL/Git Bash/MSYS2).

### Build from source

> Requires **Go 1.22+** ([download](https://go.dev/dl/))

```bash
git clone <repo-url>
cd governor
make build
```

This produces a binary at `./bin/governor`.

### Install to your PATH

```bash
make install
```

This copies the binary to `~/.local/bin/governor`. Make sure `~/.local/bin` is in your `PATH`.

### Verify the installation

```bash
governor version
```

You should see the installed version (e.g. `governor v0.1.0`). You can also run `governor help` to see the full usage summary.

## Your First Audit

### 1. Initialize the workspace (optional)

Run `governor init` inside your repository to scaffold the `.governor/` directory:

```bash
governor init
```

This creates:
- `.governor/checks/` for custom check definitions
- `.governor/.gitignore` to keep runs out of version control
- `.governor/config.yaml` with commented defaults you can customize

This step is optional — Governor creates the `runs/` directory automatically when you run an audit. But initializing upfront gives you a config file and checks directory ready for team use.

If you want to set an AI profile at init time:

```bash
governor init --ai-profile openai
```

### 2. Run an audit

Point Governor at any source folder or `.zip` archive:

```bash
governor audit ./my-app
```

That's it. Governor will:

1. **Stage** a filtered workspace -- copying only source files and skipping binaries, `node_modules`, `vendor`, `.git`, symlinks, and other non-source content.
2. **Select checks** -- loading the 10 built-in checks (3 AI-powered, 7 rule-based) plus any custom checks you've defined.
3. **Execute** checks in parallel (up to 3 workers by default).
4. **Generate reports** with deduplicated findings.

### 3. Watch progress

If you're running in an interactive terminal, Governor displays a live TUI showing worker status, durations, and events. In non-interactive environments (CI, pipes), it falls back to plain log output.

You can control this explicitly:

```bash
# Force the TUI on
governor audit ./my-app --tui

# Force plain output (useful for CI)
governor audit ./my-app --no-tui
```

### 4. Review the summary

When the audit completes, Governor prints a summary to stdout:

```
run id:         a1b2c3d4-5678-90ab-cdef-1234567890ab
artifacts dir:  ./.governor/runs/20260214-103000/
audit markdown: ./.governor/runs/20260214-103000/audit.md
audit json:     ./.governor/runs/20260214-103000/audit.json
audit html:     ./.governor/runs/20260214-103000/audit.html
checks:         10 (builtin=10 custom=0)
check engines:  ai=5 rule=5
findings:       7 (critical=1 high=3 medium=2 low=0 info=1)
worker appsec                  status=completed  findings=2 duration=45000ms
worker deps_supply_chain       status=completed  findings=1 duration=32000ms
worker secrets_config          status=completed  findings=1 duration=38000ms
worker prompt_injection        status=completed  findings=0 duration=120ms
worker hardcoded_credentials   status=completed  findings=2 duration=85ms
worker command_injection       status=completed  findings=1 duration=60ms
...
```

## Understanding the Output

All artifacts are written to `./.governor/runs/<timestamp>/` by default. You can customize this with `--out`:

```bash
governor audit ./my-app --out ./my-audit-results
```

### Output files

| File | Purpose |
|------|---------|
| `audit.md` | Human-readable Markdown report with all findings, evidence, and remediation guidance |
| `audit.json` | Machine-readable JSON for automation, CI gates, and integrations |
| `audit.html` | Standalone HTML report for sharing with stakeholders |
| `audit.sarif` | SARIF v2.1.0 export for GitHub Code Scanning integration |
| `manifest.json` | List of all files that were included in the audit workspace |
| `worker-<check-id>.log` | Raw execution log for each check worker |
| `worker-<check-id>-output.json` | Structured output from each check worker |
| `workspace/` | Staged source files (deleted by default; kept on warning/failed runs with `--keep-workspace-error`) |

### Anatomy of a finding

Each finding in the report includes:

- **title** -- what was found
- **severity** -- `critical`, `high`, `medium`, `low`, or `info`
- **category** -- classification like `auth`, `secrets`, `rce`, `crypto`, etc.
- **evidence** -- specific code or configuration that triggered the finding
- **impact** -- what could go wrong if this isn't addressed
- **remediation** -- concrete steps to fix the issue
- **file_refs** -- which files are affected
- **confidence** -- 0 to 1 score indicating detection certainty
- **source_track** -- which check produced this finding

### Example finding (from audit.json)

```json
{
  "title": "Hardcoded API key or token detected",
  "severity": "critical",
  "category": "secrets",
  "evidence": "api_key = \"sk-abc123...\" in config/settings.py:14",
  "impact": "Exposed API keys can be used by attackers to access your services and incur costs",
  "remediation": "Use environment variables or a secrets vault to store API keys. Rotate any exposed keys immediately.",
  "file_refs": ["config/settings.py"],
  "confidence": 0.8,
  "source_track": "hardcoded_credentials"
}
```

## Built-in Checks

Governor ships with 10 built-in checks that run by default:

### AI-powered checks (require an AI provider)

| Check ID | Name | Focus |
|----------|------|-------|
| `appsec` | Application Security | Auth flaws, input validation, data exposure, RCE paths |
| `deps_supply_chain` | Dependencies and Supply Chain | Risky deps, lockfile hygiene, CI/CD supply chain |
| `secrets_config` | Secrets and Security Configuration | Hardcoded secrets, insecure defaults, missing headers |
| `ssrf` | Server-Side Request Forgery | User-controlled URLs passed to server-side HTTP clients |
| `missing_rate_limiting` | Missing Rate Limiting | Sensitive endpoints without throttling |
| `insecure_deserialization` | Insecure Deserialization | Unsafe deserialization of untrusted data |

### Rule-based checks (no AI required, fully offline)

| Check ID | Name | Focus |
|----------|------|-------|
| `prompt_injection` | Prompt Injection Signals | Prompt override and jailbreak phrases |
| `hardcoded_credentials` | Hardcoded Credentials | Passwords, API keys, tokens in source |
| `command_injection` | Command Injection Patterns | OS command injection via string interpolation |
| `path_traversal` | Path Traversal Patterns | Directory traversal via user input |
| `insecure_crypto` | Insecure Cryptography | Weak algorithms (MD5, SHA-1, DES, ECB mode) |

## Running Only Rule-Based Checks (No AI)

If you don't have an AI provider configured, you can still audit using only the deterministic rule-based checks:

```bash
# Run only rule-based checks by specifying them
governor audit ./my-app \
  --only-check prompt_injection \
  --only-check hardcoded_credentials \
  --only-check command_injection \
  --only-check path_traversal \
  --only-check insecure_crypto
```

These checks use pattern matching (contains/regex) and require no network access or API keys.

## Filtering Checks

You can control which checks run:

```bash
# Run only a specific check
governor audit ./my-app --only-check appsec

# Skip specific checks
governor audit ./my-app --skip-check deps_supply_chain --skip-check ssrf

# Run only built-in checks (ignore custom checks)
governor audit ./my-app --no-custom-checks
```

## CI/CD Integration Quick Start

Use `--fail-on` to set an exit-code threshold for your pipeline:

```bash
# Fail if any critical or high severity findings exist
governor audit ./my-app --fail-on high --no-tui

# Fail on any finding at all
governor audit ./my-app --fail-on info --no-tui
```

The exit code is non-zero when findings meet or exceed the specified severity, making it easy to gate deployments.

## Next Steps

- [Configuration](./configuration.md) -- set up AI profiles, layered config files, and tune audit behavior
- [Check Authoring](./checks/authoring.md) -- create custom checks for your organization's security policies
- [Check Templates](./checks/templates.md) -- start from pre-built templates
- [Check Reference](./checks/reference.md) -- full schema reference for check definitions
