<p align="center">
  <img src="docs/assets/governor_logo.webp" alt="Governor" width="200">
</p>

<h1 align="center">Governor</h1>

<p align="center"><em>Let's make vibe coding safe.</em></p>

<p align="center">
  <a href="https://github.com/ulsc/governor/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/ulsc/governor/ci.yml?branch=main&style=for-the-badge&label=build%20%26%20test" alt="Build & Test"></a>
  <a href="https://github.com/ulsc/governor/actions/workflows/release.yml"><img src="https://img.shields.io/github/actions/workflow/status/ulsc/governor/release.yml?style=for-the-badge&label=release%20artifacts" alt="Release Artifacts"></a>
</p>

Governor is an extensible CLI for security-auditing AI-generated applications.

It's designed to give you:
- repeatable security audits with machine-readable output,
- built-in + organization-specific custom checks,
- a check-extraction workflow from internal security documents,
- terminal-native progress UI while workers run.

License note:
- Governor is released under the **MIT License**.

Disclaimer note:
- Governor is an AI-assisted security tool and may produce incorrect, incomplete, or misleading output.
- You are solely responsible for validating findings and for any security, legal, compliance, or operational decisions made from its output.

## Table of Contents

- [Who It Is For](#who-it-is-for)
- [How It Works](#how-it-works)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Init Command](#init-command)
- [CI/CD](#cicd)
- [Audit Command](#audit-command)
- [Matrix Command](#matrix-command)
- [Policy Command](#policy-command)
- [Isolated Runs](#isolated-runs)
- [Checks Command](#checks-command)
- [Scan Command](#scan-command)
- [Diff Command](#diff-command)
- [Hooks Command](#hooks-command)
- [Ignore File](#ignore-file)
- [Custom Check Format](#custom-check-format)
- [Extractor (Docs to Checks)](#extractor-docs-to-checks)
- [Checks Docs](#checks-docs)
- [TUI and Progress](#tui-and-progress)
- [Output Artifacts](#output-artifacts)
- [License](#license)
- [Disclaimer](#disclaimer)
- [Contributing](#contributing)

## Who It Is For

Governor is built for organizations that receive many source folders/zips and need:
- consistent security review quality,
- audit evidence in markdown + JSON + HTML,
- reusable security policy checks across teams.

## How It Works

1. Intake:
- Accepts a local folder or `.zip`.
- Builds a filtered staging workspace with only allowed source files.
- Applies file-count and byte limits to the staged set before workers run.

2. Check selection:
- Uses built-in checks by default.
- Adds enabled custom checks from `./.governor/checks` and `~/.governor/checks` (repo-local takes precedence on duplicate IDs).
- Supports `engine: ai` and deterministic `engine: rule` check types.

3. Execution:
- Runs checks with bounded concurrency (`--workers`, default `3`).
- `engine: ai` checks execute via the configured AI profile/provider (`--ai-profile`, `--ai-provider`).
- For `codex-cli` provider, sandbox behavior is controlled by `--execution-mode` and `--ai-sandbox`.
- `engine: rule` checks execute deterministically without model calls.
- Worker subprocesses run with a constrained environment allowlist.
- AI binaries are resolved and attested only when selected checks require `codex-cli`.

4. Reporting:
- Merges and de-duplicates findings.
- Writes `audit.md`, `audit.json`, and `audit.html`.

## Quick Start

```bash
# 1) Install
curl -fsSL https://governor.sh/install.sh | bash

# 2) Verify
governor version

# 3) Initialize the .governor/ workspace
governor init

# 4) Run audit on a folder
governor audit /path/to/app

# 5) Initialize a draft custom check from a template
governor checks init \
  --id authz-missing-role-check \
  --template authz-missing-checks \
  --name "Missing role checks"

# 6) Enable it
governor checks enable authz-missing-role-check

# 7) Re-run audit with built-ins + enabled custom checks
governor audit /path/to/app
```

## Installation

### Install script (recommended)

```bash
curl -fsSL https://governor.sh/install.sh | bash
```

Override the install directory:

```bash
INSTALL_DIR=/opt/bin curl -fsSL https://governor.sh/install.sh | bash
```

The script detects your OS and architecture, downloads the latest release binary, verifies the SHA-256 checksum, and installs to `/usr/local/bin` (or `~/.local/bin` if not writable).

Supported platforms: Linux (amd64, arm64), macOS (amd64, arm64), Windows (amd64 via WSL/Git Bash/MSYS2).

### Requirements

- Go `1.22+` (only if building from source)
- `codex` CLI in `PATH` when using `--ai-provider codex-cli`

### Built-in AI Profiles

Governor includes built-in profiles you can select via `--ai-profile`, including:
- `codex`, `codex-api`
- `openai`, `openrouter`, `vercel-ai-gateway`
- `claude`, `gemini`, `minimax`, `chatglm`
- `mistral`, `deepseek`, `grok`, `perplexity`, `huggingface`
- `local-openai` (for local OpenAI-compatible endpoints such as Ollama)

Profiles can be overridden or extended via:
- `~/.governor/ai/profiles.yaml`
- `./.governor/ai/profiles.yaml`

### Build from source

```bash
make build
```

Binary:

```text
./bin/governor
```

### Install to local bin

```bash
make install
```

Default install path:

```text
~/.local/bin/governor
```

## Init Command

```bash
governor init [flags]
```

Scaffolds the `.governor/` workspace in the current repository:

- `.governor/` and `.governor/checks/` directories
- `.governor/.gitignore` (keeps checks in git, ignores runs)
- `.governor/config.yaml` (commented template with sensible defaults)

The command is idempotent — it skips files that already exist unless `--force` is used.

### Flags

- `--force`: overwrite existing files
- `--ai-profile <name>`: set the default AI profile in the generated config

### Examples

```bash
# Initialize with defaults
governor init

# Initialize with a specific AI profile
governor init --ai-profile openai

# Re-initialize, overwriting existing files
governor init --force
```

If run outside a git repository, Governor warns and initializes in the current directory.

## CI/CD

### GitHub Action

The easiest way to run Governor in CI is with the official GitHub Action:

```yaml
name: Security Audit
on: [push, pull_request]

permissions:
  security-events: write

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ulsc/governor-action@v1
        with:
          fail-on: high
```

This installs Governor, runs the audit, uploads SARIF results to GitHub Code Scanning, and saves audit artifacts. See [governor-action](https://github.com/ulsc/governor-action) for full documentation.

### Internal workflows

Governor uses GitHub Actions with two maintained workflows:

- `CI` (`.github/workflows/ci.yml`)
- Trigger: push to `main` and all pull requests.
- Runtime: Go `1.25`.
- Steps: `go test -mod=readonly ./...`, `govulncheck`, and `go build -mod=readonly -o bin/governor .`
- GitHub Actions are pinned to immutable commit SHAs.

- `Release Artifacts` (`.github/workflows/release.yml`)
- Trigger: tags matching `v*` (for example `v0.1.0`).
- Runtime: Go `1.25`.
- Builds cross-platform binaries for:
  - linux/amd64
  - darwin/arm64
- windows/amd64
- Uploads packaged artifacts (`.tar.gz` for linux/macOS, `.zip` for windows) to the workflow run.
- Generates SHA-256 checksum files for release archives.
- Emits build provenance attestations for release artifacts.
- Verifies release tag commits are reachable from `main`.

To trigger release artifacts:

```bash
git tag v0.1.0
git push origin v0.1.0
```

## Audit Command

```bash
governor audit <path-or-zip> [flags]
```

### Important flags

- `--workers <1-3>`: max concurrent worker processes (default `3`)
- `--ai-profile <name>`: AI profile (default `codex`)
- `--ai-provider <name>`: provider override (`codex-cli|openai-compatible`)
- `--ai-model <id>`: model override
- `--ai-auth-mode <mode>`: auth override (`auto|account|api-key`)
- `--ai-base-url <url>`: base URL override for openai-compatible providers
- `--ai-api-key-env <name>`: API key env var override
- `--ai-bin <path>`: AI CLI executable path for `codex-cli` provider
- `--execution-mode <sandboxed|host>`: worker execution mode (default `sandboxed`)
- `--ai-sandbox <mode>`: sandbox mode for sandboxed execution (`read-only` default)
- `--checks-dir <dir>`: custom checks directory override
  - Read defaults (when omitted): `./.governor/checks` + `~/.governor/checks` (repo first)
  - Write defaults for `checks add`/`checks extract` (when omitted): `./.governor/checks` in repo, otherwise `~/.governor/checks`
- `--only-check <id>`: run only specified check IDs (repeatable)
- `--skip-check <id>`: skip specified check IDs (repeatable)
- `--no-custom-checks`: run built-in checks only
- `--quick`: run only rule-engine checks (no AI, no network)
- `--policy <path>`: apply policy file (defaults to `./.governor/policy.yaml` when present)
- `--require-policy`: fail when no policy file can be resolved
- `--changed-only`: scan only files with uncommitted changes (vs HEAD)
- `--changed-since <ref>`: scan only files changed since a git ref (branch, tag, or commit)
- `--staged`: scan only staged files (for pre-commit use)
- `--tui`: force interactive TUI
- `--no-tui`: force plain mode
- `--timeout <duration>`: per-check timeout (default `4m`, set `0` to disable)
- `--out <dir>`: custom output directory
- `--ignore-file <path>`: path to a `.governorignore` file (auto-detected in input root if omitted)
- `--keep-workspace-error`: keep staged `workspace/` only for warning/failed runs (default deletes)

Notes:
- `--quick` and AI flags (`--ai-profile`, etc.) are mutually exclusive.
- `--changed-only`, `--changed-since`, and `--staged` are mutually exclusive. All three require a git repository.

### Examples

```bash
# Built-ins only
governor audit ./my-app --no-custom-checks

# Run only a specific check
governor audit ./my-app --only-check appsec

# Run selected custom check
governor audit ./my-app --only-check authz-missing-role-check

# Quick rule-only scan (no AI, instant)
governor audit ./my-app --quick

# Scan only uncommitted changes
governor audit ./my-app --changed-only

# Scan only changes since a branch point
governor audit ./my-app --changed-since main

# Quick scan of staged files (ideal for pre-commit)
governor audit ./my-app --staged --quick --fail-on high

# Enforce policy-as-code gates
governor audit ./my-app --policy ./.governor/policy.yaml --require-policy
```

## Matrix Command

```bash
governor matrix run [flags]
```

Runs multiple audits from a single matrix file (monorepo-friendly), then writes aggregate summary artifacts.

Flags:
- `--config <path>`: matrix config path (default `./.governor/matrix.yaml`)
- `--out <dir>`: output directory for matrix summaries and target runs
- `--json`: print matrix summary JSON to stdout

Config schema:

```yaml
api_version: governor/matrix/v1
defaults:
  fail_on: high
  ai_profile: codex
  policy: ./.governor/policy.yaml
  require_policy: true
targets:
  - name: api
    path: ./services/api
    quick: true
  - name: web
    path: ./apps/web
    fail_on: medium
aggregation:
  fail_fast: false
  overall_fail_on: high
  require_all_targets: true
```

Notes:
- Target options merge as `defaults` then per-target override.
- Each target runs as an audit subprocess (`governor audit <target.path> --no-tui ...`).
- Matrix writes `matrix-summary.json` and `matrix-summary.md` plus per-target audit artifacts under the matrix output dir.

## Policy Command

```bash
governor policy <validate|explain> [flags]
```

Commands:
- `governor policy validate --file ./.governor/policy.yaml`
- `governor policy explain --file ./.governor/policy.yaml`

Flag:
- `--file <path>`: policy file path (default `./.governor/policy.yaml`)

Example policy:

```yaml
api_version: governor/policy/v1
defaults:
  fail_on_severity: high
  max_suppression_ratio: 0.40
  max_new_findings: 0
  require_checks: [appsec]
rules:
  - name: backend-relaxed
    when:
      paths: ["api/**"]
    enforce:
      fail_on_severity: medium
waivers:
  - id: waiver-123
    reason: accepted risk pending redesign
    expires: "2099-01-01"
    match:
      checks: ["appsec"]
```

Policy behavior:
- `audit` and `ci` accept `--policy` and `--require-policy`.
- If policy is applied, Governor evaluates violations after audit execution.
- Unwaived policy violations fail command exit status (`audit`/`ci`) and are included in `audit.json`, `audit.md`, and `audit.html`.

## Isolated Runs

Run Governor in a disposable container with strict mounts and runtime limits:

```bash
# Optional: build local runner image first
make build-isolation-image IMAGE=governor-runner:local

governor isolate audit ./my-app \
  --runtime auto \
  --network unrestricted \
  --pull never \
  --image governor-runner:local
```

Key behavior:
- Input is mounted read-only (`/input`).
- Output is mounted read/write at a fresh host output directory (`--out` or default `./.governor/runs/<timestamp>`) and mapped to `/output` in-container.
- Container root filesystem is read-only with restricted capabilities.
- Worker execution inside container defaults to host mode (`--execution-mode host`) for reliable repository access.
- If you explicitly choose sandboxed execution, Governor can auto-rerun sandbox-denied tracks in host mode.
- CLI prints final artifact paths using host filesystem paths.

Account auth (no API key):
- `--auth-mode account` (default for `codex-cli`) uses host account state from `~/.codex/auth.json`.
- Governor stages a minimal read-only auth bundle from `--ai-home` into an ephemeral directory and mounts it into the container.
- No write-back is performed to host `--ai-home`.

Useful flags:
- `--auth-mode auto|account|api-key`
- `--ai-home ~/.codex`
- `--ai-profile <name>`
- `--ai-provider codex-cli|openai-compatible`
- `--ai-model <id>`
- `--ai-auth-mode auto|account|api-key`
- `--ai-base-url <url>`
- `--ai-api-key-env <name>`
- `--ai-bin <path>`
- `--runtime auto|docker|podman`
- `--image <runner-image>`
- `--pull always|if-missing|never`
- `--network unrestricted|none`
- `--execution-mode sandboxed|host`
- `--ai-sandbox read-only|workspace-write|danger-full-access`
- `--clean-image`
- `--keep-workspace-error`

Notes:
- `--out` is optional; default is `./.governor/runs/<timestamp>`.
- Isolated defaults are hardened while remaining practical: `--network none`, `--pull never`, `--auth-mode account`, `--execution-mode host`.
- `--network unrestricted` allows normal outbound network for model/tool calls; `none` is fully offline.
- For `codex-cli`, isolated preflight includes endpoint reachability and a short CLI exec probe.
- Worker tracks retryable AI transport failures (for example stream/network disconnects) and emits a fallback non-empty JSON output when retries are exhausted.
- If `--pull` is `always` or `if-missing`, `--image` must be digest pinned (`name@sha256:...`).
- Container runtime/image caches are external to Governor output and may persist unless cleaned (`--clean-image`).
- If you do not have a published runner image, use `Dockerfile.isolate-runner` with `make build-isolation-image`.

### Isolated Troubleshooting

Common diagnostic labels in worker/preflight errors:

- `[infra.tls_trust]`: Runner image CA trust is missing or broken. Rebuild image from `Dockerfile.isolate-runner` and ensure `ca-certificates` are installed.
- `[auth.account]`: Account/API auth is unavailable in the isolated environment. Re-run `codex login` on host or use `--auth-mode api-key`.
- `[infra.network]`: Network/DNS/connectivity issue to AI endpoints.
- `[stream.transient]`: Stream dropped mid-response; Governor retries and may fall back to non-empty JSON output.

## Checks Command

```bash
governor checks [<tui|init|add|extract|list|validate|doctor|explain|enable|disable|lock|update-packs|trust>]
```

Default behavior:
- Interactive terminal: `governor checks` opens the checks workspace TUI.
- Non-interactive shell (CI/pipes): `governor checks` falls back to `governor checks list`.

### `checks tui`

Interactive checks workspace for enterprise operations.

```bash
governor checks
governor checks tui
```

Key actions:
- `j`/`k`: move selection
- `/`: search
- `s`: cycle status filter
- `o`: cycle source filter
- `1..5`: sort by id/status/source/severity/path
- `e` / `d`: enable/disable selected mutable custom check (with confirmation)
- `n`: duplicate selected check as draft
- `p`: show selected check path
- `r`: refresh from disk
- `h`: toggle details pane

### `checks init` (recommended)

Guided/template-based check authoring for production teams.

```bash
# List templates
governor checks init --list-templates

# Non-interactive creation
governor checks init \
  --non-interactive \
  --template authz-missing-checks \
  --id insecure-admin-surface \
  --name "Insecure admin surface"
```

Interactive usage:

```bash
governor checks init
```

By default this writes to:
- `./.governor/checks` when inside a git repo.
- `~/.governor/checks` otherwise.

Key flags:
- `--template <id>`: template ID (`blank`, `authz-missing-checks`, `secrets-handling`, etc.)
- `--overwrite`: replace existing file with same ID
- `--status draft|enabled|disabled`

### `checks add`

Creates a draft check YAML quickly (backward-compatible path).
For new checks, prefer `checks init`.

```bash
governor checks add \
  --id insecure-admin-surface \
  --name "Insecure admin surface" \
  --description "Detect admin endpoints without authorization checks" \
  --instructions "Identify admin routes and verify role/permission checks." \
  --include-glob "**/*.go" \
  --category auth
```

### `checks list`

Lists built-in/custom checks and statuses.

```bash
governor checks list
governor checks list --source custom
governor checks list --status enabled
```

### `checks validate`

Validates check files and duplicate IDs.

```bash
governor checks validate
```

### `checks doctor`

Runs diagnostics on effective and shadowed checks.

```bash
governor checks doctor
governor checks doctor --strict
governor checks doctor --format json
```

Reports:
- invalid YAML/schema issues,
- duplicate/shadowed IDs,
- authoring quality warnings (weak instructions, broad scope, missing scope hints).

### `checks explain`

Explains exactly which check definition is active and why.

```bash
governor checks explain insecure-admin-surface
governor checks explain insecure-admin-surface --format json
```

Shows:
- searched directories,
- effective check file path,
- shadowed alternatives,
- invalid candidates.

### `checks enable` / `checks disable`

```bash
governor checks enable insecure-admin-surface
governor checks disable insecure-admin-surface
```

Default behavior without `--checks-dir`:
- Searches `./.governor/checks` first, then `~/.governor/checks`.
- Enables/disables the first matching check by that precedence.

### `checks trust validate` / `checks trust pin`

Validate or pin check-pack trust policy for taps/lockfile workflows.

```bash
# Validate all locked packs against trust policy and taps
governor checks trust validate --trust-policy ./.governor/check-trust.yaml --strict

# Pin one pack (creates trust policy file if missing)
governor checks trust pin web
```

Trust policy schema:

```yaml
api_version: governor/check-trust/v1
mode: warn # off|warn|strict
trusted_sources:
  - name: acme/checks
    url: https://example.com/acme/checks.git
pinned_packs:
  - pack: web
    source: acme/checks
    version: 1.2.3
    digest: sha256:...
    commit: abcdef123456
requirements:
  require_digest: true
  require_lock_entry: true
  allow_major_updates: false
```

Mode behavior:
- `off`: trust checks never block install/update.
- `warn`: emits warnings/errors but does not block install/update.
- `strict`: blocks install/update when trust errors exist.

Pack install/update integration:
- `governor checks install-pack` and `governor checks update-packs` accept `--trust-policy` and `--strict-trust`.
- `--strict-trust` forces blocking behavior regardless of policy mode.

## Hooks Command

```bash
governor hooks <install|remove|status>
```

Manage a git pre-commit hook that runs Governor automatically on every commit.

### `hooks install`

Installs a pre-commit hook that runs `governor audit --staged --quick --fail-on high`:

```bash
governor hooks install
```

The hook runs rule-engine checks against staged files and blocks the commit if any high-severity findings are detected. This provides instant security feedback without AI calls or network access.

If a pre-commit hook already exists, `install` refuses to overwrite it unless `--force` is passed:

```bash
governor hooks install --force
```

Installing again when the Governor hook is already present is a no-op (idempotent).

### `hooks remove`

Removes the Governor pre-commit hook:

```bash
governor hooks remove
```

Only removes hooks installed by Governor (identified by a marker comment). Refuses to remove hooks not installed by Governor.

### `hooks status`

Shows whether the Governor pre-commit hook is currently installed:

```bash
governor hooks status
```

## Scan Command

```bash
governor scan <file> [file2 ...] [flags]
```

Lightweight single-file scanning that runs rule-engine checks against one or more files and prints findings to stdout. No workspace, no manifest, no output directory -- ideal for quick checks during development.

### Flags

- `--json`: output findings as a JSON array
- `--only-check <id>`: run only specified check IDs (repeatable)
- `--skip-check <id>`: skip specified check IDs (repeatable)
- `--no-custom-checks`: run built-in rule checks only
- `--checks-dir <dir>`: custom checks directory
- `--fail-on <severity>`: exit non-zero if findings meet or exceed severity

### Examples

```bash
# Scan a single file
governor scan config.go

# Scan multiple files
governor scan main.go config.go auth/handler.go

# JSON output for tooling
governor scan --json src/*.go

# Run only credential checks
governor scan --only-check hardcoded_credentials config.go

# Gate on severity (useful in scripts)
governor scan --fail-on high config.go
```

Notes:
- Only accepts files, not directories. Use `governor audit` for directory scanning.
- Runs only `engine: rule` checks (deterministic, no AI, no network).
- Default exit code: 0 = no findings, 1 = findings exist (or `--fail-on` threshold met).

## Diff Command

```bash
governor diff <old.json> <new.json> [flags]
```

Compares two `audit.json` files and reports new, resolved, and unchanged findings. This is useful for tracking security posture changes between audits without running a new audit.

### Flags

- `--json`: output the full diff report as JSON
- `--fail-on <severity>`: exit non-zero if new findings (regressions) meet or exceed severity
- `--out <file>`: write the diff JSON to a file

### Examples

```bash
# Compare two audit reports
governor diff baseline/audit.json latest/audit.json

# JSON output for CI integration
governor diff --json old.json new.json

# Fail CI if there are new high+ findings
governor diff --fail-on high old.json new.json

# Save diff to a file
governor diff --out diff-report.json old.json new.json
```

Notes:
- `--fail-on` applies only to new findings (regressions), not unchanged findings.
- Findings are matched by title + category + file refs + evidence (first 200 chars).

## Ignore File

Governor supports a `.governorignore` file for excluding paths from scanning during intake, using gitignore-style patterns.

### Location

Place a `.governorignore` file in the root of the input being audited. Governor auto-detects it when present. You can also specify an explicit path:

```bash
governor audit ./my-app --ignore-file /path/to/.governorignore
```

### Syntax

```text
# Comments start with #
# Blank lines are ignored

# Glob patterns
*.generated.go
*.min.js

# Directory patterns (trailing slash)
fixtures/
test_data/

# Double-star for recursive matching
**/migrations/**
docs/**/*.pdf

# Negation to re-include
!important.generated.go
```

Rules:
- Lines starting with `#` are comments.
- Patterns without a `/` match against the file basename anywhere in the tree.
- Patterns with a `/` match against the relative path from the input root.
- A trailing `/` matches directories only.
- `!` prefix negates a pattern (re-includes previously excluded paths).
- Last matching pattern wins (standard gitignore semantics).
- If the file is missing, scanning proceeds normally with no exclusions.

Excluded files are tracked in `manifest.json` under the `"governorignore"` skip reason.

## Custom Check Format

Custom checks live in:

```text
./.governor/checks/<id>.check.yaml   # default write target when inside a git repo
~/.governor/checks/<id>.check.yaml   # fallback/global location
```

Load precedence:
- Governor merges both locations and uses repo-local definitions first when duplicate IDs exist.

Example:

```yaml
api_version: governor/v1
id: insecure-admin-surface
name: Insecure admin surface
status: draft # draft | enabled | disabled
source: custom
engine: ai # ai | rule
description: Detect admin endpoints without authorization checks
instructions: |
  Identify admin and privileged routes, then verify role/permission checks
  are present before any sensitive action.
scope:
  include_globs:
    - "**/*.go"
    - "**/*.ts"
  exclude_globs:
    - "**/vendor/**"
    - "**/node_modules/**"
categories_hint:
  - auth
severity_hint: high
confidence_hint: 0.8
origin:
  method: manual # manual | extracted
```

Deterministic rule example:

```yaml
api_version: governor/v1
id: prompt-injection-local
name: Prompt Injection Local Rule
status: enabled
source: custom
engine: rule
description: Detect prompt-injection override phrases in prompt-bearing files.
rule:
  target: file_content
  detectors:
    - id: ignore-previous
      kind: contains
      pattern: ignore previous instructions
      title: Prompt override phrase detected
      category: prompt_injection
      severity: high
      confidence: 0.75
      max_matches: 5
      remediation: Reject prompt content that attempts to override system instructions.
scope:
  include_globs:
    - "**/*.md"
    - "**/*.txt"
```

Behavior:
- `draft`: not executed during audits.
- `enabled`: included in audits.
- `disabled`: ignored.

## Extractor (Docs to Checks)

Generate draft checks from local documents:

```bash
governor checks extract --input ./security-policies --max-checks 10
```

Supported inputs:
- `.md`
- `.txt`
- `.pdf` only with `--allow-pdf` (requires `pdftotext` in `PATH`)

Notes:
- Extracted checks are written as `draft` by default.
- Review and enable only the checks you trust.
- PDF parsing is disabled by default to reduce local parser attack surface.

## Checks Docs

- `docs/checks/authoring.md`: day-1 check creation workflow.
- `docs/checks/templates.md`: template catalog and usage guidance.
- `docs/checks/troubleshooting.md`: resolving common check issues quickly.
- `docs/checks/reference.md`: schema/reference for check fields and behaviors.
- `docs/checks/tui.md`: interactive checks workspace usage and keymap.

## TUI and Progress

- Interactive terminal: TUI is enabled by default.
- Non-interactive (pipe/CI): plain progress logs are used.
- Audit TUI shows worker-level status, durations, error badges, and a filterable/pauseable events panel.
- Controls: `d` toggle details, `p` pause/resume events panel, `f` cycle event-track filter, `q` close when run completes.

## Output Artifacts

Default output directory:

```text
./.governor/runs/<timestamp>/
```

Contents:

```text
audit.md
audit.json
audit.html
manifest.json
worker-output-schema.json
worker-<check-id>.log
worker-<check-id>-output.json
workspace/                 # deleted by default; kept for warning/failed runs with --keep-workspace-error
```

`audit.json` is intended for automation. `audit.md` and `audit.html` are intended for humans. The HTML report is interactive -- it includes severity/category/check filtering, text search, collapsible finding cards, and a dark mode toggle.

When policy is enabled (`--policy`), audit artifacts also include a `policy_decision` section with violations and waiver status.

Matrix runs additionally write:

```text
matrix-summary.json
matrix-summary.md
<target-name>/audit.{json,md,html}
```

Git hygiene:
- Keep `.governor/.gitignore` tracked so `runs/` artifacts stay out of git while `.governor/checks/` can be versioned.

## License

This project is licensed under the **MIT License**.

See `LICENSE` for full legal terms.

## Disclaimer

Governor is provided on an "as is" and "as available" basis.

- It is an AI-assisted tool and can produce false positives, false negatives, incomplete analysis, or incorrect recommendations.
- It does not provide legal, compliance, or professional security assurance.
- You are solely responsible for independently validating all output before acting on it.
- By using Governor, you accept full responsibility for outcomes related to its use, including security, compliance, data handling, and operational impact.
- The maintainers and contributors disclaim liability for any direct, indirect, incidental, special, consequential, or exemplary damages arising from use of the tool or reliance on its output.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
