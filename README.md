# Governor

[![Build & Test](https://img.shields.io/github/actions/workflow/status/OWNER/REPO/ci.yml?branch=main&style=for-the-badge&label=build%20%26%20test)](https://github.com/OWNER/REPO/actions/workflows/ci.yml)
[![Release Artifacts](https://img.shields.io/github/actions/workflow/status/OWNER/REPO/release.yml?style=for-the-badge&label=release%20artifacts)](https://github.com/OWNER/REPO/actions/workflows/release.yml)

Governor is an extensible CLI for security-auditing AI-generated applications.

It is designed for teams with many “Citizen Developer” apps and gives you:
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
- [CI/CD](#cicd)
- [Audit Command](#audit-command)
- [Isolated Runs](#isolated-runs)
- [Checks Command](#checks-command)
- [Custom Check Format](#custom-check-format)
- [Extractor (Docs to Checks)](#extractor-docs-to-checks)
- [Checks Docs](#checks-docs)
- [TUI and Progress](#tui-and-progress)
- [Output Artifacts](#output-artifacts)
- [Security and Safety](#security-and-safety)
- [Architecture](#architecture)
- [Roadmap](#roadmap)
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

3. Execution:
- Runs checks with bounded concurrency (`--workers`, default `3`).
- Each check executes with sandboxed Codex mode by default (`--execution-mode sandboxed`).
- Worker subprocesses run with a constrained environment allowlist.
- Codex binary is resolved to a canonical path and attested (version + sha256) at startup.

4. Reporting:
- Merges and de-duplicates findings.
- Writes `audit.md`, `audit.json`, and `audit.html`.

## Quick Start

```bash
# 1) Build
make build

# 2) Run audit on a folder
./bin/governor audit /path/to/app

# 3) Initialize a draft custom check from a template
./bin/governor checks init \
  --id authz-missing-role-check \
  --template authz-missing-checks \
  --name "Missing role checks"

# 4) Enable it
./bin/governor checks enable authz-missing-role-check

# 5) Re-run audit with built-ins + enabled custom checks
./bin/governor audit /path/to/app
```

## Installation

### Requirements

- Go `1.22+`
- `codex` CLI in `PATH`

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

## CI/CD

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

Badge note:
- Replace `OWNER/REPO` in the badge URLs above with your actual GitHub org/user and repository name.

## Audit Command

```bash
governor audit <path-or-zip> [flags]
```

### Important flags

- `--workers <1-3>`: max concurrent worker processes (default `3`)
- `--execution-mode <sandboxed|host>`: worker execution mode (default `sandboxed`)
- `--codex-sandbox <mode>`: Codex sandbox for sandboxed mode (`read-only` default)
- `--checks-dir <dir>`: custom checks directory override
  - Read defaults (when omitted): `./.governor/checks` + `~/.governor/checks` (repo first)
  - Write defaults for `checks add`/`checks extract` (when omitted): `./.governor/checks` in repo, otherwise `~/.governor/checks`
- `--only-check <id>`: run only specified check IDs (repeatable)
- `--skip-check <id>`: skip specified check IDs (repeatable)
- `--no-custom-checks`: run built-in checks only
- `--tui`: force interactive TUI
- `--no-tui`: force plain mode
- `--timeout <duration>`: per-check timeout (default `4m`)
- `--out <dir>`: custom output directory
- `--keep-workspace-error`: keep staged `workspace/` only for warning/failed runs (default deletes)

### Examples

```bash
# Built-ins only
governor audit ./my-app --no-custom-checks

# Run only a specific check
governor audit ./my-app --only-check appsec

# Run selected custom check
governor audit ./my-app --only-check authz-missing-role-check
```

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
- Worker execution inside container defaults to host mode (`--execution-mode host`) for reliable repository access with current Codex sandbox behavior.
- If you explicitly choose sandboxed execution, Governor can auto-rerun sandbox-denied tracks in host mode.
- CLI prints final artifact paths using host filesystem paths.

Subscription auth (no API key):
- `--auth-mode subscription` (default) requires host Codex subscription state.
- Governor stages a minimal read-only auth bundle from `~/.codex` (`auth.json`) into an ephemeral directory and mounts it into the container.
- No write-back is performed to host `~/.codex`.

Useful flags:
- `--auth-mode auto|subscription|api-key`
- `--codex-home ~/.codex`
- `--runtime auto|docker|podman`
- `--image <runner-image>`
- `--pull always|if-missing|never`
- `--network unrestricted|none`
- `--execution-mode sandboxed|host`
- `--codex-sandbox read-only|workspace-write|danger-full-access`
- `--clean-image`
- `--keep-workspace-error`

Notes:
- `--out` is optional; default is `./.governor/runs/<timestamp>`.
- Isolated defaults are hardened while remaining practical: `--network none`, `--pull never`, `--auth-mode subscription`, `--execution-mode host`.
- `--network unrestricted` allows normal outbound network for model/tool calls; `none` is fully offline.
- Isolated preflight now includes both endpoint reachability and a short Codex exec probe. The Codex probe is authoritative for runtime health.
- Worker tracks retry Codex transport failures classified as retryable (for example stream/network disconnects) and emit a fallback non-empty JSON output when retries are exhausted.
- If `--pull` is `always` or `if-missing`, `--image` must be digest pinned (`name@sha256:...`).
- Container runtime/image caches are external to Governor output and may persist unless cleaned (`--clean-image`).
- If you do not have a published runner image, use `Dockerfile.isolate-runner` with `make build-isolation-image`.

### Isolated Troubleshooting

Common diagnostic labels in worker/preflight errors:

- `[infra.tls_trust]`: Runner image CA trust is missing or broken. Rebuild image from `Dockerfile.isolate-runner` and ensure `ca-certificates` are installed.
- `[auth.subscription]`: Subscription/API auth is unavailable in the isolated environment. Re-run `codex login` on host or use `--auth-mode api-key`.
- `[infra.network]`: Network/DNS/connectivity issue to Codex endpoints.
- `[stream.transient]`: Stream dropped mid-response; Governor retries and may fall back to non-empty JSON output.

## Checks Command

```bash
governor checks [<tui|init|add|extract|list|validate|doctor|explain|enable|disable>]
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

`audit.json` is intended for automation. `audit.md` and `audit.html` are intended for humans.

Git hygiene:
- Keep `.governor/.gitignore` tracked so `runs/` artifacts stay out of git while `.governor/checks/` can be versioned.

## Security and Safety

- ZIP extraction blocks path traversal and absolute paths.
- ZIP extraction enforces bounded entry count/size before and during extraction.
- Symlinks are skipped in intake and not copied into the worker workspace.
- Large inputs are constrained by `--max-files` and `--max-bytes` on the staged workspace.
- Bulky/non-source paths are excluded (`node_modules`, `vendor`, `.git`, etc.).
- Non-default `--codex-bin` requires `--allow-custom-codex-bin`.
- Run directories default to `0700`; report/log/check artifacts default to `0600`.
- Worker/report text is redacted for common secret patterns before persistence.

## Architecture

Core packages:
- `cmd`: CLI entrypoints and flags
- `internal/app`: audit orchestration
- `internal/checks`: check model, YAML load/validate, selection
- `internal/worker`: bounded-concurrency worker runner
- `internal/prompt`: per-check prompt generation
- `internal/extractor`: documents-to-checks pipeline
- `internal/report`: markdown/json/html report rendering
- `internal/tui`: terminal-native progress UI
- `internal/intake`: input staging and manifest generation

## Roadmap

- Connector-based document ingestion (Confluence/SharePoint/etc.)
- Additional built-in security check packs
- Policy profiles per organization/team
- More granular severity/confidence calibration

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

Contributions are welcome.

Local development:

```bash
make test
make build
```

When changing behavior, update this README in the same PR so users always have accurate docs.
