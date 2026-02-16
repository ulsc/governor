# Output and Reports

Every Governor audit produces a set of artifacts in the output directory. By default, output goes to `.governor/runs/<timestamp>/` where `<timestamp>` is `YYYYMMDD-HHMMSS` in UTC.

Override with `--out <dir>`.

## Output Directory Structure

```
.governor/runs/20260214-153042/
  audit.json                    # Machine-readable full report
  audit.md                      # Human-readable markdown report
  audit.html                    # Standalone HTML report
  audit.sarif                   # SARIF v2.1.0 for code scanning
  audit-diff.json               # Baseline diff (only with --baseline)
  manifest.json                 # Input file manifest
  worker-output-schema.json     # JSON schema for worker output
  worker-appsec.log             # Worker log for the appsec check
  worker-appsec-output.json     # Raw worker output for appsec
  worker-deps_supply_chain.log  # Worker log for deps check
  ...
  workspace/                    # Staged source (deleted by default)
```

File permissions: directories are `0700`, report/log files are `0600`.

## audit.json

The primary machine-readable report. Use this for automation, dashboards, and programmatic analysis.

### Top-Level Structure

```json
{
  "run_metadata": { ... },
  "input_summary": { ... },
  "findings": [ ... ],
  "counts_by_severity": { ... },
  "counts_by_category": { ... },
  "worker_summaries": [ ... ],
  "errors": [ ... ]
}
```

### run_metadata

Run-level metadata including timing, AI configuration, and check counts.

| Field | Type | Description |
|-------|------|-------------|
| `run_id` | string | Run identifier (timestamp-based) |
| `started_at` | string | ISO 8601 start time |
| `completed_at` | string | ISO 8601 completion time |
| `duration_ms` | int | Total run duration in milliseconds |
| `prompt_version` | string | Internal prompt version used |
| `ai_profile` | string | AI profile name (e.g., `openai`, `codex`) |
| `ai_provider` | string | Provider type (`codex-cli` or `openai-compatible`) |
| `ai_model` | string | Model identifier |
| `ai_auth_mode` | string | Auth mode (`auto`, `account`, `api-key`) |
| `ai_bin` | string | Resolved AI binary path (codex-cli only) |
| `ai_version` | string | AI binary version (codex-cli only) |
| `ai_sha256` | string | AI binary SHA-256 hash (codex-cli only) |
| `execution_mode` | string | `sandboxed` or `host` |
| `ai_sandbox` | string | Sandbox mode (when sandboxed) |
| `ai_required` | bool | Whether any enabled check needs AI |
| `ai_used` | bool | Whether AI was actually invoked |
| `workers` | int | Max concurrent worker count |
| `enabled_checks` | int | Total enabled checks run |
| `builtin_checks` | int | Built-in checks count |
| `custom_checks` | int | Custom checks count |
| `ai_checks` | int | AI-engine checks count |
| `rule_checks` | int | Rule-engine checks count |
| `check_ids` | string[] | List of enabled check IDs |

### input_summary

Information about the audited input.

| Field | Type | Description |
|-------|------|-------------|
| `input_type` | string | `folder` or `zip` |
| `input_path` | string | Original input path |
| `workspace_path` | string | Staged workspace path |
| `manifest_path` | string | Path to `manifest.json` |
| `included_files` | int | Files included in workspace |
| `included_bytes` | int | Total bytes of included files |
| `skipped_files` | int | Files excluded during intake |

### findings

Array of security findings. Sorted by severity (critical first), then category, then title.

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Finding identifier |
| `title` | string | Short description of the issue |
| `severity` | string | `critical`, `high`, `medium`, `low`, or `info` |
| `category` | string | Issue category (e.g., `auth`, `injection`, `secrets`) |
| `evidence` | string | Evidence supporting the finding |
| `impact` | string | Potential impact description |
| `remediation` | string | Suggested fix |
| `file_refs` | string[] | Referenced file paths (may be empty) |
| `confidence` | float | Confidence score 0-1 (omitted if 0) |
| `source_track` | string | Check ID(s) that produced this finding |
| `created_at` | string | ISO 8601 timestamp (omitted if zero) |

### counts_by_severity

```json
{
  "critical": 0,
  "high": 2,
  "medium": 5,
  "low": 3,
  "info": 1
}
```

### counts_by_category

```json
{
  "auth": 3,
  "injection": 2,
  "secrets": 1,
  "general": 5
}
```

Categories are lowercase. Findings without a category are counted under `general`.

### worker_summaries

Per-check worker execution results.

| Field | Type | Description |
|-------|------|-------------|
| `track` | string | Check ID |
| `status` | string | `success`, `warning`, `failed`, `timeout`, `cancelled` |
| `duration_ms` | int | Worker execution time |
| `started_at` | string | ISO 8601 start time |
| `completed_at` | string | ISO 8601 completion time |
| `finding_count` | int | Findings from this worker |
| `error` | string | Error message (empty on success) |
| `log_path` | string | Path to worker log file |
| `output_path` | string | Path to worker output JSON |

### errors

Array of warning strings collected during the run. Non-empty when workers fail or produce warnings but the run still completes.

## audit.md

Human-readable markdown report with:

- Executive summary (run metadata, AI config, severity counts)
- Worker results table
- Warnings section (if any)
- Full findings list sorted by severity

Open in any markdown viewer or render to PDF.

## audit.html

Interactive standalone HTML report with no external dependencies. Includes:

- Styled hero header with run ID and duration
- Executive summary with severity stat cards
- Worker results table with status badges
- Expandable/collapsible findings with severity badges, metadata, file refs, evidence, impact, and remediation
- **Filtering** by severity, category, and source check (click filter buttons to toggle)
- **Text search** to filter findings by keyword
- **Expand All / Collapse All** button to toggle all finding cards at once
- **Dark mode** toggle (also respects `prefers-color-scheme: dark` automatically)
- **Reset Filters** button to clear all active filters and search
- Responsive layout for mobile viewing

Finding cards are collapsed by default. Click a finding header to expand it, or use the "Expand All" button.

Can be opened directly in a browser or served as a static file. Suitable for sharing with non-technical stakeholders.

## audit.sarif

SARIF v2.1.0 file for integration with GitHub Code Scanning, Azure DevOps, and other SARIF-compatible tools.

Governor maps its severity levels to SARIF levels:

| Governor Severity | SARIF Level |
|-------------------|-------------|
| critical | error |
| high | error |
| medium | warning |
| low | note |
| info | note |

Each finding becomes a SARIF result with:
- `ruleId` from the finding ID
- `message` from the finding evidence (falls back to title)
- `locations` from file refs
- `properties` with Governor-specific metadata (severity, category, confidence, impact)

See [CI/CD Integration](ci-cd.md) for uploading SARIF to GitHub Code Scanning.

## audit-diff.json

Generated only when `--baseline <path>` is used. Compares the current audit against a previous `audit.json`.

```json
{
  "new": [ ... ],
  "fixed": [ ... ],
  "unchanged": [ ... ],
  "summary": {
    "new_count": 2,
    "fixed_count": 1,
    "unchanged_count": 8
  }
}
```

| Field | Description |
|-------|-------------|
| `new` | Findings present in the current run but not in the baseline |
| `fixed` | Findings present in the baseline but not in the current run |
| `unchanged` | Findings present in both |
| `summary` | Aggregate counts |

Findings are matched by a composite key of title + category + file refs + evidence (first 200 chars). This means findings are considered the same even if severity or confidence changed slightly.

### Standalone diff

You can also compare any two `audit.json` files without running a new audit using `governor diff`:

```bash
governor diff baseline/audit.json latest/audit.json
```

This produces the same diff output and supports `--json`, `--fail-on`, and `--out` flags. See the [Diff Command](../README.md#diff-command) section for details.

## manifest.json

The input manifest listing all files included in and excluded from the workspace.

```json
{
  "root_path": "/path/to/workspace",
  "input_path": "/path/to/source",
  "input_type": "folder",
  "included_files": 142,
  "included_bytes": 524288,
  "skipped_files": 38,
  "skipped_by_reason": {
    "binary": 5,
    "symlink": 2,
    "excluded_dir": 31,
    "governorignore": 4
  },
  "files": [
    { "path": "main.go", "size": 1234 },
    { "path": "internal/app/audit.go", "size": 5678 }
  ],
  "generated_at": "2026-02-14T15:30:42Z"
}
```

## Parsing Findings Programmatically

### jq Examples

```bash
# Count findings by severity
jq '.counts_by_severity' audit.json

# List all high/critical findings
jq '[.findings[] | select(.severity == "high" or .severity == "critical")] | length' audit.json

# Extract finding titles and severities
jq '.findings[] | {title, severity, category}' audit.json

# Get new findings from a diff
jq '.new[] | {title, severity}' audit-diff.json

# Check if any critical findings exist (useful in scripts)
jq -e '.counts_by_severity.critical > 0' audit.json
```

### Go

```go
import (
    "encoding/json"
    "os"
    "governor/internal/model"
)

data, _ := os.ReadFile("audit.json")
var report model.AuditReport
json.Unmarshal(data, &report)

for _, f := range report.Findings {
    fmt.Printf("[%s] %s\n", f.Severity, f.Title)
}
```

### Python

```python
import json

with open("audit.json") as f:
    report = json.load(f)

for finding in report["findings"]:
    print(f"[{finding['severity']}] {finding['title']}")

# Check for failures
critical = report["counts_by_severity"]["critical"]
high = report["counts_by_severity"]["high"]
if critical + high > 0:
    print(f"FAIL: {critical} critical, {high} high findings")
```

## Deduplication

Governor deduplicates findings before writing reports. Two findings are considered duplicates when they share the same:

- Title (case-insensitive)
- Category (case-insensitive)
- File refs (sorted)
- Evidence (first 200 characters, case-insensitive)

When duplicates are found:
- The higher severity is kept
- The higher confidence score is kept
- Source tracks are merged (comma-separated)
- File refs from the first non-empty set are used

Final findings are sorted by severity (critical first), then category, then title.

## Secret Redaction

Governor redacts common secret patterns from all output artifacts before writing them to disk. This applies to findings, worker output, and warning messages.

Redacted patterns include:

| Pattern | Replacement |
|---------|-------------|
| PEM private keys | `[REDACTED PRIVATE KEY]` |
| Bearer tokens | `Bearer [REDACTED]` |
| AWS access keys (AKIA/ASIA/...) | `[REDACTED_AWS_ACCESS_KEY]` |
| GitHub tokens (ghp/gho/ghs/...) | `[REDACTED_GITHUB_TOKEN]` |
| Slack webhooks | `[REDACTED_SLACK_WEBHOOK]` |
| Discord webhooks | `[REDACTED_DISCORD_WEBHOOK]` |
| Anthropic API keys (sk-ant-...) | `[REDACTED_ANTHROPIC_KEY]` |
| JWT tokens | `[REDACTED_JWT]` |
| Database connection strings | `[REDACTED_CONNECTION_STRING]` |
| npm tokens | `[REDACTED_NPM_TOKEN]` |
| Base64-encoded secrets | `[REDACTED_BASE64_SECRET]` |
| Generic key=value assignments | Value replaced with `[REDACTED]` |

Redaction runs at two layers: once during worker result collection and again during report rendering. This ensures secrets do not leak even if a worker outputs them in evidence or remediation text.

## Workspace Cleanup

The staged `workspace/` directory inside the output folder is deleted by default after a successful run. Use `--keep-workspace-error` to retain it when the run ends with warnings or failures (useful for debugging).

## Git Hygiene

The default `.governor/.gitignore` keeps `runs/` out of version control while allowing `.governor/checks/` and `.governor/config.yaml` to be committed.

```
# .governor/.gitignore
runs/
```
