# Troubleshooting

This guide covers the most common issues you will encounter when running Governor audits.
Each section describes the symptom, explains the likely cause, and provides a concrete solution.

## AI Provider Failures

### Authentication errors

**Symptom:** Worker logs show `[auth.account]` labels, or errors containing `unauthorized`, `401`, `403`, or `run codex login`.

**Cause:** Governor cannot authenticate with the AI provider. For `codex-cli`, this typically means your account session has expired. For `openai-compatible`, the API key environment variable is empty or invalid.

**Solution (codex-cli):**

```bash
# Re-authenticate on the host
codex login

# Verify the auth file exists
ls -la ~/.codex/auth.json
```

**Solution (openai-compatible):**

```bash
# Set the API key for your profile
export OPENAI_API_KEY="sk-..."

# Or for other providers
export MISTRAL_API_KEY="..."
export DEEPSEEK_API_KEY="..."

# Verify the variable is set
governor audit ./my-app --ai-profile openai --verbose
```

### Per-check timeouts

**Symptom:** Worker summary shows `status=timeout`. The worker log mentions `context deadline exceeded`.

**Cause:** The AI provider took longer than the per-check timeout (default 4 minutes) to respond. Large codebases or complex checks are the usual trigger.

**Solution:**

```bash
# Increase the per-check timeout
governor audit ./my-app --timeout 8m

# Reduce concurrency so each worker gets more resources
governor audit ./my-app --workers 1 --timeout 8m

# Disable per-check timeout entirely (run can take much longer)
governor audit ./my-app --timeout 0
```

### Rate limits (HTTP 429)

**Symptom:** Worker logs contain `429` or `rate limit`. Multiple workers fail in quick succession.

**Cause:** The AI provider is throttling requests. Running 3 concurrent workers with a high-throughput profile can exceed per-minute token quotas.

**Solution:**

```bash
# Reduce concurrency
governor audit ./my-app --workers 1

# Or switch to a provider with higher rate limits
governor audit ./my-app --ai-profile openrouter
```

### Stream disconnects and transient failures

**Symptom:** Worker summaries show `status=warning` with `[stream.transient]` labels. The report contains a fallback note instead of real findings.

**Cause:** The AI stream dropped mid-response. Governor retries up to 3 times with exponential backoff. If all retries fail, it writes a fallback output to prevent empty artifacts.

**Solution:**

- Re-run the audit when provider connectivity is stable.
- Check your network connection and proxy settings (`HTTP_PROXY`, `HTTPS_PROXY`).
- If the issue persists, switch to a different AI profile.

### TLS trust failures

**Symptom:** Errors tagged `[infra.tls_trust]`, messages about `certificate verify failed` or `x509:`.

**Cause:** The environment cannot validate the AI provider's TLS certificate. Common in corporate networks with TLS inspection proxies, or in containers missing CA certificates.

**Solution:**

```bash
# On the host, check your CA bundle
curl -v https://api.openai.com/v1/models 2>&1 | grep -i certificate

# In containers, ensure ca-certificates is installed
# (Dockerfile.isolate-runner already includes this)
```

If you are behind a corporate proxy, inject your root CA into the runner image or set `NODE_EXTRA_CA_CERTS`.

### Network connectivity failures

**Symptom:** Errors tagged `[infra.network]`, messages about `temporary failure in name resolution`, `connection refused`, or `no route to host`.

**Cause:** DNS or network connectivity to the AI provider endpoint is broken. In isolated runs with `--network none`, all outbound traffic is blocked by design.

**Solution:**

```bash
# For isolated runs, allow network access
governor isolate audit ./my-app --network unrestricted

# Test connectivity manually
curl -sS https://api.openai.com/v1/models | head -c 200
```

## Rule Check Issues

### Rule check produces no findings

**Symptom:** A `engine: rule` check runs successfully but reports zero findings.

**Cause:** The detector pattern does not match any file content in the staged workspace. Common reasons:
- The `scope.include_globs` exclude the files you expect to match.
- The `pattern` is case-sensitive and the target text uses different casing.
- The files were filtered out during intake (binary, too large, skipped directory).

**Solution:**

```bash
# Test the check against a specific path
governor checks test my-rule-check ./my-app

# Inspect what was staged
governor audit ./my-app --keep-workspace-error --verbose
# Then check the workspace/ directory in the output for the actual files
```

### Regex detector does not match

**Symptom:** A rule check with `kind: regex` finds nothing, even though the pattern seems correct.

**Cause:** Governor uses Go's `regexp` package, which uses RE2 syntax. Lookaheads, lookbehinds, and backreferences are not supported.

**Solution:** Rewrite the pattern using supported RE2 syntax. Test it with:

```bash
# Quick test outside Governor
echo "test string" | grep -P 'your-pattern'  # PCRE (reference)
echo "test string" | grep -E 'your-pattern'  # ERE (closer to RE2)
```

## Input and Intake Errors

### "included file count exceeds limit"

**Symptom:** Audit exits immediately with `included file count exceeds limit: N > 20000`.

**Cause:** The input folder or ZIP contains more source files than the default cap (20,000).

**Solution:**

```bash
# Raise the file limit
governor audit ./my-app --max-files 50000

# Or narrow the input to a specific subdirectory
governor audit ./my-app/src
```

### "included byte size exceeds limit"

**Symptom:** Audit exits with `included byte size exceeds limit`.

**Cause:** The total byte size of staged files exceeds the default 250 MB cap.

**Solution:**

```bash
# Raise the byte limit (500 MB example)
governor audit ./my-app --max-bytes 524288000
```

### ZIP extraction: "unsafe relative path" or "absolute path"

**Symptom:** `zip contains unsafe relative path: ../etc/passwd` or `zip contains absolute path: /etc/passwd`.

**Cause:** The ZIP archive contains path-traversal entries. Governor blocks these for security.

**Solution:** The ZIP is malformed or intentionally crafted. Re-create the archive without `../` or absolute paths:

```bash
cd my-app && zip -r ../my-app.zip .
```

### ZIP extraction: "entry count exceeds limit"

**Symptom:** `zip entry count exceeds limit: N > M`.

**Cause:** The ZIP has more entries than the bounded limit (20x `--max-files`). This is a safety guard against zip bombs.

**Solution:**

```bash
# Raise max-files to increase the entry cap proportionally
governor audit ./my-app.zip --max-files 50000
```

### "input must be a folder or .zip file"

**Symptom:** Governor rejects the input path.

**Cause:** The input is neither a directory nor a `.zip` file.

**Solution:** Governor only accepts folders or ZIP archives. Convert other archive formats first:

```bash
# For .tar.gz
mkdir extracted && tar -xzf app.tar.gz -C extracted
governor audit ./extracted
```

## Check Selection Problems

### Check exists but does not run

**Symptom:** You created a custom check but it does not appear in the audit.

**Cause:** The check's `status` is `draft` or `disabled`, or it is shadowed by a repo-local check with the same ID.

**Solution:**

```bash
# Check the effective status and location
governor checks explain my-check-id

# Enable it
governor checks enable my-check-id

# Run diagnostics
governor checks doctor
```

### "check not found" errors

**Symptom:** `--only-check my-check` fails with `check "my-check" not found or not enabled`.

**Cause:** The check ID does not exist, the file is in the wrong directory, or the YAML is invalid.

**Solution:**

```bash
# See where Governor searched
governor checks explain my-check

# Validate all check files
governor checks validate

# List all known checks
governor checks list
```

### Duplicate check IDs

**Symptom:** `checks doctor` reports shadowed checks.

**Cause:** The same check ID exists in both `./.governor/checks/` and `~/.governor/checks/`. The repo-local version takes precedence.

**Solution:** Rename or remove the duplicate. Use `checks doctor` to see which file is shadowed:

```bash
governor checks doctor
```

### Invalid YAML or schema errors

**Symptom:** `checks validate` reports errors about `api_version`, missing `instructions`, or invalid field values.

**Solution:**

```bash
governor checks validate
```

Fix the reported issues. The most common mistakes:
- Missing `api_version: governor/v1`
- Missing `instructions` for `engine: ai` checks
- Invalid `status` (must be `draft`, `enabled`, or `disabled`)
- `confidence_hint` outside 0-1 range

## Sandbox and Execution Mode Issues

### Sandbox denies file access

**Symptom:** Worker logs show `[infra.sandbox_access]` labels, mentioning `landlock` or `blocked by sandbox`.

**Cause:** The AI CLI's sandbox mode prevents reading files outside the workspace. Some checks require broader file access.

**Solution:**

```bash
# Switch to host execution mode (no sandbox)
governor audit ./my-app --execution-mode host

# Or use a less restrictive sandbox
governor audit ./my-app --ai-sandbox workspace-write
```

In isolated runs, Governor can automatically rerun sandbox-denied tracks in host mode (enabled by default via `--sandbox-deny-host-fallback`).

### codex CLI not found

**Symptom:** `exec: "codex": executable file not found in $PATH`.

**Cause:** The `codex` binary is not installed or not in your PATH.

**Solution:**

```bash
# Install codex globally
npm install -g @openai/codex

# Verify it's available
which codex

# Or point Governor to a specific path
governor audit ./my-app --ai-bin /usr/local/bin/codex --allow-custom-ai-bin
```

## TUI Display Issues

### TUI does not appear

**Symptom:** Governor prints plain text progress instead of the interactive terminal UI.

**Cause:** Governor detected a non-interactive terminal (piped output, CI environment, or a terminal that does not report as a TTY).

**Solution:**

```bash
# Force TUI mode
governor audit ./my-app --tui
```

### TUI renders incorrectly

**Symptom:** Garbled output, overlapping lines, or missing characters in the TUI.

**Cause:** Terminal emulator compatibility issues or a very narrow terminal width.

**Solution:**
- Resize your terminal to at least 80 columns wide.
- Try a different terminal emulator.
- Fall back to plain mode: `governor audit ./my-app --no-tui`

### "--tui and --no-tui" conflict

**Symptom:** `cannot set both --tui and --no-tui`.

**Solution:** Use only one of the two flags. Remove the conflicting flag from your command or config file.

## "No Findings" Scenarios

### Audit completes but reports zero findings

**Symptom:** All workers succeed but `findings: 0`.

**Possible causes:**
1. The application genuinely has no detectable issues (unlikely for most apps).
2. Check scope globs exclude the relevant files.
3. The AI model produced a valid but empty findings array.
4. Only rule-based checks ran and none matched.

**Solution:**

```bash
# Check which files were staged
governor audit ./my-app --verbose --keep-workspace-error

# Run a single check with verbose output to see what happens
governor checks test appsec ./my-app

# Inspect the worker output files
cat .governor/runs/<timestamp>/worker-appsec-output.json
```

### Only rule checks produce findings

**Symptom:** Rule checks find issues but AI checks return empty findings.

**Cause:** AI authentication or connectivity failed silently, and fallback output was used.

**Solution:** Check the worker logs for warnings:

```bash
cat .governor/runs/<timestamp>/worker-<check-id>.log
```

Look for `[stream.transient]`, `[auth.account]`, or `[infra.network]` labels.

## Common Flag Mistakes

### "--workers must be between 1 and 3"

**Symptom:** Governor rejects `--workers 5`.

**Cause:** The worker count is capped at 3 to prevent overwhelming AI providers.

**Solution:** Use a value between 1 and 3:

```bash
governor audit ./my-app --workers 3
```

### "--ai-bin cannot be empty"

**Symptom:** Governor rejects an empty `--ai-bin` flag.

**Cause:** The flag was set to an empty string, possibly via a config file.

**Solution:** Either omit the flag (defaults to `codex`) or provide a valid path:

```bash
governor audit ./my-app --ai-bin codex
```

### "--execution-mode must be sandboxed or host"

**Symptom:** Governor rejects a typo in the execution mode.

**Solution:** Use exactly `sandboxed` or `host`:

```bash
governor audit ./my-app --execution-mode host
```

### Config file overrides not applying

**Symptom:** Flags from `.governor/config.yaml` seem to be ignored.

**Cause:** CLI flags always take precedence over config file values. If you explicitly set a flag on the command line, the config file value is ignored.

**Solution:** Check your config file syntax and ensure you are not also passing the same flag on the command line:

```bash
# View the config file
cat .governor/config.yaml

# Config values only apply for flags you do NOT set on the CLI
governor audit ./my-app  # uses config defaults
governor audit ./my-app --workers 1  # overrides config
```

## Output and Report Issues

### "audit.json not found" after isolated run

**Symptom:** Isolated run completes but `warning: read isolated report` appears.

**Cause:** The inner Governor process failed before writing report artifacts. This usually means an early error during intake or check selection.

**Solution:**

```bash
# Run with verbose output to see the inner error
governor isolate audit ./my-app --verbose --network unrestricted

# Check what was written to the output directory
ls -la .governor/runs/<timestamp>/
```

### Worker logs are empty

**Symptom:** `worker-<check-id>.log` contains only `[governor] no worker log output`.

**Cause:** The AI process produced no stdout/stderr before exiting. This can happen with very fast failures (binary not found, immediate auth rejection).

**Solution:** Run the failing check in isolation with verbose mode:

```bash
governor checks test <check-id> ./my-app --verbose
```

## Getting More Help

If none of the above scenarios match your issue:

1. Run with `--verbose` to get detailed logs.
2. Inspect the worker log files in the output directory (`worker-*.log`).
3. Run `governor checks doctor` to check for configuration issues.
4. Check the per-check output files (`worker-*-output.json`) for partial results.
