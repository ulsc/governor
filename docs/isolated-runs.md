# Isolated Runs

Governor can run audits inside a disposable container with strict security boundaries.
This guide explains when to use isolated runs, how to set them up, and how to customize them.

## When to Use Isolated Runs

Use `governor isolate audit` when you need:

- **Untrusted inputs** -- auditing source code from external teams or vendors where you do not want the code to touch your host filesystem directly.
- **Reproducible environments** -- ensuring the audit runs in a consistent container image regardless of host OS differences.
- **Blast radius reduction** -- confining AI subprocess execution to a disposable container with dropped capabilities, read-only root filesystem, and strict resource limits.
- **CI/CD pipelines** -- running audits in automation where host isolation adds a layer of defense.

For trusted local development, `governor audit` (without isolation) is simpler and faster.

## Prerequisites

You need one of the following container runtimes installed:

- [Docker](https://docs.docker.com/get-docker/) (Docker Engine or Docker Desktop)
- [Podman](https://podman.io/docs/installation)

Governor auto-detects the runtime. Docker is preferred if both are available.

## Quick Start

### 1. Build the runner image

```bash
make build-isolation-image
```

This builds a local image tagged `governor-runner:local` from `Dockerfile.isolate-runner`. The image contains:
- Governor binary (built from your current source)
- Node.js 20 runtime
- Codex CLI (pinned version with integrity verification)
- CA certificates for HTTPS connectivity

### 2. Run your first isolated audit

```bash
governor isolate audit ./my-app --network unrestricted
```

This mounts your source folder read-only into the container, runs the audit, and writes output artifacts to `.governor/runs/<timestamp>/` on the host.

### 3. Review the output

```bash
ls .governor/runs/*/
# audit.md  audit.json  audit.html  audit.sarif  manifest.json  worker-*.log
```

## How It Works

When you run `governor isolate audit`, Governor:

1. Resolves the container runtime (Docker or Podman).
2. Validates the runner image is available locally.
3. Stages an auth bundle if account authentication is needed.
4. Runs a preflight check: DNS probe, HTTPS probe, and AI CLI exec probe inside the container.
5. Launches the container with hardened settings and executes `governor audit` inside it.
6. Copies output artifacts to the host output directory.

### Container security settings

Every isolated run applies these restrictions:

| Setting | Value |
|---|---|
| Root filesystem | Read-only (`--read-only`) |
| Capabilities | All dropped (`--cap-drop=ALL`) |
| Privilege escalation | Blocked (`--security-opt=no-new-privileges:true`) |
| PID limit | 256 processes |
| Memory limit | 2 GB |
| CPU limit | 1 core |
| Temp filesystems | `/tmp` (512 MB), `/home/governor` (256 MB), `/work` (128 MB), `/ai-home` (64 MB) |

### Mount layout

| Container path | Host source | Mode |
|---|---|---|
| `/input` | Your source folder or ZIP | Read-only |
| `/output` | Host output directory | Read-write |
| `/checks` | Custom checks directory (if provided) | Read-only |
| `/ai-seed` | Staged auth bundle (if account auth) | Read-only |

## Authentication

Governor needs to authenticate with an AI provider for `engine: ai` checks. In isolated mode, there are two approaches.

### Account authentication (default)

Account auth uses your host Codex login session. Governor stages a read-only copy of `~/.codex/auth.json` into an ephemeral directory and mounts it into the container. No credentials are written back to the host.

```bash
# Ensure you are logged in on the host
codex login

# Run with account auth (this is the default)
governor isolate audit ./my-app --auth-mode account --network unrestricted
```

If `~/.codex/auth.json` does not exist, Governor exits with a clear error message.

### API key authentication

For providers that use API keys, pass the key via an environment variable. Governor forwards recognized API key variables into the container.

```bash
# OpenAI-compatible providers
export OPENAI_API_KEY="sk-..."
governor isolate audit ./my-app \
  --auth-mode api-key \
  --ai-profile openai \
  --network unrestricted

# Other providers
export MISTRAL_API_KEY="..."
governor isolate audit ./my-app \
  --auth-mode api-key \
  --ai-profile mistral \
  --network unrestricted
```

Governor forwards these environment variables into the container when `--auth-mode api-key` is set:

- `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `OPENAI_ORG_ID`, `OPENAI_PROJECT`
- `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_VERSION`
- `ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY`, `MISTRAL_API_KEY`
- `DEEPSEEK_API_KEY`, `MINIMAX_API_KEY`, `XAI_API_KEY`
- `PERPLEXITY_API_KEY`, `CHATGLM_API_KEY`
- `HUGGINGFACEHUB_API_TOKEN`, `HF_TOKEN`
- `CODEX_API_KEY`, `CODEX_BASE_URL`
- Custom key from `--ai-api-key-env`

Proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`) are always forwarded.

## Network Policies

| Policy | Flag | Behavior |
|---|---|---|
| **none** (default) | `--network none` | All outbound traffic is blocked. Use this for fully offline audits with rule-only checks. |
| **unrestricted** | `--network unrestricted` | Normal outbound network. Required for AI provider API calls. |

For AI-powered checks, you almost always need `--network unrestricted`. The default is `none` as a security-first posture.

```bash
# Rule-only checks work offline
governor isolate audit ./my-app --no-custom-checks --only-check prompt-injection-local

# AI checks need network
governor isolate audit ./my-app --network unrestricted
```

## Image Management

### Building the image

```bash
# Default tag
make build-isolation-image

# Custom tag
make build-isolation-image IMAGE=my-registry/governor-runner:v1
```

The Dockerfile uses multi-stage builds:
1. **Builder stage** -- compiles Governor from Go source.
2. **Runner stage** -- Node.js 20 slim image with Codex CLI, CA certificates, and a non-root user (UID 65532).

### Pull policies

| Policy | Flag | Behavior |
|---|---|---|
| **never** (default) | `--pull never` | Use only locally built images. No registry contact. |
| **if-missing** | `--pull if-missing` | Pull only if image not found locally. Requires digest-pinned image. |
| **always** | `--pull always` | Always pull before running. Requires digest-pinned image. |

When `--pull` is `always` or `if-missing`, the `--image` value must be digest-pinned for supply chain safety:

```bash
governor isolate audit ./my-app \
  --pull if-missing \
  --image my-registry/governor-runner@sha256:abc123...
```

### Cleaning up

```bash
# Remove the runner image after the audit
governor isolate audit ./my-app --clean-image --network unrestricted

# Or remove it manually
docker rmi governor-runner:local
```

## Docker vs Podman

Governor supports both Docker and Podman. The container arguments are compatible with both runtimes.

### Specifying a runtime

```bash
# Auto-detect (default)
governor isolate audit ./my-app --runtime auto

# Force Docker
governor isolate audit ./my-app --runtime docker

# Force Podman
governor isolate audit ./my-app --runtime podman
```

### Podman-specific notes

- Podman runs rootless by default, which is a natural fit for Governor's security model.
- On SELinux-enabled systems, you may need to set appropriate labels on mounted volumes. Governor does not add `:Z` or `:z` labels automatically.
- If you see permission errors on mounted volumes with Podman, try:

```bash
podman unshare chown 65532:65532 /path/to/output
```

## Execution Mode Inside the Container

Governor supports two execution modes for AI workers inside the container:

### Host mode (default for isolated runs)

```bash
governor isolate audit ./my-app --execution-mode host --network unrestricted
```

Workers run with full access to the staged workspace inside the container. Since the container itself is already sandboxed, this provides reliable file access while maintaining isolation.

### Sandboxed mode

```bash
governor isolate audit ./my-app --execution-mode sandboxed --network unrestricted
```

Workers additionally use the AI CLI's own sandbox (Landlock on Linux). This provides defense-in-depth but may cause file access denials for some checks. When this happens, Governor can automatically rerun the failed track in host mode.

Sandbox levels:
- `read-only` (default) -- workers can read files but not modify the workspace
- `workspace-write` -- workers can modify files within the workspace
- `danger-full-access` -- no sandbox restrictions (equivalent to host mode)

```bash
governor isolate audit ./my-app \
  --execution-mode sandboxed \
  --ai-sandbox workspace-write \
  --network unrestricted
```

## Custom Checks in Isolated Runs

Mount your custom checks directory into the container:

```bash
governor isolate audit ./my-app \
  --checks-dir ./.governor/checks \
  --network unrestricted
```

The checks directory is mounted read-only at `/checks` inside the container. Governor reads checks from this mount during the audit.

To run built-in checks only:

```bash
governor isolate audit ./my-app --no-custom-checks --network unrestricted
```

## Performance Considerations

Isolated runs add overhead compared to direct host execution:

- **Container startup** -- ~1-2 seconds for image loading and entrypoint execution.
- **Preflight probes** -- ~5-20 seconds for AI endpoint and exec probes (skipped when checks are deterministic-only).
- **tmpfs overhead** -- all workspace files live in memory-backed tmpfs. For very large codebases, the 128 MB `/work` tmpfs may be too small.
- **CPU/memory limits** -- the container is capped at 1 CPU and 2 GB RAM, which limits worker parallelism.

For large inputs, consider:

```bash
# Lower the worker count to reduce memory pressure
governor isolate audit ./my-app --workers 1 --network unrestricted

# Or reduce the staged file set
governor isolate audit ./my-app --max-files 5000 --max-bytes 50000000 --network unrestricted
```

## Preflight Diagnostics

Before the audit starts, Governor runs diagnostic probes inside the container:

1. **DNS lookup** -- resolves the AI provider endpoint.
2. **HTTPS probe** -- verifies TLS connectivity and certificate validation.
3. **AI exec probe** -- runs a minimal Codex command to verify end-to-end auth.
4. **CA bundle check** -- confirms CA certificates are present in the image.

Preflight warnings are printed to stderr with diagnostic labels and appended to the audit report.

| Label | Meaning |
|---|---|
| `[infra.tls_trust]` | CA trust is broken. Rebuild the image with `ca-certificates`. |
| `[auth.account]` | Account auth is unavailable. Re-run `codex login` on host or use `--auth-mode api-key`. |
| `[infra.network]` | Network/DNS connectivity failed. Check `--network` policy and proxy settings. |
| `[stream.transient]` | AI stream dropped. May succeed on retry during the actual audit. |

## Complete Example

End-to-end isolated audit with custom checks, OpenAI provider, and verbose output:

```bash
# Build the image
make build-isolation-image

# Set the API key
export OPENAI_API_KEY="sk-..."

# Run the isolated audit
governor isolate audit ./my-app \
  --runtime auto \
  --network unrestricted \
  --auth-mode api-key \
  --ai-profile openai \
  --ai-model gpt-4o \
  --checks-dir ./.governor/checks \
  --workers 2 \
  --timeout 6m \
  --verbose \
  --out ./audit-output

# Review output
cat ./audit-output/audit.md
```

## Flag Reference

| Flag | Default | Description |
|---|---|---|
| `--runtime` | `auto` | Container runtime: `auto`, `docker`, `podman` |
| `--image` | `governor-runner:local` | Runner image reference |
| `--network` | `none` | Network policy: `unrestricted`, `none` |
| `--pull` | `never` | Image pull policy: `always`, `if-missing`, `never` |
| `--clean-image` | `false` | Remove runner image after execution |
| `--auth-mode` | `account` | Auth mode: `auto`, `account`, `api-key` |
| `--ai-home` | `~/.codex` | Host AI account home for auth bundle |
| `--ai-profile` | `codex` | AI profile name |
| `--ai-provider` | (from profile) | Provider override: `codex-cli`, `openai-compatible` |
| `--ai-model` | (from profile) | Model override |
| `--ai-auth-mode` | (from profile) | AI auth override |
| `--ai-base-url` | (from profile) | Base URL override |
| `--ai-api-key-env` | (from profile) | API key env var override |
| `--ai-bin` | `codex` | AI CLI executable path |
| `--execution-mode` | `host` | Inner worker execution mode: `sandboxed`, `host` |
| `--ai-sandbox` | `read-only` | Sandbox mode: `read-only`, `workspace-write`, `danger-full-access` |
| `--workers` | `3` | Max concurrent workers (1-3) |
| `--max-files` | `20000` | Included file count cap |
| `--max-bytes` | `250 MB` | Included file bytes cap |
| `--timeout` | `4m` | Per-worker timeout (`0` disables timeout) |
| `--out` | `.governor/runs/<timestamp>` | Output directory |
| `--checks-dir` | (none) | Custom checks directory to mount |
| `--only-check` | (none) | Run only specified check IDs (repeatable) |
| `--skip-check` | (none) | Skip specified check IDs (repeatable) |
| `--no-custom-checks` | `false` | Run built-in checks only |
| `--keep-workspace-error` | `false` | Retain workspace on warning/failed runs |
| `--fail-on` | (none) | Exit non-zero if findings meet/exceed severity |
| `--verbose` | `false` | Enable verbose logs |
