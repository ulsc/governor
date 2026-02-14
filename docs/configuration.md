# Configuration

Governor uses a layered configuration system. Settings can come from config files, CLI flags, or a combination of both. CLI flags always take precedence over config files.

## Config File Locations

Governor reads config from two YAML files, merged in order:

1. **Global**: `~/.governor/config.yaml`
2. **Repo-local**: `./.governor/config.yaml` (takes precedence over global)

Missing files are silently ignored. If neither file exists, Governor uses built-in defaults.

### Precedence order (lowest to highest)

```
Built-in defaults  <  Global config  <  Repo-local config  <  CLI flags
```

A repo-local config value overrides the same field from global config. A CLI flag overrides both.

## Config File Format

The config file uses YAML and mirrors the CLI flag names (with underscores instead of hyphens):

```yaml
# .governor/config.yaml
workers: 2
ai_profile: openai
ai_model: gpt-4o
timeout: 5m
verbose: true
```

### All config fields

| Field | Type | CLI Flag | Default | Description |
|-------|------|----------|---------|-------------|
| `workers` | int | `--workers` | `3` | Max concurrent worker processes (1-3) |
| `ai_profile` | string | `--ai-profile` | `codex` | AI profile name |
| `ai_provider` | string | `--ai-provider` | from profile | Provider override: `codex-cli` or `openai-compatible` |
| `ai_model` | string | `--ai-model` | from profile | Model ID override |
| `ai_auth_mode` | string | `--ai-auth-mode` | from profile | Auth mode: `auto`, `account`, or `api-key` |
| `ai_bin` | string | `--ai-bin` | `codex` | AI CLI executable path (for `codex-cli` provider) |
| `ai_base_url` | string | `--ai-base-url` | from profile | Base URL for `openai-compatible` providers |
| `ai_api_key_env` | string | `--ai-api-key-env` | from profile | Environment variable name holding the API key |
| `execution_mode` | string | `--execution-mode` | `sandboxed` | Worker execution mode: `sandboxed` or `host` |
| `ai_sandbox` | string | `--ai-sandbox` | `read-only` | Sandbox mode: `read-only`, `workspace-write`, or `danger-full-access` |
| `max_files` | int | `--max-files` | `20000` | Max file count in staged workspace |
| `max_bytes` | int | `--max-bytes` | `262144000` (~250MB) | Max total bytes in staged workspace |
| `timeout` | string | `--timeout` | `4m` | Per-check worker timeout (Go duration format) |
| `verbose` | bool | `--verbose` | `false` | Enable verbose execution logs |
| `checks_dir` | string | `--checks-dir` | auto | Custom checks directory override |
| `no_custom_checks` | bool | `--no-custom-checks` | `false` | Ignore all custom checks |
| `fail_on` | string | `--fail-on` | (none) | Exit non-zero if findings at/above severity: `critical`, `high`, `medium`, `low`, `info` |
| `baseline` | string | `--baseline` | (none) | Path to a previous `audit.json` for diff comparison |

### Example: global config for your team

```yaml
# ~/.governor/config.yaml
ai_profile: openai
ai_model: gpt-4o
workers: 2
timeout: 5m
fail_on: high
```

### Example: repo-local config overriding the model

```yaml
# ./.governor/config.yaml
ai_model: gpt-4o-mini
verbose: true
no_custom_checks: true
```

With both files present, the effective config would be:

```
ai_profile:       openai       (from global)
ai_model:         gpt-4o-mini  (repo-local overrides global)
workers:          2            (from global)
timeout:          5m           (from global)
fail_on:          high         (from global)
verbose:          true         (from repo-local)
no_custom_checks: true         (from repo-local)
```

## AI Profiles

Governor's AI profile system lets you configure how AI-powered checks connect to language models. Profiles bundle provider type, model, auth mode, and connection details into a named configuration.

### Built-in profiles

Governor ships with these profiles ready to use:

| Profile | Provider | Model | Auth Mode | API Key Env |
|---------|----------|-------|-----------|-------------|
| `codex` | codex-cli | (CLI default) | account | `CODEX_API_KEY` |
| `codex-api` | codex-cli | (CLI default) | api-key | `CODEX_API_KEY` |
| `openai` | openai-compatible | gpt-4o-mini | api-key | `OPENAI_API_KEY` |
| `openrouter` | openai-compatible | openai/gpt-4o-mini | api-key | `OPENROUTER_API_KEY` |
| `claude` | openai-compatible | anthropic/claude-3.5-sonnet | api-key | `OPENROUTER_API_KEY` |
| `gemini` | openai-compatible | google/gemini-2.0-flash-001 | api-key | `OPENROUTER_API_KEY` |
| `mistral` | openai-compatible | mistral-large-latest | api-key | `MISTRAL_API_KEY` |
| `deepseek` | openai-compatible | deepseek-chat | api-key | `DEEPSEEK_API_KEY` |
| `grok` | openai-compatible | grok-2-latest | api-key | `XAI_API_KEY` |
| `perplexity` | openai-compatible | sonar-pro | api-key | `PERPLEXITY_API_KEY` |
| `huggingface` | openai-compatible | openai/gpt-oss-120b | api-key | `HUGGINGFACEHUB_API_TOKEN` |
| `local-openai` | openai-compatible | llama3.1 | auto | `LOCAL_AI_API_KEY` |

### Using a built-in profile

```bash
# Use OpenAI directly
export OPENAI_API_KEY="sk-..."
governor audit ./my-app --ai-profile openai

# Use Mistral
export MISTRAL_API_KEY="..."
governor audit ./my-app --ai-profile mistral

# Use a local model via Ollama
governor audit ./my-app --ai-profile local-openai
```

### Providers

Governor supports two provider types:

**`codex-cli`** -- Runs AI checks via the Codex CLI subprocess. Supports `account` auth (browser login) and `api-key` auth. The binary is resolved and attested before execution.

**`openai-compatible`** -- Sends prompts to any OpenAI-compatible HTTP API. Works with OpenAI, OpenRouter, Mistral, DeepSeek, local servers (Ollama, vLLM), and any other compatible endpoint.

### Auth modes

| Mode | Description |
|------|-------------|
| `auto` | Governor picks the best available auth method |
| `account` | Uses browser-based account login (stored in `~/.codex/auth.json` for codex-cli) |
| `api-key` | Uses an API key from the environment variable specified by `api_key_env` |

## Custom AI Profiles

You can define custom profiles or override built-in ones using YAML files:

- **Global**: `~/.governor/ai/profiles.yaml`
- **Repo-local**: `./.governor/ai/profiles.yaml` (takes precedence)

### Profile file format

```yaml
api_version: governor/ai/v1
profiles:
  - name: my-openai
    provider: openai-compatible
    model: gpt-4o
    auth_mode: api-key
    base_url: https://api.openai.com/v1
    api_key_env: OPENAI_API_KEY

  - name: my-ollama
    provider: openai-compatible
    model: llama3.1:70b
    auth_mode: auto
    base_url: http://127.0.0.1:11434/v1
    api_key_env: LOCAL_AI_API_KEY

  - name: internal-gateway
    provider: openai-compatible
    model: gpt-4o
    auth_mode: api-key
    base_url: https://ai-gateway.internal.company.com/v1
    api_key_env: INTERNAL_AI_KEY
    headers:
      X-Team-ID: security-team
      X-Request-Source: governor
```

### Profile fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | yes | Profile name (used with `--ai-profile`) |
| `provider` | no | `codex-cli` or `openai-compatible` (default: `openai-compatible`) |
| `model` | no | Model ID |
| `auth_mode` | no | `auto`, `account`, or `api-key` |
| `bin` | no | AI CLI binary path (for codex-cli) |
| `base_url` | no | API base URL (for openai-compatible) |
| `api_key_env` | no | Environment variable name for the API key |
| `headers` | no | Extra HTTP headers (map of key-value strings) |
| `account_home` | no | Path to account auth data (for codex-cli, default `~/.codex`) |

### Using a custom profile

```bash
governor audit ./my-app --ai-profile my-ollama
```

### Overriding profile fields via CLI

CLI flags override individual fields from the selected profile:

```bash
# Use the openai profile but swap the model
governor audit ./my-app --ai-profile openai --ai-model gpt-4o

# Use the openai profile but point to a different endpoint
governor audit ./my-app --ai-profile openai --ai-base-url https://my-proxy.example.com/v1
```

## Directory Structure

Governor uses the `.governor/` directory for configuration, checks, and output:

```
.governor/
  config.yaml              # repo-local config
  ai/
    profiles.yaml          # repo-local AI profiles
  checks/
    my-check.check.yaml    # custom check definitions
  runs/
    20260214-103000/       # audit run output (gitignored)
      audit.md
      audit.json
      audit.html
      ...
  .gitignore               # keeps runs/ out of git
```

The global equivalent lives at `~/.governor/`:

```
~/.governor/
  config.yaml              # global config
  ai/
    profiles.yaml          # global AI profiles
  checks/
    shared-check.check.yaml  # global custom checks
```

### Git hygiene

Keep `.governor/.gitignore` tracked so `runs/` output stays out of version control while `config.yaml`, `ai/profiles.yaml`, and `checks/` can be committed and shared with your team.

## Common Configuration Patterns

### Team with OpenAI API

```yaml
# .governor/config.yaml
ai_profile: openai
ai_model: gpt-4o
fail_on: high
workers: 3
```

```bash
export OPENAI_API_KEY="sk-..."
governor audit ./my-app
```

### Local model with Ollama (fully offline)

```yaml
# .governor/config.yaml
ai_profile: local-openai
ai_model: llama3.1:70b
```

```bash
# Start Ollama first
ollama serve &
governor audit ./my-app
```

### CI pipeline (rule-based only, no AI)

```yaml
# .governor/config.yaml
no_custom_checks: true
fail_on: high
```

```bash
governor audit ./my-app \
  --only-check hardcoded_credentials \
  --only-check command_injection \
  --only-check path_traversal \
  --only-check insecure_crypto \
  --only-check prompt_injection \
  --no-tui
```

### Multiple environments with per-repo overrides

```yaml
# ~/.governor/config.yaml (global defaults for all repos)
ai_profile: openai
ai_model: gpt-4o-mini
workers: 2
```

```yaml
# ./high-risk-app/.governor/config.yaml (override for this repo)
ai_model: gpt-4o
workers: 3
fail_on: medium
```
