# Check Authoring Best Practices

This guide covers how to write effective Governor checks that produce high-signal findings with minimal noise.

## Writing AI Check Instructions

AI check instructions directly shape what the model looks for. Good instructions are specific, scoped, and outcome-oriented.

### Be Specific About What to Find

Vague instructions produce vague findings. Tell the model exactly what vulnerability patterns matter.

**Weak:**

```yaml
instructions: |
  Look for security issues in the code.
```

**Strong:**

```yaml
instructions: |
  Track focus: server-side request forgery (SSRF)
  - HTTP client calls (fetch, axios, http.get, requests.get) where the URL is derived from user input
  - Webhook or callback URL handlers that accept arbitrary URLs
  - Missing URL allowlists or hostname validation before outbound requests
  - DNS rebinding risk: validating hostname at check time but resolving differently at fetch time
```

### Use Bullet Lists for Detection Criteria

The model responds well to structured lists. Each bullet should describe one concrete pattern or condition to look for.

```yaml
instructions: |
  Track focus: insecure deserialization
  - Python: pickle.loads(), yaml.load() without SafeLoader on untrusted data
  - JavaScript: node-serialize, js-yaml.load() with dangerous schema
  - Java: ObjectInputStream.readObject(), XStream without allowlist
  - General: deserialization of HTTP request bodies without schema validation
  - Missing integrity checks (HMAC/signature) on serialized data before deserialization
```

### State What NOT to Flag

Reducing false positives is as important as catching real issues. Add exclusion guidance when your check has known noisy patterns.

```yaml
instructions: |
  Track focus: missing rate limiting
  - Authentication endpoints (login, register, password reset) without rate limiting
  - API endpoints performing expensive operations without throttling
  - Token generation or OTP verification endpoints vulnerable to brute-force
  Note: Focus on endpoints that are clearly sensitive or expensive. Not every endpoint needs rate limiting.
```

### Start From Built-in Check Instructions

The built-in checks in Governor are good starting points. Use `governor checks explain <id>` to see any check's full definition, then adapt the instructions for your specific stack.

## Scope Optimization

Scope controls which files a check examines. Tight scopes mean faster audits and fewer irrelevant findings.

### Include Globs

Restrict checks to relevant file types. A check looking for Python command injection does not need to scan `.css` files.

```yaml
scope:
  include_globs:
    - "**/*.py"
    - "**/*.js"
    - "**/*.ts"
```

### Exclude Globs

Remove directories and files that produce noise. Vendored dependencies, test fixtures, and generated code are common exclusions.

```yaml
scope:
  exclude_globs:
    - "**/node_modules/**"
    - "**/vendor/**"
    - "**/*_test.go"
    - "**/test/**"
    - "**/*.test.*"
    - "**/fixtures/**"
    - "**/*.lock"
    - "**/go.sum"
```

### Glob Pattern Reference

| Pattern | Matches |
|---------|---------|
| `**/*` | All files (default when no include globs set) |
| `**/*.go` | All Go files at any depth |
| `*.yaml` | YAML files in root only |
| `**/vendor/**` | Anything under any `vendor/` directory |
| `src/**/*.ts` | TypeScript files under `src/` |
| `**/*.{js,ts}` | Does **not** work -- use separate entries |

Important: `**/*` is the default include pattern when no `include_globs` are specified. Always set explicit includes for targeted checks.

### Scope Strategy by Check Type

- **AI checks**: Broader scopes are acceptable since the AI model has context awareness. Still exclude vendored code.
- **Rule checks**: Tight scopes are critical. A regex matching `eval(` will fire on every JavaScript test helper if you do not exclude test directories.

## Severity and Confidence Calibration

### Severity Levels

Set `severity_hint` based on realistic worst-case impact:

| Level | Use When |
|-------|----------|
| `critical` | Direct RCE, credential exposure, auth bypass |
| `high` | SSRF, SQL injection, path traversal, privilege escalation |
| `medium` | Weak crypto, missing rate limiting, insecure defaults |
| `low` | Informational security hygiene issues |
| `info` | Style, best-practice, non-exploitable observations |

For rule-engine checks, each detector can override `severity_hint` with its own `severity` field. Use this when a single check has detectors of varying severity (e.g., MD5 usage is `medium` while ECB mode is `high`).

### Confidence Calibration

`confidence_hint` ranges from `0` to `1`. This signals how reliable findings from this check typically are.

| Range | Meaning |
|-------|---------|
| `0.85-1.0` | High precision -- pattern is almost always a real issue (e.g., private key in source) |
| `0.65-0.84` | Good signal -- most matches are real but some context-dependent false positives |
| `0.50-0.64` | Moderate -- requires human review, common in heuristic patterns |
| `< 0.50` | Noisy -- use only when the potential finding is severe enough to justify noise |

Rule-engine detectors can set per-detector `confidence` values. The built-in `math-rand-crypto` detector uses `0.5` because `Math.random()` is only a security issue in specific contexts.

## Reducing False Positives

### For AI Checks

1. **Add negative examples** in instructions: "Do not flag X when Y"
2. **Narrow scope** to only relevant file types
3. **Use `categories_hint`** to help the model classify correctly
4. **Start as `draft`**, run with `governor checks test`, review output, then enable

### For Rule Checks

1. **Use `case_sensitive: true`** when the pattern is case-specific (e.g., `-----BEGIN RSA PRIVATE KEY-----`)
2. **Set `max_matches`** to avoid flooding reports -- 5-10 matches per file is usually enough
3. **Exclude test directories** where patterns appear in test data, not production code
4. **Prefer regex over contains** when you need boundary matching (e.g., `\beval\s*\(` vs plain `eval(`)

## Testing Checks

The `governor checks test` command runs a single check against a target path without a full audit. This is the primary workflow for developing and iterating on checks.

### Basic Usage

```bash
# Test a rule-engine check against a project
governor checks test hardcoded_credentials ./my-project

# Test an AI check (requires AI provider configured)
governor checks test ssrf ./my-project

# Output as JSON for scripted validation
governor checks test prompt_injection ./my-project --format json
```

### Development Workflow

1. **Create the check as `draft`:**

```bash
governor checks init --non-interactive \
  --template blank \
  --id my-xss-check \
  --name "XSS Detection" \
  --status draft
```

2. **Edit the check file** (`.governor/checks/my-xss-check.check.yaml`) to refine instructions and scope.

3. **Test against a known-vulnerable sample:**

```bash
governor checks test my-xss-check ./test-samples/vulnerable-app
```

4. **Review findings**, tune instructions or patterns, and re-test.

5. **Test against a clean project** to verify no false positives:

```bash
governor checks test my-xss-check ./known-clean-project
```

6. **Enable when satisfied:**

```bash
governor checks enable my-xss-check
```

### Validate and Diagnose

Before testing, ensure your check file is valid:

```bash
# Validate all checks for schema errors
governor checks validate

# Diagnose conflicts, shadowing, and quality issues
governor checks doctor

# See full resolution details for a specific check
governor checks explain my-xss-check
```

## Complete AI Check Example

Based on the built-in `ssrf` check:

```yaml
api_version: governor/v1
id: ssrf-custom
name: SSRF Detection (Custom)
status: enabled
source: custom
engine: ai
description: >
  Identifies server-side request forgery vulnerabilities where
  user-controlled URLs reach server-side HTTP clients.
instructions: |
  Track focus: server-side request forgery (SSRF)
  - HTTP client calls (fetch, axios, http.get, requests.get, net/http) where the URL or host is derived from user input
  - Webhook or callback URL handlers that accept arbitrary URLs from users
  - URL redirect endpoints that follow user-supplied URLs server-side
  - Internal service URLs or cloud metadata endpoints (169.254.169.254) reachable via user-controlled requests
  - Missing URL allowlists or hostname validation before making outbound requests
  - DNS rebinding risk: validating hostname at check time but resolving differently at fetch time
scope:
  include_globs:
    - "**/*.go"
    - "**/*.py"
    - "**/*.js"
    - "**/*.ts"
  exclude_globs:
    - "**/node_modules/**"
    - "**/vendor/**"
    - "**/test/**"
categories_hint:
  - ssrf
  - input_validation
severity_hint: high
confidence_hint: 0.75
```

## Complete Rule Check Example

Based on the built-in `hardcoded_credentials` check:

```yaml
api_version: governor/v1
id: hardcoded-aws-keys
name: Hardcoded AWS Credentials
status: enabled
source: custom
engine: rule
description: Detects AWS access keys and secret keys embedded in source code.
rule:
  target: file_content
  detectors:
    - id: aws-access-key
      kind: regex
      pattern: '(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}'
      case_sensitive: true
      title: AWS access key ID detected
      category: secrets
      severity: critical
      confidence: 0.9
      remediation: >
        Remove the AWS access key from source code. Use IAM roles,
        environment variables, or AWS Secrets Manager instead.
      max_matches: 10
    - id: aws-secret-key
      kind: regex
      pattern: '(?i)aws_secret_access_key\s*[:=]\s*["\x27][A-Za-z0-9/+=]{40}["\x27]'
      title: AWS secret access key detected
      category: secrets
      severity: critical
      confidence: 0.85
      remediation: >
        Rotate the exposed secret key immediately. Store credentials
        in a secrets manager, not in source code.
      max_matches: 10
scope:
  include_globs:
    - "**/*.go"
    - "**/*.py"
    - "**/*.js"
    - "**/*.ts"
    - "**/*.yaml"
    - "**/*.yml"
    - "**/*.json"
    - "**/*.env"
    - "**/*.cfg"
    - "**/*.conf"
  exclude_globs:
    - "**/node_modules/**"
    - "**/vendor/**"
    - "**/*_test.go"
    - "**/test/**"
    - "**/*.lock"
categories_hint:
  - secrets
  - credentials
severity_hint: critical
confidence_hint: 0.85
```

## Choosing Between AI and Rule Engines

| Factor | Use `engine: ai` | Use `engine: rule` |
|--------|-------------------|---------------------|
| Pattern complexity | Complex, context-dependent | Simple, literal or regex-matchable |
| False positive tolerance | AI has contextual awareness | Rules need careful scoping |
| Speed | Slower (model call per check) | Instant (no network, no AI) |
| Offline / CI use | Requires AI provider access | Works everywhere, no dependencies |
| Confidence | Varies by model quality | Deterministic, reproducible |
| Cost | API/compute cost per run | Free |

**General guidance:** Use rules for well-defined patterns (hardcoded secrets, known-bad functions, literal strings). Use AI for nuanced analysis that requires understanding code flow, business logic, or contextual security impact.
