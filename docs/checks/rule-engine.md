# Rule Engine Reference

Governor's rule engine runs deterministic pattern-matching checks against source files. Rule checks require no AI provider, no network access, and produce reproducible results. They execute instantly and are ideal for CI pipelines.

## How It Works

When a rule check runs, the engine:

1. Iterates over every file in the intake manifest
2. Filters files through the check's `scope` (include/exclude globs)
3. Skips files larger than 2 MB
4. Runs each detector's pattern against the file content
5. For each match, builds a `Finding` with the matched evidence snippet (match + 80 chars of surrounding context)

Rule checks use `engine: rule` and define their patterns under the `rule` field instead of `instructions`.

## Check Structure

```yaml
api_version: governor/v1
id: my-rule-check
name: My Rule Check
status: enabled
source: custom
engine: rule
description: What this check detects.
rule:
  target: file_content
  detectors:
    - id: detector-id
      kind: contains          # or: regex
      pattern: "the pattern"
      case_sensitive: false   # default: false
      title: Finding title
      category: finding_category
      severity: high
      confidence: 0.8
      remediation: How to fix this.
      max_matches: 5          # default: 5
scope:
  include_globs:
    - "**/*.py"
  exclude_globs:
    - "**/test/**"
categories_hint:
  - secrets
severity_hint: high
confidence_hint: 0.8
```

## Target Types

Currently one target type is supported:

| Target | Description |
|--------|-------------|
| `file_content` | Match patterns against the full text content of each file |

## Detector Kinds

### `contains` -- Substring Matching

Searches for a literal substring in file content. Fast and simple.

```yaml
- id: private-key-header
  kind: contains
  pattern: "-----BEGIN RSA PRIVATE KEY-----"
  case_sensitive: true
  title: Embedded RSA private key detected
  severity: critical
  confidence: 0.95
```

**Behavior:**
- When `case_sensitive: false` (the default), both the pattern and file content are lowercased before comparison
- Matches every non-overlapping occurrence up to `max_matches`
- Best for: exact literal strings, known-bad phrases, file headers

### `regex` -- Regular Expression Matching

Matches using Go's `regexp` syntax (RE2). Supports full regex features except backreferences.

```yaml
- id: password-assignment
  kind: regex
  pattern: '(?i)(password|passwd|pwd)\s*[:=]\s*["''][\S]{8,}["'']'
  title: Hardcoded password detected
  severity: critical
  confidence: 0.8
```

**Behavior:**
- When `case_sensitive: false`, the engine prepends `(?i)` to the pattern automatically -- you do not need to add it yourself
- Uses `FindAllStringIndex` to locate up to `max_matches` matches
- Best for: patterns with variation, boundary conditions, multi-keyword combinations

**Important:** Patterns use Go's RE2 engine. Features like lookaheads (`(?=...)`) and backreferences (`\1`) are not supported. Use non-capturing groups `(?:...)` freely.

## Detector Fields

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `id` | Yes | -- | Unique identifier within this check |
| `kind` | Yes | -- | `contains` or `regex` |
| `pattern` | Yes | -- | The string or regex to match |
| `case_sensitive` | No | `false` | Whether matching is case-sensitive |
| `title` | No | `"Rule detector {id} matched"` | Finding title |
| `category` | No | First `categories_hint` or `"input_validation"` | Finding category |
| `severity` | No | `severity_hint` or `"medium"` | Finding severity |
| `confidence` | No | `confidence_hint` or `0.7` | Finding confidence (0-1) |
| `remediation` | No | Generic prompt-handling message | How to fix the issue |
| `max_matches` | No | `5` | Max matches per file per detector |

### Default Cascading

The engine resolves detector values with this priority:

1. Detector-level field (e.g., `detector.severity`)
2. Check-level hint (e.g., `severity_hint`)
3. Engine default (e.g., `"medium"` for severity, `0.7` for confidence)

This means you can set `severity_hint: high` at the check level and only override it on specific detectors that differ.

## Finding IDs

Each finding gets a deterministic ID in the format:

```
{check-id}-{detector-id}-{NNN}
```

For example: `hardcoded_credentials-password-assignment-001`. The sequence number counts matches within a single file.

## Evidence Snippets

When a detector matches, the engine captures the matched text plus 80 characters of surrounding context on each side. Newlines and tabs are replaced with spaces. Long snippets are trimmed with `...` markers.

## Practical Examples

### 1. Detect `eval()` with User Input

```yaml
- id: eval-user-input
  kind: regex
  pattern: '\beval\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.|input|args|argv)'
  title: eval() called with potentially user-controlled input
  category: rce
  severity: critical
  confidence: 0.8
  remediation: >
    Never use eval() with user-controlled input. Use safe parsing
    alternatives like JSON.parse() or purpose-built parsers.
  max_matches: 10
```

### 2. Detect Hardcoded Bearer Tokens

```yaml
- id: bearer-token-literal
  kind: regex
  pattern: '(?i)["'']Bearer\s+[A-Za-z0-9\-._~+/]+=*["'']'
  title: Hardcoded Bearer token detected
  category: secrets
  severity: high
  confidence: 0.85
  remediation: >
    Replace static Bearer tokens with runtime token retrieval
    from a secure credential store.
  max_matches: 10
```

### 3. Detect Prompt Injection Phrases

```yaml
- id: ignore-previous-instructions
  kind: contains
  pattern: "ignore previous instructions"
  case_sensitive: false
  title: Prompt injection override phrase detected
  category: prompt_injection
  severity: high
  confidence: 0.75
  remediation: >
    Treat prompt content as untrusted input and enforce policy
    guardrails before model execution.
  max_matches: 5
```

### 4. Detect Jailbreak Override Patterns

```yaml
- id: jailbreak-override
  kind: regex
  pattern: '(?i)(disregard|forget|bypass).{0,80}(policy|guardrail|safety|instruction)'
  title: Jailbreak override pattern detected
  category: prompt_injection
  severity: medium
  confidence: 0.7
  remediation: >
    Introduce strict prompt filtering and deny model directives
    that attempt to bypass policy controls.
  max_matches: 5
```

### 5. Detect `subprocess` with `shell=True`

```yaml
- id: subprocess-shell-true
  kind: regex
  pattern: 'subprocess\.\w+\([^)]*shell\s*=\s*True'
  title: Subprocess invocation with shell=True (Python)
  category: rce
  severity: high
  confidence: 0.65
  remediation: >
    Avoid shell=True in subprocess calls. Use argument lists
    instead of shell command strings to prevent injection.
  max_matches: 10
```

### 6. Detect MD5 Usage Across Languages

```yaml
- id: md5-usage
  kind: regex
  pattern: '(?i)(?:md5\.New|md5\.Sum|hashlib\.md5|crypto\.createHash\s*\(\s*[''"]md5[''"]|MessageDigest\.getInstance\s*\(\s*[''"]MD5[''"]\))'
  title: MD5 hash function used (cryptographically broken)
  category: crypto
  severity: medium
  confidence: 0.8
  remediation: >
    Replace MD5 with SHA-256 or SHA-3 for integrity checks,
    or use bcrypt/scrypt/argon2 for password hashing.
  max_matches: 10
```

### 7. Detect AES ECB Mode

```yaml
- id: ecb-mode
  kind: regex
  pattern: '(?i)(?:AES/ECB|\.MODE_ECB|cipher\.NewECB|createCipheriv\s*\(\s*[''"]aes-\d+-ecb[''"]\))'
  title: AES ECB mode detected (insecure block cipher mode)
  category: crypto
  severity: high
  confidence: 0.9
  remediation: >
    Use AES-GCM or AES-CBC with HMAC instead of ECB mode. ECB does
    not provide semantic security and leaks patterns in ciphertext.
  max_matches: 5
```

### 8. Detect AWS Access Key IDs

```yaml
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
```

### 9. Detect Embedded Private Keys (All Types)

```yaml
- id: private-key-pem
  kind: regex
  pattern: '-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'
  case_sensitive: true
  title: Embedded private key detected
  category: secrets
  severity: critical
  confidence: 0.95
  remediation: >
    Remove private keys from source code. Store them in a secure
    key management system and load at runtime.
  max_matches: 3
```

### 10. Detect File Operations with User Input (Go)

```yaml
- id: unsanitized-filepath-go
  kind: regex
  pattern: '(?:os\.Open|os\.ReadFile|os\.Create|ioutil\.ReadFile)\s*\(\s*(?:r\.|req\.|c\.|ctx\.)'
  title: File operation with request-derived path (Go)
  category: path_traversal
  severity: high
  confidence: 0.7
  remediation: >
    Use filepath.Clean() and verify the cleaned path is within
    the expected base directory before opening files from user input.
  max_matches: 10
```

## Multi-Detector Checks

A single rule check can contain multiple detectors. Each detector operates independently -- they are effectively OR'd together. Every detector match produces its own finding.

This is useful for grouping related patterns into a single logical check:

```yaml
rule:
  target: file_content
  detectors:
    - id: md5-usage
      kind: regex
      pattern: '(?i)md5\.New|hashlib\.md5'
      title: MD5 usage detected
      severity: medium
      confidence: 0.8
    - id: sha1-usage
      kind: regex
      pattern: '(?i)sha1\.New|hashlib\.sha1'
      title: SHA-1 usage detected
      severity: medium
      confidence: 0.75
    - id: ecb-mode
      kind: regex
      pattern: '(?i)AES/ECB|\.MODE_ECB'
      title: AES ECB mode detected
      severity: high
      confidence: 0.9
```

Each detector can have its own severity, confidence, title, category, and remediation. The check-level `severity_hint` and `confidence_hint` act as fallback defaults.

## Rule Notes

The `rule.notes` field is an optional list of strings for documentation purposes. Notes are included in the worker output but do not affect detection behavior.

```yaml
rule:
  target: file_content
  notes:
    - "Patterns cover Go, Python, JavaScript, and Java"
    - "Excludes test files to reduce false positives"
  detectors:
    - ...
```

## Pattern Writing Tips

### Use Non-Capturing Groups

Go's regex engine does not support backreferences. Always use `(?:...)` instead of `(...)` when you do not need the capture:

```
# Good
(?:password|passwd|pwd)\s*=

# Also works but captures unnecessarily
(password|passwd|pwd)\s*=
```

### Match Word Boundaries

Use `\b` to avoid matching substrings:

```
# Matches "eval(" but not "medieval("
\beval\s*\(
```

### Keep Patterns Readable

For complex patterns, break them into multiple detectors rather than one monster regex:

```yaml
# Better: separate detectors for each language
detectors:
  - id: exec-injection-js
    kind: regex
    pattern: '(?:exec|execSync|spawn)\s*\(\s*`[^`]*\$\{'
    title: Command injection via template literal (JavaScript)
  - id: exec-injection-py
    kind: regex
    pattern: 'os\.system\s*\(\s*f?["'']'
    title: Command injection via string construction (Python)
```

### Case Sensitivity

By default, all matching is case-insensitive. Set `case_sensitive: true` only when needed:

- **Case-sensitive:** Private key headers (`-----BEGIN RSA PRIVATE KEY-----`), AWS key prefixes (`AKIA`)
- **Case-insensitive (default):** Keywords like `password`, `secret`, function names that vary by convention

When `case_sensitive: false` and `kind: regex`, the engine prepends `(?i)` to your pattern automatically. You do not need to include `(?i)` yourself.

## Limits and Constraints

| Constraint | Value |
|------------|-------|
| Max file size for scanning | 2 MB |
| Default max matches per detector per file | 5 |
| Evidence snippet context | 80 chars each side |
| Regex engine | Go RE2 (no lookaheads, no backreferences) |
| Target types | `file_content` only |

Files exceeding 2 MB are skipped with a note in the worker output. Increase `max_matches` on a detector if you need more matches per file (the built-in checks use 5-10).

## When to Use Rules vs AI

**Use rules when:**
- The pattern is a literal string or well-defined regex
- You need deterministic, reproducible results
- The check must run offline or without API costs
- Speed matters (CI pipelines, large codebases)
- You want zero false negatives for a known-bad pattern

**Use AI when:**
- Detection requires understanding code flow or context
- The vulnerability involves multiple interacting components
- You need to assess business logic implications
- Simple pattern matching would produce too many false positives
- The pattern is hard to express as a regex

**Combine both:** Use a rule check to catch known-bad patterns deterministically, and a companion AI check to find contextual variations the rule cannot express. Governor runs both engines in the same audit.
