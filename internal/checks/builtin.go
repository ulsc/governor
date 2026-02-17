package checks

func Builtins() []Definition {
	return []Definition{
		{
			APIVersion: APIVersion,
			ID:         "appsec",
			Name:       "Application Security",
			Status:     StatusEnabled,
			Source:     SourceBuiltin,
			Engine:     EngineAI,
			Description: "Authentication, authorization, input validation, data exposure, " +
				"and exploitable application logic flaws.",
			Instructions: `Track focus: application security
- Authentication and authorization flaws
- Input validation issues and injection risk
- Data exposure and insecure direct object access
- Dangerous deserialization / SSRF / command execution paths`,
			CategoriesHint: []string{"auth", "input_validation", "data_exposure", "rce"},
			SeverityHint:   "high",
			ConfidenceHint: 0.8,
			CWE:            "CWE-284",
			OWASP:          "A01:2021",
			Origin: Origin{
				Method: "builtin",
			},
		},
		{
			APIVersion: APIVersion,
			ID:         "deps_supply_chain",
			Name:       "Dependencies and Supply Chain",
			Status:     StatusEnabled,
			Source:     SourceBuiltin,
			Engine:     EngineAI,
			Description: "Dependency, lockfile, package source, and CI/CD supply-chain " +
				"security risk indicators.",
			Instructions: `Track focus: dependency and supply-chain security
- Risky dependency usage and lockfile hygiene
- Unpinned tooling/package sources
- Insecure CI/CD scripts affecting supply chain trust
- Build/runtime package risk indicators in repo configuration`,
			CategoriesHint: []string{"supply_chain", "dependencies", "ci_cd"},
			SeverityHint:   "medium",
			ConfidenceHint: 0.7,
			CWE:            "CWE-829",
			OWASP:          "A06:2021",
			Origin: Origin{
				Method: "builtin",
			},
		},
		{
			APIVersion: APIVersion,
			ID:         "secrets_config",
			Name:       "Secrets and Security Configuration",
			Status:     StatusEnabled,
			Source:     SourceBuiltin,
			Engine:     EngineAI,
			Description: "Hardcoded secrets, insecure defaults, unsafe environment handling, " +
				"and missing protection headers.",
			Instructions: `Track focus: secrets and security configuration
- Hardcoded secrets/tokens/keys
- Insecure default configs and env handling
- Missing transport/security headers for web apps
- Overly broad permissions in config/infra files`,
			CategoriesHint: []string{"secrets", "configuration"},
			SeverityHint:   "high",
			ConfidenceHint: 0.8,
			CWE:            "CWE-798",
			OWASP:          "A07:2021",
			Origin: Origin{
				Method: "builtin",
			},
		},
		{
			APIVersion: APIVersion,
			ID:         "prompt_injection",
			Name:       "Prompt Injection Signals",
			Status:     StatusEnabled,
			Source:     SourceBuiltin,
			Engine:     EngineRule,
			Description: "Deterministic detection of prompt-injection and jailbreak override " +
				"phrases in prompts, policy docs, and prompt-bearing source files.",
			Rule: Rule{
				Target: RuleTargetFileContent,
				Detectors: []RuleDetector{
					{
						ID:          "ignore-previous-instructions",
						Kind:        RuleDetectorContains,
						Pattern:     "ignore previous instructions",
						Title:       "Prompt injection override phrase detected",
						Category:    "prompt_injection",
						Severity:    "high",
						Confidence:  0.75,
						Remediation: "Treat prompt content as untrusted input and enforce policy guardrails before model execution.",
						MaxMatches:  5,
					},
					{
						ID:          "reveal-system-prompt",
						Kind:        RuleDetectorContains,
						Pattern:     "reveal the system prompt",
						Title:       "System-prompt exfiltration phrase detected",
						Category:    "prompt_injection",
						Severity:    "high",
						Confidence:  0.8,
						Remediation: "Block instructions requesting hidden prompts or privileged model configuration details.",
						MaxMatches:  5,
					},
					{
						ID:          "jailbreak-override-pattern",
						Kind:        RuleDetectorRegex,
						Pattern:     `(?i)(disregard|forget|bypass).{0,80}(policy|guardrail|safety|instruction)`,
						Title:       "Jailbreak override pattern detected",
						Category:    "prompt_injection",
						Severity:    "medium",
						Confidence:  0.7,
						Remediation: "Introduce strict prompt filtering and deny model directives that attempt to bypass policy controls.",
						MaxMatches:  5,
					},
				},
			},
			Scope: Scope{
				IncludeGlobs: []string{
					"**/*.md",
					"**/*.txt",
					"**/*.yaml",
					"**/*.yml",
					"**/*.json",
					"**/*.go",
					"**/*.ts",
					"**/*.js",
					"**/*.py",
				},
				ExcludeGlobs: []string{
					"**/node_modules/**",
					"**/vendor/**",
					// Exclude check-definition and documentation files that
					// contain detector patterns as examples / string literals.
					"**/checks/builtin.go", "**/checks/templates.go",
					"**/docs/checks/**", "**/README.md",
				},
			},
			CategoriesHint: []string{"prompt_injection", "input_validation"},
			SeverityHint:   "high",
			ConfidenceHint: 0.75,
			CWE:            "CWE-77",
			OWASP:          "A03:2021",
			Origin: Origin{
				Method: "builtin",
			},
		},

		// ── Rule-engine checks ──────────────────────────────────────────

		{
			APIVersion:  APIVersion,
			ID:          "hardcoded_credentials",
			Name:        "Hardcoded Credentials",
			Status:      StatusEnabled,
			Source:      SourceBuiltin,
			Engine:      EngineRule,
			Description: "Detects hardcoded passwords, API keys, tokens, and secrets embedded directly in source code.",
			Rule: Rule{
				Target: RuleTargetFileContent,
				Detectors: []RuleDetector{
					{
						ID:            "password-assignment",
						Kind:          RuleDetectorRegex,
						Pattern:       `(?i)(password|passwd|pwd)\s*[:=]\s*["'][\S]{8,}["']`,
						CaseSensitive: false,
						Title:         "Hardcoded password detected",
						Category:      "secrets",
						Severity:      "critical",
						Confidence:    0.8,
						Remediation:   "Move credentials to environment variables or a secrets manager. Never commit passwords to source control.",
						MaxMatches:    10,
					},
					{
						ID:            "api-key-assignment",
						Kind:          RuleDetectorRegex,
						Pattern:       `(?i)(api_key|apikey|api_secret|api_token)\s*[:=]\s*["'][\w\-/+=]{16,}["']`,
						CaseSensitive: false,
						Title:         "Hardcoded API key or token detected",
						Category:      "secrets",
						Severity:      "critical",
						Confidence:    0.8,
						Remediation:   "Use environment variables or a secrets vault to store API keys. Rotate any exposed keys immediately.",
						MaxMatches:    10,
					},
					{
						ID:            "bearer-token-literal",
						Kind:          RuleDetectorRegex,
						Pattern:       `(?i)["']Bearer\s+[A-Za-z0-9\-._~+/]+=*["']`,
						CaseSensitive: false,
						Title:         "Hardcoded Bearer token detected",
						Category:      "secrets",
						Severity:      "high",
						Confidence:    0.85,
						Remediation:   "Replace static Bearer tokens with runtime token retrieval from a secure credential store.",
						MaxMatches:    10,
					},
					{
						ID:            "private-key-header",
						Kind:          RuleDetectorContains,
						Pattern:       "-----BEGIN RSA PRIVATE KEY-----",
						CaseSensitive: true,
						Title:         "Embedded RSA private key detected",
						Category:      "secrets",
						Severity:      "critical",
						Confidence:    0.95,
						Remediation:   "Remove private keys from source code. Store them in a secure key management system and load at runtime.",
						MaxMatches:    3,
					},
					{
						ID:            "generic-secret-assignment",
						Kind:          RuleDetectorRegex,
						Pattern:       `(?i)(secret|token|auth_key|access_key|private_key)\s*[:=]\s*["'][A-Za-z0-9\-._~+/]{20,}["']`,
						CaseSensitive: false,
						Title:         "Hardcoded secret or access key detected",
						Category:      "secrets",
						Severity:      "high",
						Confidence:    0.7,
						Remediation:   "Externalize secrets using environment variables, a .env file excluded from version control, or a secrets manager.",
						MaxMatches:    10,
					},
				},
			},
			Scope: Scope{
				IncludeGlobs: []string{
					"**/*.go", "**/*.py", "**/*.js", "**/*.ts", "**/*.jsx", "**/*.tsx",
					"**/*.java", "**/*.rb", "**/*.php", "**/*.rs", "**/*.cs",
					"**/*.yaml", "**/*.yml", "**/*.json", "**/*.toml", "**/*.env",
					"**/*.cfg", "**/*.conf", "**/*.ini", "**/*.properties",
				},
				ExcludeGlobs: []string{
					"**/node_modules/**", "**/vendor/**",
					"**/*.lock", "**/go.sum",
					"**/checks/builtin.go", // contains detector pattern strings
				},
			},
			CategoriesHint: []string{"secrets", "credentials"},
			SeverityHint:   "critical",
			ConfidenceHint: 0.8,
			CWE:            "CWE-798",
			OWASP:          "A07:2021",
			Origin: Origin{
				Method: "builtin",
			},
		},
		{
			APIVersion:  APIVersion,
			ID:          "command_injection",
			Name:        "Command Injection Patterns",
			Status:      StatusEnabled,
			Source:      SourceBuiltin,
			Engine:      EngineRule,
			Description: "Detects patterns where user-controlled input may be interpolated into OS commands, enabling command injection.",
			Rule: Rule{
				Target: RuleTargetFileContent,
				Detectors: []RuleDetector{
					{
						ID:          "exec-string-concat-js",
						Kind:        RuleDetectorRegex,
						Pattern:     `(?:child_process|exec|execSync|spawn|spawnSync)\s*\(\s*(?:` + "`" + `[^` + "`" + `]*\$\{|['"][^'"]*['"]\s*\+)`,
						Title:       "Potential command injection via string interpolation (JavaScript/TypeScript)",
						Category:    "rce",
						Severity:    "critical",
						Confidence:  0.75,
						Remediation: "Use parameterized APIs like spawn() with argument arrays instead of shell string interpolation. Validate and sanitize all user input before passing to command execution functions.",
						MaxMatches:  10,
					},
					{
						ID:          "exec-string-concat-py",
						Kind:        RuleDetectorRegex,
						Pattern:     `(?:os\.system|os\.popen|subprocess\.call|subprocess\.run|subprocess\.Popen)\s*\(\s*f?["']`,
						Title:       "Potential command injection via string construction (Python)",
						Category:    "rce",
						Severity:    "critical",
						Confidence:  0.7,
						Remediation: "Use subprocess with a list of arguments (shell=False) instead of string-based command construction. Never pass user input directly into shell commands.",
						MaxMatches:  10,
					},
					{
						ID:          "exec-shell-true-py",
						Kind:        RuleDetectorRegex,
						Pattern:     `subprocess\.\w+\([^)]*shell\s*=\s*True`,
						Title:       "Subprocess invocation with shell=True (Python)",
						Category:    "rce",
						Severity:    "high",
						Confidence:  0.65,
						Remediation: "Avoid shell=True in subprocess calls. Use argument lists instead of shell command strings to prevent injection.",
						MaxMatches:  10,
					},
					{
						ID:          "exec-command-go",
						Kind:        RuleDetectorRegex,
						Pattern:     `exec\.Command\s*\(\s*["'](?:sh|bash|cmd|powershell)["']\s*,\s*["']-c["']`,
						Title:       "Shell command execution via exec.Command (Go)",
						Category:    "rce",
						Severity:    "high",
						Confidence:  0.65,
						Remediation: "Avoid launching a shell with exec.Command. Execute the target binary directly with explicit arguments to prevent injection.",
						MaxMatches:  10,
					},
					{
						ID:          "eval-usage",
						Kind:        RuleDetectorRegex,
						Pattern:     `\beval\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.|input|args|argv)`,
						Title:       "eval() called with potentially user-controlled input",
						Category:    "rce",
						Severity:    "critical",
						Confidence:  0.8,
						Remediation: "Never use eval() with user-controlled input. Use safe parsing alternatives like JSON.parse() or purpose-built parsers.",
						MaxMatches:  10,
					},
				},
			},
			Scope: Scope{
				IncludeGlobs: []string{
					"**/*.go", "**/*.py", "**/*.js", "**/*.ts", "**/*.jsx", "**/*.tsx",
					"**/*.rb", "**/*.php", "**/*.java",
				},
				ExcludeGlobs: []string{
					"**/node_modules/**", "**/vendor/**",
				},
			},
			CategoriesHint: []string{"rce", "input_validation"},
			SeverityHint:   "critical",
			ConfidenceHint: 0.75,
			CWE:            "CWE-78",
			OWASP:          "A03:2021",
			Origin: Origin{
				Method: "builtin",
			},
		},
		{
			APIVersion:  APIVersion,
			ID:          "path_traversal",
			Name:        "Path Traversal Patterns",
			Status:      StatusEnabled,
			Source:      SourceBuiltin,
			Engine:      EngineRule,
			Description: "Detects patterns where file paths are constructed from user input without proper sanitization, enabling directory traversal attacks.",
			Rule: Rule{
				Target: RuleTargetFileContent,
				Detectors: []RuleDetector{
					{
						ID:          "path-join-user-input",
						Kind:        RuleDetectorRegex,
						Pattern:     `(?:path\.join|path\.resolve|os\.path\.join)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.|input|args)`,
						Title:       "File path constructed from user-controlled input",
						Category:    "path_traversal",
						Severity:    "high",
						Confidence:  0.7,
						Remediation: "Validate that resolved paths stay within the intended base directory. Use path canonicalization and check that the result starts with the expected prefix.",
						MaxMatches:  10,
					},
					{
						ID:          "dot-dot-slash-literal",
						Kind:        RuleDetectorRegex,
						Pattern:     `(?:readFile|readFileSync|createReadStream|open)\s*\([^)]*\.\./`,
						Title:       "File operation with parent directory traversal",
						Category:    "path_traversal",
						Severity:    "high",
						Confidence:  0.75,
						Remediation: "Avoid using relative paths with '../' in file operations. Resolve paths against a known safe base directory and reject traversal sequences.",
						MaxMatches:  10,
					},
					{
						ID:          "unsanitized-filepath-go",
						Kind:        RuleDetectorRegex,
						Pattern:     `(?:os\.Open|os\.ReadFile|os\.Create|ioutil\.ReadFile)\s*\(\s*(?:r\.|req\.|c\.|ctx\.)`,
						Title:       "File operation with request-derived path (Go)",
						Category:    "path_traversal",
						Severity:    "high",
						Confidence:  0.7,
						Remediation: "Use filepath.Clean() and verify the cleaned path is within the expected base directory before opening files from user input.",
						MaxMatches:  10,
					},
					{
						ID:          "send-file-user-input",
						Kind:        RuleDetectorRegex,
						Pattern:     `(?:res\.sendFile|res\.download|send_file|send_from_directory)\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.)`,
						Title:       "File serving endpoint with user-controlled path",
						Category:    "path_traversal",
						Severity:    "high",
						Confidence:  0.75,
						Remediation: "Restrict served files to a specific directory. Validate filenames against an allowlist or verify resolved paths are within the intended root.",
						MaxMatches:  10,
					},
				},
			},
			Scope: Scope{
				IncludeGlobs: []string{
					"**/*.go", "**/*.py", "**/*.js", "**/*.ts", "**/*.jsx", "**/*.tsx",
					"**/*.rb", "**/*.php", "**/*.java",
				},
				ExcludeGlobs: []string{
					"**/node_modules/**", "**/vendor/**",
				},
			},
			CategoriesHint: []string{"path_traversal", "input_validation"},
			SeverityHint:   "high",
			ConfidenceHint: 0.7,
			CWE:            "CWE-22",
			OWASP:          "A01:2021",
			Origin: Origin{
				Method: "builtin",
			},
		},
		{
			APIVersion:  APIVersion,
			ID:          "insecure_crypto",
			Name:        "Insecure Cryptography",
			Status:      StatusEnabled,
			Source:      SourceBuiltin,
			Engine:      EngineRule,
			Description: "Detects usage of weak or broken cryptographic algorithms and insecure cryptographic practices.",
			Rule: Rule{
				Target: RuleTargetFileContent,
				Detectors: []RuleDetector{
					{
						ID:          "md5-usage",
						Kind:        RuleDetectorRegex,
						Pattern:     `(?i)(?:md5\.New|md5\.Sum|hashlib\.md5|crypto\.createHash\s*\(\s*['"]md5['"]|MessageDigest\.getInstance\s*\(\s*['"]MD5['"])`,
						Title:       "MD5 hash function used (cryptographically broken)",
						Category:    "crypto",
						Severity:    "medium",
						Confidence:  0.8,
						Remediation: "Replace MD5 with SHA-256 or SHA-3 for integrity checks, or use bcrypt/scrypt/argon2 for password hashing.",
						MaxMatches:  10,
					},
					{
						ID:          "sha1-usage",
						Kind:        RuleDetectorRegex,
						Pattern:     `(?i)(?:sha1\.New|sha1\.Sum|hashlib\.sha1|crypto\.createHash\s*\(\s*['"]sha1['"]|MessageDigest\.getInstance\s*\(\s*['"]SHA-?1['"])`,
						Title:       "SHA-1 hash function used (cryptographically weak)",
						Category:    "crypto",
						Severity:    "medium",
						Confidence:  0.75,
						Remediation: "Replace SHA-1 with SHA-256 or SHA-3. SHA-1 is vulnerable to collision attacks and should not be used for security purposes.",
						MaxMatches:  10,
					},
					{
						ID:          "ecb-mode",
						Kind:        RuleDetectorRegex,
						Pattern:     `(?i)(?:AES/ECB|\.MODE_ECB|cipher\.NewECB|createCipheriv\s*\(\s*['"]aes-\d+-ecb['"])`,
						Title:       "AES ECB mode detected (insecure block cipher mode)",
						Category:    "crypto",
						Severity:    "high",
						Confidence:  0.9,
						Remediation: "Use AES-GCM or AES-CBC with HMAC instead of ECB mode. ECB does not provide semantic security and leaks patterns in ciphertext.",
						MaxMatches:  5,
					},
					{
						ID:          "des-usage",
						Kind:        RuleDetectorRegex,
						Pattern:     `(?i)(?:DES/|des\.new|\.MODE_DES|createCipheriv\s*\(\s*['"]des['"]|DESede|DES\.encrypt)`,
						Title:       "DES/3DES encryption detected (weak cipher)",
						Category:    "crypto",
						Severity:    "high",
						Confidence:  0.85,
						Remediation: "Replace DES or Triple-DES with AES-256-GCM. DES has a 56-bit key size and is trivially breakable.",
						MaxMatches:  5,
					},
					{
						ID:          "hardcoded-iv",
						Kind:        RuleDetectorRegex,
						Pattern:     `(?i)(?:iv|nonce|initialization.vector)\s*[:=]\s*(?:["'][0-9a-fA-F]{16,}["']|(?:bytes|bytearray)\s*\(\s*b?["'][^"']+["']\s*\)|new\s+byte\s*\[\s*\]\s*\{)`,
						Title:       "Hardcoded initialization vector or nonce detected",
						Category:    "crypto",
						Severity:    "high",
						Confidence:  0.7,
						Remediation: "Generate IVs and nonces using a cryptographically secure random number generator. Never reuse or hardcode them.",
						MaxMatches:  5,
					},
					{
						ID:          "math-rand-crypto",
						Kind:        RuleDetectorRegex,
						Pattern:     `(?:math/rand|Math\.random\(\)|random\.random\(\)|rand\.Intn|rand\.Int\(\))`,
						Title:       "Non-cryptographic random number generator in potentially security-sensitive context",
						Category:    "crypto",
						Severity:    "medium",
						Confidence:  0.5,
						Remediation: "Use crypto/rand (Go), crypto.randomBytes (Node.js), or secrets module (Python) for security-sensitive random values like tokens and keys.",
						MaxMatches:  5,
					},
				},
			},
			Scope: Scope{
				IncludeGlobs: []string{
					"**/*.go", "**/*.py", "**/*.js", "**/*.ts", "**/*.jsx", "**/*.tsx",
					"**/*.java", "**/*.rb", "**/*.php", "**/*.rs", "**/*.cs",
				},
				ExcludeGlobs: []string{
					"**/node_modules/**", "**/vendor/**",
					"**/checks/builtin.go", // contains detector pattern strings
				},
			},
			CategoriesHint: []string{"crypto", "configuration"},
			SeverityHint:   "high",
			ConfidenceHint: 0.75,
			CWE:            "CWE-327",
			OWASP:          "A02:2021",
			Origin: Origin{
				Method: "builtin",
			},
		},

		{
			APIVersion:  APIVersion,
			ID:          "sql_injection",
			Name:        "SQL Injection Patterns",
			Status:      StatusEnabled,
			Source:      SourceBuiltin,
			Engine:      EngineRule,
			Description: "Detects patterns where user-controlled input is interpolated or concatenated into SQL queries, enabling SQL injection.",
			Rule: Rule{
				Target: RuleTargetFileContent,
				Detectors: []RuleDetector{
					{
						ID:          "sql-template-literal-js",
						Kind:        RuleDetectorRegex,
						Pattern:     "`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)[^`]*\\$\\{[^}]*(?:req\\.|request\\.|params\\.|query\\.|body\\.|input|args)",
						Title:       "SQL query built with template literal interpolation (JavaScript/TypeScript)",
						Category:    "sql_injection",
						Severity:    "critical",
						Confidence:  0.75,
						Remediation: "Use parameterized queries or prepared statements instead of string interpolation in SQL. Pass user input as bind parameters.",
						MaxMatches:  10,
					},
					{
						ID:          "sql-fstring-py",
						Kind:        RuleDetectorRegex,
						Pattern:     `(?:execute|executemany|cursor\.execute)\s*\(\s*f["'](?i)(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)`,
						Title:       "SQL query built with f-string (Python)",
						Category:    "sql_injection",
						Severity:    "critical",
						Confidence:  0.8,
						Remediation: "Use parameterized queries with %s or ? placeholders. Pass user input as the second argument to execute().",
						MaxMatches:  10,
					},
					{
						ID:          "sql-format-py",
						Kind:        RuleDetectorRegex,
						Pattern:     `(?:execute|executemany|cursor\.execute)\s*\(\s*["'](?i)(?:SELECT|INSERT|UPDATE|DELETE)[^"']*["']\s*\.format\s*\(`,
						Title:       "SQL query built with .format() (Python)",
						Category:    "sql_injection",
						Severity:    "critical",
						Confidence:  0.75,
						Remediation: "Replace .format() with parameterized queries. Use placeholders (%s, ?) and pass values as a tuple.",
						MaxMatches:  10,
					},
					{
						ID:          "sql-sprintf-go",
						Kind:        RuleDetectorRegex,
						Pattern:     `(?:Query|QueryRow|Exec)\s*\(\s*fmt\.Sprintf\s*\(\s*["'](?i)(?:SELECT|INSERT|UPDATE|DELETE)`,
						Title:       "SQL query built with fmt.Sprintf (Go)",
						Category:    "sql_injection",
						Severity:    "critical",
						Confidence:  0.8,
						Remediation: "Use parameterized queries with $1/$2 or ? placeholders. Pass user input as additional arguments to Query/Exec.",
						MaxMatches:  10,
					},
					{
						ID:          "sql-concat-java",
						Kind:        RuleDetectorRegex,
						Pattern:     `(?:executeQuery|executeUpdate|execute|prepareStatement)\s*\(\s*["'](?i)(?:SELECT|INSERT|UPDATE|DELETE)[^"']*["']\s*\+\s*(?:request\.|req\.|param|input)`,
						Title:       "SQL query built with string concatenation (Java)",
						Category:    "sql_injection",
						Severity:    "critical",
						Confidence:  0.75,
						Remediation: "Use PreparedStatement with ? placeholders and setString/setInt methods. Never concatenate user input into SQL.",
						MaxMatches:  10,
					},
					{
						ID:          "sql-interpolation-ruby",
						Kind:        RuleDetectorRegex,
						Pattern:     `(?:find_by_sql|execute|select_all|where)\s*\(\s*["'](?i)(?:SELECT|INSERT|UPDATE|DELETE)[^"']*#\{`,
						Title:       "SQL query built with string interpolation (Ruby)",
						Category:    "sql_injection",
						Severity:    "critical",
						Confidence:  0.75,
						Remediation: "Use parameterized queries with ? placeholders or ActiveRecord's safe query interface. Avoid string interpolation in SQL.",
						MaxMatches:  10,
					},
					{
						ID:          "sql-concat-php",
						Kind:        RuleDetectorRegex,
						Pattern:     `(?:query|execute|prepare)\s*\(\s*["'](?i)(?:SELECT|INSERT|UPDATE|DELETE)[^"']*["']\s*\.\s*\$_(?:GET|POST|REQUEST|COOKIE)`,
						Title:       "SQL query built with superglobal concatenation (PHP)",
						Category:    "sql_injection",
						Severity:    "critical",
						Confidence:  0.8,
						Remediation: "Use PDO prepared statements with named or positional placeholders. Never concatenate $_GET/$_POST into SQL queries.",
						MaxMatches:  10,
					},
				},
			},
			Scope: Scope{
				IncludeGlobs: []string{
					"**/*.go", "**/*.py", "**/*.js", "**/*.ts", "**/*.jsx", "**/*.tsx",
					"**/*.rb", "**/*.php", "**/*.java",
				},
				ExcludeGlobs: []string{
					"**/node_modules/**", "**/vendor/**",
					"**/checks/builtin.go", // contains detector pattern strings
				},
			},
			CategoriesHint: []string{"sql_injection", "input_validation"},
			SeverityHint:   "critical",
			ConfidenceHint: 0.75,
			CWE:            "CWE-89",
			OWASP:          "A03:2021",
			Origin: Origin{
				Method: "builtin",
			},
		},

		// ── AI-engine checks ────────────────────────────────────────────

		{
			APIVersion:  APIVersion,
			ID:          "ssrf",
			Name:        "Server-Side Request Forgery",
			Status:      StatusEnabled,
			Source:      SourceBuiltin,
			Engine:      EngineAI,
			Description: "Identifies server-side request forgery vulnerabilities where user-controlled URLs " +
				"are passed to server-side HTTP clients without validation.",
			Instructions: `Track focus: server-side request forgery (SSRF)
- HTTP client calls (fetch, axios, http.get, requests.get, net/http, etc.) where the URL or host is derived from user input
- Webhook or callback URL handlers that accept arbitrary URLs from users
- URL redirect endpoints that follow user-supplied URLs server-side
- Internal service URLs or cloud metadata endpoints (169.254.169.254) reachable via user-controlled requests
- Missing URL allowlists or hostname validation before making outbound requests
- DNS rebinding risk: validating hostname at check time but resolving differently at fetch time`,
			CategoriesHint: []string{"ssrf", "input_validation"},
			SeverityHint:   "high",
			ConfidenceHint: 0.75,
			CWE:            "CWE-918",
			OWASP:          "A10:2021",
			Origin: Origin{
				Method: "builtin",
			},
		},
		{
			APIVersion:  APIVersion,
			ID:          "missing_rate_limiting",
			Name:        "Missing Rate Limiting",
			Status:      StatusEnabled,
			Source:      SourceBuiltin,
			Engine:      EngineAI,
			Description: "Identifies API endpoints and sensitive operations that lack rate limiting or throttling, " +
				"enabling brute-force, credential stuffing, or resource exhaustion attacks.",
			Instructions: `Track focus: missing rate limiting and throttling
- Authentication endpoints (login, register, password reset) without rate limiting
- API endpoints that perform expensive operations (database queries, file processing, AI inference) without request throttling
- Endpoints accepting file uploads without size or frequency limits
- Public-facing API routes with no rate-limiting middleware or decorator
- Token generation or OTP verification endpoints vulnerable to brute-force
- Missing rate-limit headers (X-RateLimit-*, Retry-After) in API responses
Note: Focus on endpoints that are clearly sensitive or expensive. Not every endpoint needs rate limiting.`,
			CategoriesHint: []string{"dos", "auth", "api_security"},
			SeverityHint:   "medium",
			ConfidenceHint: 0.65,
			CWE:            "CWE-770",
			OWASP:          "A04:2021",
			Origin: Origin{
				Method: "builtin",
			},
		},
		{
			APIVersion:  APIVersion,
			ID:          "insecure_deserialization",
			Name:        "Insecure Deserialization",
			Status:      StatusEnabled,
			Source:      SourceBuiltin,
			Engine:      EngineAI,
			Description: "Identifies unsafe deserialization of untrusted data that could lead to " +
				"remote code execution, injection, or data tampering.",
			Instructions: `Track focus: insecure deserialization
- Python: pickle.loads(), yaml.load() without SafeLoader, marshal.loads() on untrusted data
- JavaScript/TypeScript: node-serialize, js-yaml.load() with dangerous schema, JSON.parse() of untrusted data fed directly to object construction
- Java: ObjectInputStream.readObject(), XMLDecoder, XStream without allowlist, Kryo without registration
- Go: gob.Decode, encoding/xml with untrusted input into complex structures
- Ruby: Marshal.load(), YAML.load() on user input
- General: any deserialization of data from HTTP requests, message queues, or external files without schema validation
- Look for missing integrity checks (HMAC/signature) on serialized data before deserialization
- Flag cases where deserialized objects are used to make security decisions or construct queries`,
			CategoriesHint: []string{"deserialization", "rce", "input_validation"},
			SeverityHint:   "high",
			ConfidenceHint: 0.7,
			CWE:            "CWE-502",
			OWASP:          "A08:2021",
			Origin: Origin{
				Method: "builtin",
			},
		},
		{
			APIVersion:  APIVersion,
			ID:          "xss",
			Name:        "Cross-Site Scripting (XSS)",
			Status:      StatusEnabled,
			Source:      SourceBuiltin,
			Engine:      EngineAI,
			Description: "Identifies cross-site scripting vulnerabilities where untrusted data is rendered " +
				"in HTML without proper escaping or sanitization.",
			Instructions: `Track focus: cross-site scripting (XSS)
- Direct use of innerHTML, outerHTML, document.write() with user-controlled data
- React dangerouslySetInnerHTML with unsanitized input
- Template engines using unescaped output (|safe in Jinja2, {!! !!} in Blade, <%- in EJS, != in Pug)
- Reflected input rendered back in HTML responses without encoding
- Missing Content-Security-Policy headers or overly permissive CSP (unsafe-inline, unsafe-eval)
- DOM-based XSS via location.hash, location.search, document.referrer flowing into DOM sinks
- SVG/MathML injection vectors in user-generated content
- Stored XSS patterns where database content is rendered without escaping`,
			CategoriesHint: []string{"xss", "input_validation"},
			SeverityHint:   "high",
			ConfidenceHint: 0.75,
			CWE:            "CWE-79",
			OWASP:          "A03:2021",
			Scope: Scope{
				IncludeGlobs: []string{
					"**/*.html", "**/*.htm", "**/*.jsx", "**/*.tsx", "**/*.js", "**/*.ts",
					"**/*.py", "**/*.rb", "**/*.erb", "**/*.php", "**/*.vue", "**/*.svelte",
				},
			},
			Origin: Origin{
				Method: "builtin",
			},
		},
		{
			APIVersion:  APIVersion,
			ID:          "csrf",
			Name:        "Cross-Site Request Forgery (CSRF)",
			Status:      StatusEnabled,
			Source:      SourceBuiltin,
			Engine:      EngineAI,
			Description: "Identifies missing or inadequate CSRF protections on state-changing endpoints, " +
				"allowing attackers to perform actions on behalf of authenticated users.",
			Instructions: `Track focus: cross-site request forgery (CSRF)
- State-changing endpoints (POST, PUT, DELETE, PATCH) without CSRF token validation
- Forms missing hidden CSRF token fields or missing csrf_token/csrfmiddlewaretoken
- Missing or disabled CSRF middleware (e.g., @csrf_exempt in Django, csurf not applied in Express)
- Cookie configuration missing SameSite attribute or using SameSite=None without Secure
- REST APIs relying solely on cookies for authentication without additional CSRF measures
- Missing Origin/Referer header validation on sensitive endpoints
- Custom CSRF token implementations that use predictable or static values
- AJAX requests to state-changing endpoints without X-CSRF-Token or similar headers`,
			CategoriesHint: []string{"csrf", "auth"},
			SeverityHint:   "medium",
			ConfidenceHint: 0.7,
			CWE:            "CWE-352",
			OWASP:          "A01:2021",
			Scope: Scope{
				IncludeGlobs: []string{
					"**/*.js", "**/*.ts", "**/*.jsx", "**/*.tsx",
					"**/*.py", "**/*.rb", "**/*.php", "**/*.go", "**/*.java",
				},
			},
			Origin: Origin{
				Method: "builtin",
			},
		},

		// ── Vibe-coding rule-engine checks ─────────────────────────────────

		{
			APIVersion:  APIVersion,
			ID:          "missing_auth_middleware",
			Name:        "Missing Authentication on Routes",
			Status:      StatusEnabled,
			Source:      SourceBuiltin,
			Engine:      EngineRule,
			Description: "Detects route handlers for state-changing HTTP methods that appear to lack authentication " +
				"middleware, a common pattern in AI-generated scaffolding code.",
			Rule: Rule{
				Target: RuleTargetFileContent,
				Detectors: []RuleDetector{
					{
						ID:          "express-unprotected-route",
						Kind:        RuleDetectorRegex,
						Pattern:     `(?:app|router)\.(post|put|delete|patch)\s*\(\s*['"][^'"]+['"]\s*,\s*(?:async\s+)?\(?(?:req|ctx)`,
						Title:       "Express/Fastify route handler without auth middleware",
						Category:    "auth",
						Severity:    "high",
						Confidence:  0.6,
						Remediation: "Add authentication middleware (e.g., requireAuth, isAuthenticated) before route handlers that mutate state.",
						MaxMatches:  10,
					},
					{
						ID:          "nextjs-unprotected-api-route",
						Kind:        RuleDetectorRegex,
						Pattern:     `export\s+(?:default\s+)?(?:async\s+)?function\s+(?:POST|PUT|DELETE|PATCH)\s*\(`,
						Title:       "Next.js API route handler without auth check",
						Category:    "auth",
						Severity:    "high",
						Confidence:  0.6,
						Remediation: "Add an authentication guard at the top of the route handler (e.g., getServerSession, auth()) before processing the request.",
						MaxMatches:  10,
					},
					{
						ID:          "fastapi-unprotected-route",
						Kind:        RuleDetectorRegex,
						Pattern:     `@(?:app|router)\.(post|put|delete|patch)\s*\(\s*["'][^"']+["']\s*\)\s*\n\s*(?:async\s+)?def\s+\w+\s*\(`,
						Title:       "FastAPI route handler without Depends auth injection",
						Category:    "auth",
						Severity:    "high",
						Confidence:  0.6,
						Remediation: "Inject an authentication dependency using Depends() (e.g., current_user: User = Depends(get_current_user)) in the route signature.",
						MaxMatches:  10,
					},
				},
			},
			Scope: Scope{
				IncludeGlobs: []string{
					"**/*.js", "**/*.ts", "**/*.jsx", "**/*.tsx", "**/*.py",
				},
				ExcludeGlobs: []string{
					"**/node_modules/**", "**/vendor/**",
					"**/checks/builtin.go",
				},
			},
			CategoriesHint: []string{"auth", "vibe_coding"},
			SeverityHint:   "high",
			ConfidenceHint: 0.6,
			CWE:            "CWE-306",
			OWASP:          "A07:2021",
			Origin: Origin{
				Method: "builtin",
			},
		},
		{
			APIVersion:  APIVersion,
			ID:          "exposed_env_in_client",
			Name:        "Client-Exposed Environment Variables",
			Status:      StatusEnabled,
			Source:      SourceBuiltin,
			Engine:      EngineRule,
			Description: "Detects environment variables with client-visible prefixes (NEXT_PUBLIC_, VITE_, REACT_APP_) " +
				"whose names suggest they hold secrets, keys, or tokens.",
			Rule: Rule{
				Target: RuleTargetFileContent,
				Detectors: []RuleDetector{
					{
						ID:          "next-public-secret",
						Kind:        RuleDetectorRegex,
						Pattern:     `NEXT_PUBLIC_\w*(?i:secret|key|token|password|auth|private|credential)\w*\s*[:=]`,
						Title:       "Secret-like value exposed via NEXT_PUBLIC_ env variable",
						Category:    "secrets",
						Severity:    "critical",
						Confidence:  0.8,
						Remediation: "Move secret values to server-only environment variables (without the NEXT_PUBLIC_ prefix). Access them only in server components or API routes.",
						MaxMatches:  10,
					},
					{
						ID:          "vite-public-secret",
						Kind:        RuleDetectorRegex,
						Pattern:     `VITE_\w*(?i:secret|key|token|password|auth|private|credential)\w*\s*[:=]`,
						Title:       "Secret-like value exposed via VITE_ env variable",
						Category:    "secrets",
						Severity:    "critical",
						Confidence:  0.8,
						Remediation: "Move secret values to server-only environment variables (without the VITE_ prefix). Use a backend API to proxy requests that require secrets.",
						MaxMatches:  10,
					},
					{
						ID:          "react-app-secret",
						Kind:        RuleDetectorRegex,
						Pattern:     `REACT_APP_\w*(?i:secret|key|token|password|auth|private|credential)\w*\s*[:=]`,
						Title:       "Secret-like value exposed via REACT_APP_ env variable",
						Category:    "secrets",
						Severity:    "critical",
						Confidence:  0.8,
						Remediation: "Move secret values to server-only environment variables (without the REACT_APP_ prefix). Use a backend API to proxy requests that require secrets.",
						MaxMatches:  10,
					},
				},
			},
			Scope: Scope{
				IncludeGlobs: []string{
					"**/*.env", "**/*.env.*",
					"**/*.js", "**/*.ts", "**/*.jsx", "**/*.tsx",
					"**/*.yaml", "**/*.yml", "**/*.json",
				},
				ExcludeGlobs: []string{
					"**/node_modules/**", "**/vendor/**",
					"**/checks/builtin.go",
				},
			},
			CategoriesHint: []string{"secrets", "vibe_coding"},
			SeverityHint:   "critical",
			ConfidenceHint: 0.8,
			CWE:            "CWE-200",
			OWASP:          "A01:2021",
			Origin: Origin{
				Method: "builtin",
			},
		},
		{
			APIVersion:  APIVersion,
			ID:          "permissive_cors",
			Name:        "Overly Permissive CORS",
			Status:      StatusEnabled,
			Source:      SourceBuiltin,
			Engine:      EngineRule,
			Description: "Detects wildcard or default-open CORS configurations that allow any origin to make " +
				"credentialed cross-origin requests.",
			Rule: Rule{
				Target: RuleTargetFileContent,
				Detectors: []RuleDetector{
					{
						ID:          "cors-wildcard-origin",
						Kind:        RuleDetectorRegex,
						Pattern:     `(?i)(?:Access-Control-Allow-Origin|allowedOrigins?|cors.*origin)\s*[:=]\s*['"]\*['"]`,
						Title:       "CORS origin set to wildcard (*)",
						Category:    "configuration",
						Severity:    "medium",
						Confidence:  0.75,
						Remediation: "Replace the wildcard origin with an explicit allowlist of trusted origins. Avoid '*' when credentials are in use.",
						MaxMatches:  5,
					},
					{
						ID:          "cors-middleware-wildcard",
						Kind:        RuleDetectorRegex,
						Pattern:     `cors\s*\(\s*\)`,
						Title:       "CORS middleware invoked with default (permissive) settings",
						Category:    "configuration",
						Severity:    "medium",
						Confidence:  0.75,
						Remediation: "Pass an explicit configuration object to the CORS middleware specifying allowed origins, methods, and headers.",
						MaxMatches:  5,
					},
					{
						ID:          "fastapi-cors-wildcard",
						Kind:        RuleDetectorRegex,
						Pattern:     `CORSMiddleware\s*\([^)]*allow_origins\s*=\s*\[\s*["']\*["']\s*\]`,
						Title:       "FastAPI CORSMiddleware allows all origins",
						Category:    "configuration",
						Severity:    "medium",
						Confidence:  0.75,
						Remediation: "Replace allow_origins=[\"*\"] with an explicit list of trusted origins in the CORSMiddleware configuration.",
						MaxMatches:  5,
					},
				},
			},
			Scope: Scope{
				IncludeGlobs: []string{
					"**/*.js", "**/*.ts", "**/*.jsx", "**/*.tsx",
					"**/*.py", "**/*.go", "**/*.rb", "**/*.java",
					"**/*.yaml", "**/*.yml", "**/*.json",
				},
				ExcludeGlobs: []string{
					"**/node_modules/**", "**/vendor/**",
					"**/checks/builtin.go",
				},
			},
			CategoriesHint: []string{"configuration", "vibe_coding"},
			SeverityHint:   "medium",
			ConfidenceHint: 0.75,
			CWE:            "CWE-942",
			OWASP:          "A05:2021",
			Origin: Origin{
				Method: "builtin",
			},
		},
		{
			APIVersion:  APIVersion,
			ID:          "missing_input_validation",
			Name:        "Missing Request Input Validation",
			Status:      StatusEnabled,
			Source:      SourceBuiltin,
			Engine:      EngineRule,
			Description: "Detects patterns where HTTP request bodies are passed directly to database operations " +
				"or spread into objects without validation or sanitization.",
			Rule: Rule{
				Target: RuleTargetFileContent,
				Detectors: []RuleDetector{
					{
						ID:          "req-body-to-db-js",
						Kind:        RuleDetectorRegex,
						Pattern:     `(?:\.create|\.insertOne|\.insertMany|\.updateOne|\.findOneAndUpdate)\s*\(\s*(?:req\.body|request\.body)`,
						Title:       "Request body passed directly to database operation (JavaScript/TypeScript)",
						Category:    "input_validation",
						Severity:    "high",
						Confidence:  0.7,
						Remediation: "Validate and sanitize request body fields before passing them to database operations. Use a schema validation library (e.g., Zod, Joi, ajv).",
						MaxMatches:  10,
					},
					{
						ID:          "req-body-to-db-py",
						Kind:        RuleDetectorRegex,
						Pattern:     `(?:\.insert_one|\.insert_many|\.update_one|\.find_one_and_update)\s*\(\s*(?:request\.json|request\.data|request\.form)`,
						Title:       "Request body passed directly to database operation (Python)",
						Category:    "input_validation",
						Severity:    "high",
						Confidence:  0.7,
						Remediation: "Validate request data with a schema library (e.g., Pydantic, marshmallow) before passing it to database operations.",
						MaxMatches:  10,
					},
					{
						ID:          "spread-req-body",
						Kind:        RuleDetectorRegex,
						Pattern:     `\{\s*\.\.\.req\.body\s*\}|\{\s*\*\*request\.(json|data|form)`,
						Title:       "Request body spread into object without validation",
						Category:    "input_validation",
						Severity:    "high",
						Confidence:  0.7,
						Remediation: "Destructure only expected fields from the request body instead of spreading it. Validate each field before use.",
						MaxMatches:  10,
					},
				},
			},
			Scope: Scope{
				IncludeGlobs: []string{
					"**/*.js", "**/*.ts", "**/*.jsx", "**/*.tsx", "**/*.py",
				},
				ExcludeGlobs: []string{
					"**/node_modules/**", "**/vendor/**",
					"**/checks/builtin.go",
				},
			},
			CategoriesHint: []string{"input_validation", "vibe_coding"},
			SeverityHint:   "high",
			ConfidenceHint: 0.7,
			CWE:            "CWE-20",
			OWASP:          "A03:2021",
			Origin: Origin{
				Method: "builtin",
			},
		},
		{
			APIVersion:  APIVersion,
			ID:          "insecure_jwt",
			Name:        "Insecure JWT Configuration",
			Status:      StatusEnabled,
			Source:      SourceBuiltin,
			Engine:      EngineRule,
			Description: "Detects insecure JWT configurations including the none algorithm, disabled verification, " +
				"and hardcoded signing secrets commonly found in AI-generated authentication code.",
			Rule: Rule{
				Target: RuleTargetFileContent,
				Detectors: []RuleDetector{
					{
						ID:          "jwt-none-algorithm",
						Kind:        RuleDetectorRegex,
						Pattern:     `(?i)algorithm[s]?\s*[:=]\s*['"]\s*none\s*['"]`,
						Title:       "JWT none algorithm configured",
						Category:    "auth",
						Severity:    "critical",
						Confidence:  0.9,
						Remediation: "Never allow the 'none' algorithm for JWT. Explicitly specify a strong algorithm like RS256 or ES256 and reject tokens using 'none'.",
						MaxMatches:  5,
					},
					{
						ID:          "jwt-verify-disabled",
						Kind:        RuleDetectorRegex,
						Pattern:     `(?i)(?:verify|verification)\s*[:=]\s*false|jwt\.decode\s*\([^)]*verify\s*=\s*False`,
						Title:       "JWT verification disabled",
						Category:    "auth",
						Severity:    "critical",
						Confidence:  0.85,
						Remediation: "Always verify JWT signatures. Set verify=True and provide the correct signing key when decoding tokens.",
						MaxMatches:  5,
					},
					{
						ID:          "jwt-hardcoded-secret",
						Kind:        RuleDetectorRegex,
						Pattern:     `(?:jwt\.sign|jwt\.verify)\s*\([^,]*,\s*['"][A-Za-z0-9_\-]{8,}['"]`,
						Title:       "Hardcoded JWT signing secret",
						Category:    "secrets",
						Severity:    "high",
						Confidence:  0.7,
						Remediation: "Move JWT signing secrets to environment variables or a secrets manager. Rotate any exposed secrets immediately.",
						MaxMatches:  5,
					},
				},
			},
			Scope: Scope{
				IncludeGlobs: []string{
					"**/*.js", "**/*.ts", "**/*.jsx", "**/*.tsx",
					"**/*.py", "**/*.go", "**/*.java", "**/*.rb",
				},
				ExcludeGlobs: []string{
					"**/node_modules/**", "**/vendor/**",
					"**/checks/builtin.go",
				},
			},
			CategoriesHint: []string{"auth", "secrets", "vibe_coding"},
			SeverityHint:   "critical",
			ConfidenceHint: 0.85,
			CWE:            "CWE-347",
			OWASP:          "A02:2021",
			Origin: Origin{
				Method: "builtin",
			},
		},
		{
			APIVersion:  APIVersion,
			ID:          "missing_helmet_headers",
			Name:        "Missing Security Headers Middleware",
			Status:      StatusEnabled,
			Source:      SourceBuiltin,
			Engine:      EngineRule,
			Description: "Detects Express.js applications that may be missing the helmet middleware for setting " +
				"security headers, a common omission in AI-generated Node.js servers.",
			Rule: Rule{
				Target: RuleTargetFileContent,
				Detectors: []RuleDetector{
					{
						ID:          "express-no-helmet",
						Kind:        RuleDetectorRegex,
						Pattern:     `require\s*\(\s*['"]express['"]\s*\)`,
						Title:       "Express app detected without helmet middleware",
						Category:    "configuration",
						Severity:    "medium",
						Confidence:  0.5,
						Remediation: "Add the helmet middleware to your Express app (npm install helmet; app.use(helmet())) to set secure HTTP headers by default.",
						MaxMatches:  3,
					},
				},
				Notes: []string{
					"This is a heuristic — it flags Express usage as a reminder to add helmet. Low confidence reflects this.",
				},
			},
			Scope: Scope{
				IncludeGlobs: []string{
					"**/*.js", "**/*.ts",
				},
				ExcludeGlobs: []string{
					"**/node_modules/**", "**/vendor/**",
					"**/checks/builtin.go",
				},
			},
			CategoriesHint: []string{"configuration", "vibe_coding"},
			SeverityHint:   "medium",
			ConfidenceHint: 0.5,
			CWE:            "CWE-693",
			OWASP:          "A05:2021",
			Origin: Origin{
				Method: "builtin",
			},
		},
		{
			APIVersion:  APIVersion,
			ID:          "unsafe_html_rendering",
			Name:        "Unsafe HTML Rendering in React/Vue",
			Status:      StatusEnabled,
			Source:      SourceBuiltin,
			Engine:      EngineRule,
			Description: "Detects patterns where user-controlled variables are rendered as raw HTML in React or Vue components, " +
				"creating cross-site scripting (XSS) vulnerabilities common in AI-generated frontend code.",
			Rule: Rule{
				Target: RuleTargetFileContent,
				Detectors: []RuleDetector{
					{
						ID:          "react-dangerous-html-variable",
						Kind:        RuleDetectorRegex,
						Pattern:     "dangerouslySetInnerHTML\\s*=\\s*\\{\\s*\\{\\s*__html\\s*:\\s*[a-zA-Z]",
						Title:       "React dangerouslySetInnerHTML with variable input",
						Category:    "xss",
						Severity:    "high",
						Confidence:  0.75,
						Remediation: "Sanitize HTML content with a library like DOMPurify before passing it to dangerouslySetInnerHTML. Prefer rendering text content directly when possible.",
						MaxMatches:  10,
					},
					{
						ID:          "vue-v-html-variable",
						Kind:        RuleDetectorRegex,
						Pattern:     `v-html\s*=\s*["'][a-zA-Z]`,
						Title:       "Vue v-html directive with variable binding",
						Category:    "xss",
						Severity:    "high",
						Confidence:  0.7,
						Remediation: "Sanitize dynamic HTML with DOMPurify before binding via v-html. Use v-text or template interpolation for non-HTML content.",
						MaxMatches:  10,
					},
				},
			},
			Scope: Scope{
				IncludeGlobs: []string{
					"**/*.jsx", "**/*.tsx", "**/*.vue", "**/*.svelte",
				},
				ExcludeGlobs: []string{
					"**/node_modules/**", "**/vendor/**",
					"**/checks/builtin.go",
				},
			},
			CategoriesHint: []string{"xss", "vibe_coding"},
			SeverityHint:   "high",
			ConfidenceHint: 0.7,
			CWE:            "CWE-79",
			OWASP:          "A03:2021",
			Origin: Origin{
				Method: "builtin",
			},
		},
		{
			APIVersion:  APIVersion,
			ID:          "unprotected_api_keys_frontend",
			Name:        "API Keys in Frontend Code",
			Status:      StatusEnabled,
			Source:      SourceBuiltin,
			Engine:      EngineRule,
			Description: "Detects hardcoded API keys, tokens, and service credentials embedded directly in frontend source files, " +
				"a pervasive pattern in AI-generated client-side code.",
			Rule: Rule{
				Target: RuleTargetFileContent,
				Detectors: []RuleDetector{
					{
						ID:          "frontend-api-key-assignment",
						Kind:        RuleDetectorRegex,
						Pattern:     `(?i)(?:api_?key|api_?secret|auth_?token|access_?key|secret_?key)\s*[:=]\s*['"][A-Za-z0-9_\-]{20,}['"]`,
						Title:       "Hardcoded API key or secret in frontend code",
						Category:    "secrets",
						Severity:    "critical",
						Confidence:  0.75,
						Remediation: "Move API keys to server-side environment variables. Proxy requests through a backend API to avoid exposing secrets in client-side code.",
						MaxMatches:  10,
					},
					{
						ID:          "frontend-supabase-key",
						Kind:        RuleDetectorRegex,
						Pattern:     `(?:supabaseKey|supabase_key|SUPABASE_KEY|anonKey|anon_key)\s*[:=]\s*['"]eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+`,
						Title:       "Supabase JWT key hardcoded in frontend code",
						Category:    "secrets",
						Severity:    "high",
						Confidence:  0.85,
						Remediation: "Store Supabase keys in environment variables. Use Row Level Security (RLS) policies and never expose service_role keys in client code.",
						MaxMatches:  5,
					},
					{
						ID:          "frontend-firebase-key",
						Kind:        RuleDetectorRegex,
						Pattern:     `(?i)(?:firebase|firebaseConfig)\s*[:=]\s*\{[^}]*apiKey\s*:\s*['"][A-Za-z0-9_\-]{20,}['"]`,
						Title:       "Firebase configuration with API key in frontend code",
						Category:    "secrets",
						Severity:    "medium",
						Confidence:  0.7,
						Remediation: "While Firebase API keys are designed to be public, restrict them with HTTP referrer and API restrictions in the Google Cloud Console. Consider using Firebase App Check.",
						MaxMatches:  5,
					},
				},
			},
			Scope: Scope{
				IncludeGlobs: []string{
					"**/*.jsx", "**/*.tsx", "**/*.vue", "**/*.svelte",
					"**/*.js", "**/*.ts",
				},
				ExcludeGlobs: []string{
					"**/node_modules/**", "**/vendor/**",
					"**/checks/builtin.go",
					"**/server/**", "**/api/**", "**/backend/**",
				},
			},
			CategoriesHint: []string{"secrets", "vibe_coding"},
			SeverityHint:   "critical",
			ConfidenceHint: 0.75,
			CWE:            "CWE-200",
			OWASP:          "A01:2021",
			Origin: Origin{
				Method: "builtin",
			},
		},
	}
}
