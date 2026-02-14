package worker

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"governor/internal/checks"
	"governor/internal/model"
)

func TestScopeAllows_WithDoubleStarGlobs(t *testing.T) {
	scope := checks.Scope{
		IncludeGlobs: []string{"**/*.md"},
		ExcludeGlobs: []string{"**/vendor/**"},
	}
	if !scopeAllows("docs/security/prompt.md", scope) {
		t.Fatal("expected markdown file to match include glob")
	}
	if scopeAllows("vendor/prompts/injection.md", scope) {
		t.Fatal("expected vendor path to be excluded")
	}
	if scopeAllows("docs/security/prompt.txt", scope) {
		t.Fatal("expected txt file to be outside include scope")
	}
}

func TestContainsMatches_CaseInsensitive(t *testing.T) {
	matches := containsMatches("IGNORE previous instructions", "ignore previous instructions", false, 3)
	if len(matches) != 1 {
		t.Fatalf("expected one case-insensitive match, got %d", len(matches))
	}
}

// helper: run a rule check against a single file with the given content
func runRuleCheck(t *testing.T, checkDef checks.Definition, filename string, content string) []model.Finding {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, filename), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	manifest := model.InputManifest{
		Files: []model.ManifestFile{{Path: filename, Size: int64(len(content))}},
	}
	result := executeRuleCheck(context.Background(), dir, manifest, checkDef)
	if result.err != nil {
		t.Fatalf("executeRuleCheck error: %v", result.err)
	}
	return result.payload.Findings
}

// findBuiltinCheck returns the builtin check with the given ID.
func findBuiltinCheck(t *testing.T, id string) checks.Definition {
	t.Helper()
	for _, def := range checks.Builtins() {
		if def.ID == id {
			return def
		}
	}
	t.Fatalf("builtin check %q not found", id)
	return checks.Definition{}
}

// ── Hardcoded Credentials ───────────────────────────────────────────

func TestHardcodedCredentials_PasswordAssignment(t *testing.T) {
	check := findBuiltinCheck(t, "hardcoded_credentials")
	tests := []struct {
		name    string
		content string
		want    int
	}{
		{"python password", `db_password = "SuperSecret123"`, 1},
		{"js password", `const passwd = 'MyP@ssw0rd!!'`, 1},
		{"yaml password", `password: "longpassword1"`, 1},
		{"env var reference (safe)", `password = os.Getenv("DB_PASSWORD")`, 0},
		{"short value (below threshold)", `pwd = "short"`, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := runRuleCheck(t, check, "config.py", tt.content)
			if len(findings) != tt.want {
				t.Errorf("got %d findings, want %d", len(findings), tt.want)
			}
		})
	}
}

func TestHardcodedCredentials_APIKey(t *testing.T) {
	check := findBuiltinCheck(t, "hardcoded_credentials")
	tests := []struct {
		name    string
		content string
		want    int
	}{
		{"api_key in JS", `const api_key = "sk-abc123def456ghi789"`, 1},
		{"apikey in Python", `apikey = "AKIAIOSFODNN7EXAMPLE"`, 1},
		{"api_secret in YAML", `api_secret: "wJalrXUtnFEMI-K7MDENG-bPxRfiCYEXAMPLEKEY"`, 2}, // matches api-key and generic-secret detectors
		{"no match", `apikey = getEnv("API_KEY")`, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := runRuleCheck(t, check, "app.js", tt.content)
			if len(findings) != tt.want {
				t.Errorf("got %d findings, want %d", len(findings), tt.want)
			}
		})
	}
}

func TestHardcodedCredentials_BearerToken(t *testing.T) {
	check := findBuiltinCheck(t, "hardcoded_credentials")
	content := `headers = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123"}`
	findings := runRuleCheck(t, check, "client.py", content)
	if len(findings) != 1 {
		t.Errorf("got %d findings, want 1", len(findings))
	}
}

func TestHardcodedCredentials_PrivateKey(t *testing.T) {
	check := findBuiltinCheck(t, "hardcoded_credentials")
	content := `var key = ` + "`-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----`"
	findings := runRuleCheck(t, check, "server.go", content)
	if len(findings) != 1 {
		t.Errorf("got %d findings for private key, want 1", len(findings))
	}
}

// ── Command Injection ───────────────────────────────────────────────

func TestCommandInjection_JSExec(t *testing.T) {
	check := findBuiltinCheck(t, "command_injection")
	tests := []struct {
		name    string
		content string
		want    int
	}{
		{"execSync with template literal", "const out = execSync(`ls ${userInput}`)", 1},
		{"exec with concat", `exec("rm -rf " + userPath)`, 1},
		{"spawn with array (safe)", `spawn("ls", ["-la", dir])`, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := runRuleCheck(t, check, "handler.js", tt.content)
			if len(findings) != tt.want {
				t.Errorf("got %d findings, want %d", len(findings), tt.want)
			}
		})
	}
}

func TestCommandInjection_PythonSubprocess(t *testing.T) {
	check := findBuiltinCheck(t, "command_injection")
	tests := []struct {
		name    string
		content string
		want    int
	}{
		{"os.system with f-string", `os.system(f"rm {path}")`, 1},
		{"subprocess.run with string", `subprocess.run("ls " + user_dir, shell=True)`, 2}, // matches both detectors
		{"subprocess with shell=True", `subprocess.call(cmd, shell=True)`, 1},
		{"subprocess with list (safe)", `subprocess.run(["ls", "-la", path])`, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := runRuleCheck(t, check, "app.py", tt.content)
			if len(findings) != tt.want {
				t.Errorf("got %d findings, want %d", len(findings), tt.want)
			}
		})
	}
}

func TestCommandInjection_GoExec(t *testing.T) {
	check := findBuiltinCheck(t, "command_injection")
	tests := []struct {
		name    string
		content string
		want    int
	}{
		{"bash -c", `exec.Command("bash", "-c", userCmd)`, 1},
		{"sh -c", `exec.Command("sh", "-c", cmd)`, 1},
		{"direct binary (safe)", `exec.Command("git", "status")`, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := runRuleCheck(t, check, "run.go", tt.content)
			if len(findings) != tt.want {
				t.Errorf("got %d findings, want %d", len(findings), tt.want)
			}
		})
	}
}

func TestCommandInjection_EvalWithInput(t *testing.T) {
	check := findBuiltinCheck(t, "command_injection")
	tests := []struct {
		name    string
		content string
		want    int
	}{
		{"eval with req.body", `eval(req.body.expression)`, 1},
		{"eval with params", `eval(params.code)`, 1},
		{"eval with literal (safe)", `eval("1 + 1")`, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := runRuleCheck(t, check, "routes.js", tt.content)
			if len(findings) != tt.want {
				t.Errorf("got %d findings, want %d", len(findings), tt.want)
			}
		})
	}
}

// ── Path Traversal ──────────────────────────────────────────────────

func TestPathTraversal_JoinWithUserInput(t *testing.T) {
	check := findBuiltinCheck(t, "path_traversal")
	tests := []struct {
		name    string
		content string
		want    int
	}{
		{"path.join with req.params", `const file = path.join(uploadDir, req.params.filename)`, 1},
		{"os.path.join with request", `filepath = os.path.join(base, request.args.get("file"))`, 1},
		{"path.join with literal (safe)", `const file = path.join(__dirname, "static", "index.html")`, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := runRuleCheck(t, check, "server.js", tt.content)
			if len(findings) != tt.want {
				t.Errorf("got %d findings, want %d", len(findings), tt.want)
			}
		})
	}
}

func TestPathTraversal_DotDotSlash(t *testing.T) {
	check := findBuiltinCheck(t, "path_traversal")
	tests := []struct {
		name    string
		content string
		want    int
	}{
		{"readFile with ../", `readFile("../../etc/passwd")`, 1},
		{"createReadStream with ../", `createReadStream("../secret/data.txt")`, 1},
		{"normal readFile (safe)", `readFile("config.json")`, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := runRuleCheck(t, check, "util.js", tt.content)
			if len(findings) != tt.want {
				t.Errorf("got %d findings, want %d", len(findings), tt.want)
			}
		})
	}
}

func TestPathTraversal_GoFileOps(t *testing.T) {
	check := findBuiltinCheck(t, "path_traversal")
	tests := []struct {
		name    string
		content string
		want    int
	}{
		{"os.Open with request param", `data, err := os.ReadFile(r.FormValue("path"))`, 1},
		{"os.Open with ctx param", `f, err := os.Open(ctx.Param("file"))`, 1},
		{"os.Open with literal (safe)", `f, err := os.Open("config.yaml")`, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := runRuleCheck(t, check, "handler.go", tt.content)
			if len(findings) != tt.want {
				t.Errorf("got %d findings, want %d", len(findings), tt.want)
			}
		})
	}
}

func TestPathTraversal_SendFile(t *testing.T) {
	check := findBuiltinCheck(t, "path_traversal")
	tests := []struct {
		name    string
		content string
		want    int
	}{
		{"res.sendFile with req", `res.sendFile(path.join(dir, req.params.file))`, 2}, // matches both send-file and path-join detectors
		{"send_file with request", `send_file(request.args.get("doc"))`, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := runRuleCheck(t, check, "app.py", tt.content)
			if len(findings) != tt.want {
				t.Errorf("got %d findings, want %d", len(findings), tt.want)
			}
		})
	}
}

// ── Insecure Crypto ─────────────────────────────────────────────────

func TestInsecureCrypto_MD5(t *testing.T) {
	check := findBuiltinCheck(t, "insecure_crypto")
	tests := []struct {
		name    string
		content string
		want    int
	}{
		{"Go md5.New", `h := md5.New()`, 1},
		{"Python hashlib.md5", `digest = hashlib.md5(data)`, 1},
		{"Node createHash md5", `crypto.createHash('md5')`, 1},
		{"Java MD5", `MessageDigest.getInstance("MD5")`, 1},
		{"SHA-256 (safe)", `h := sha256.New()`, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := runRuleCheck(t, check, "hash.go", tt.content)
			if len(findings) != tt.want {
				t.Errorf("got %d findings, want %d", len(findings), tt.want)
			}
		})
	}
}

func TestInsecureCrypto_SHA1(t *testing.T) {
	check := findBuiltinCheck(t, "insecure_crypto")
	tests := []struct {
		name    string
		content string
		want    int
	}{
		{"Go sha1.New", `h := sha1.New()`, 1},
		{"Python hashlib.sha1", `digest = hashlib.sha1(data)`, 1},
		{"Node createHash sha1", `crypto.createHash('sha1')`, 1},
		{"Java SHA-1", `MessageDigest.getInstance("SHA-1")`, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := runRuleCheck(t, check, "verify.go", tt.content)
			if len(findings) != tt.want {
				t.Errorf("got %d findings, want %d", len(findings), tt.want)
			}
		})
	}
}

func TestInsecureCrypto_ECBMode(t *testing.T) {
	check := findBuiltinCheck(t, "insecure_crypto")
	tests := []struct {
		name    string
		content string
		want    int
	}{
		{"Java AES/ECB", `Cipher.getInstance("AES/ECB/PKCS5Padding")`, 1},
		{"Python MODE_ECB", `cipher = AES.new(key, AES.MODE_ECB)`, 1},
		{"AES-GCM (safe)", `Cipher.getInstance("AES/GCM/NoPadding")`, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := runRuleCheck(t, check, "crypto.java", tt.content)
			if len(findings) != tt.want {
				t.Errorf("got %d findings, want %d", len(findings), tt.want)
			}
		})
	}
}

func TestInsecureCrypto_DES(t *testing.T) {
	check := findBuiltinCheck(t, "insecure_crypto")
	content := `cipher = DES.encrypt(data, key)`
	findings := runRuleCheck(t, check, "legacy.py", content)
	if len(findings) != 1 {
		t.Errorf("got %d findings for DES usage, want 1", len(findings))
	}
}

func TestInsecureCrypto_HardcodedIV(t *testing.T) {
	check := findBuiltinCheck(t, "insecure_crypto")
	tests := []struct {
		name    string
		content string
		want    int
	}{
		{"hex IV", `iv = "0000000000000000"`, 1},
		{"Python bytes nonce", `nonce = bytes(b"static_nonce!")`, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := runRuleCheck(t, check, "encrypt.py", tt.content)
			if len(findings) != tt.want {
				t.Errorf("got %d findings, want %d", len(findings), tt.want)
			}
		})
	}
}

func TestInsecureCrypto_MathRand(t *testing.T) {
	check := findBuiltinCheck(t, "insecure_crypto")
	tests := []struct {
		name    string
		content string
		want    int
	}{
		{"Go math/rand import", `import "math/rand"`, 1},
		{"JS Math.random", `const token = Math.random().toString(36)`, 1},
		{"Python random.random", `secret = random.random()`, 1},
		{"crypto.randomBytes (safe)", `const buf = crypto.randomBytes(32)`, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := runRuleCheck(t, check, "gen.js", tt.content)
			if len(findings) != tt.want {
				t.Errorf("got %d findings, want %d", len(findings), tt.want)
			}
		})
	}
}

// ── Test file exclusion ─────────────────────────────────────────────

func TestTestFileExclusion_RuleCheckExcludesTestFiles(t *testing.T) {
	check := findBuiltinCheck(t, "command_injection")
	// Apply test file exclusions as the worker layer would
	check.Scope = checks.ApplyTestFileExclusions(check.Scope)

	content := `exec.Command("bash", "-c", userCmd)`
	findings := runRuleCheck(t, check, "handler_test.go", content)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for _test.go file with exclusions, got %d", len(findings))
	}
}

func TestTestFileExclusion_RuleCheckIncludesTestFilesWhenRequested(t *testing.T) {
	check := findBuiltinCheck(t, "command_injection")
	// Do NOT apply test file exclusions (simulates --include-test-files)

	content := `exec.Command("bash", "-c", userCmd)`
	findings := runRuleCheck(t, check, "handler_test.go", content)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for _test.go file without exclusions, got %d", len(findings))
	}
}

func TestTestFileExclusion_ScopeAllowsRejectsTestPaths(t *testing.T) {
	scope := checks.ApplyTestFileExclusions(checks.Scope{
		IncludeGlobs: []string{"**/*.go"},
		ExcludeGlobs: []string{"**/vendor/**"},
	})

	tests := []struct {
		path string
		want bool
	}{
		{"main.go", true},
		{"internal/app/audit.go", true},
		{"internal/app/audit_test.go", false},
		{"test/fixtures/data.go", false},
		{"pkg/testdata/sample.go", false},
		{"vendor/lib/lib.go", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := scopeAllows(tt.path, scope)
			if got != tt.want {
				t.Errorf("scopeAllows(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// ── ReDoS timeout protection ────────────────────────────────────────

func TestRegexMatchesWithTimeout_NormalRegexCompletes(t *testing.T) {
	re := regexp.MustCompile(`(?i)password\s*[:=]\s*["']`)
	content := `password = "secret123"`
	matches := regexMatchesWithTimeout(re, content, 5, "test-detector")
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
}

func TestRegexMatchesWithTimeout_NoMatchReturnsEmpty(t *testing.T) {
	re := regexp.MustCompile(`(?i)password\s*[:=]\s*["']`)
	content := `this has no secrets`
	matches := regexMatchesWithTimeout(re, content, 5, "test-detector")
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches, got %d", len(matches))
	}
}

// ── Builtin check integrity ─────────────────────────────────────────

func TestBuiltinChecks_AllCompile(t *testing.T) {
	for _, def := range checks.Builtins() {
		if def.Engine != checks.EngineRule {
			continue
		}
		t.Run(def.ID, func(t *testing.T) {
			compiled, err := compileDetectors(def.Rule.Detectors)
			if err != nil {
				t.Fatalf("failed to compile detectors for %q: %v", def.ID, err)
			}
			if len(compiled) == 0 {
				t.Fatalf("check %q has no detectors", def.ID)
			}
		})
	}
}

func TestBuiltinChecks_HaveRequiredFields(t *testing.T) {
	for _, def := range checks.Builtins() {
		t.Run(def.ID, func(t *testing.T) {
			if def.APIVersion == "" {
				t.Error("missing APIVersion")
			}
			if def.ID == "" {
				t.Error("missing ID")
			}
			if def.Name == "" {
				t.Error("missing Name")
			}
			if def.Status == "" {
				t.Error("missing Status")
			}
			if def.Source != checks.SourceBuiltin {
				t.Errorf("expected source builtin, got %q", def.Source)
			}
			if def.Engine == checks.EngineAI && def.Instructions == "" {
				t.Error("AI engine check missing Instructions")
			}
			if def.Engine == checks.EngineRule && len(def.Rule.Detectors) == 0 {
				t.Error("rule engine check has no detectors")
			}
			if def.Description == "" {
				t.Error("missing Description")
			}
		})
	}
}
