package envsafe

import (
	"strings"
	"testing"
)

// --- Environment Variable Filtering Tests ---

func TestAIEnv_FiltersSecrets(t *testing.T) {
	env := []string{
		"PATH=/usr/bin:/bin",
		"HOME=/home/user",
		"SECRET_KEY=supersecret123",
		"DATABASE_URL=postgres://user:pass@host/db",
		"AWS_SECRET_ACCESS_KEY=myawssecret",
		"GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz",
		"MY_CUSTOM_VAR=should_not_pass",
		"OPENAI_API_KEY=sk-test1234",
	}

	result := AIEnv(env)

	allowed := map[string]bool{
		"PATH":           false,
		"HOME":           false,
		"OPENAI_API_KEY": false,
	}
	blocked := []string{
		"SECRET_KEY", "DATABASE_URL", "AWS_SECRET_ACCESS_KEY",
		"GITHUB_TOKEN", "MY_CUSTOM_VAR",
	}

	for _, kv := range result {
		parts := strings.SplitN(kv, "=", 2)
		key := parts[0]
		if _, ok := allowed[key]; ok {
			allowed[key] = true
		}
		for _, b := range blocked {
			if key == b {
				t.Errorf("blocked env var %q leaked through to AI env", b)
			}
		}
	}

	for key, found := range allowed {
		if !found {
			t.Errorf("expected allowed env var %q to be present", key)
		}
	}
}

func TestAIEnv_PathSanitization(t *testing.T) {
	env := []string{
		"PATH=/usr/bin:.:/tmp/../etc:relative/path:/sbin",
	}

	result := AIEnv(env)
	var pathVal string
	for _, kv := range result {
		if strings.HasPrefix(kv, "PATH=") {
			pathVal = kv[5:]
			break
		}
	}

	// Relative paths (., .., relative/path) should be removed
	parts := strings.Split(pathVal, ":")
	for _, part := range parts {
		if part == "." || part == ".." || !strings.HasPrefix(part, "/") {
			t.Errorf("PATH contains unsafe entry: %q", part)
		}
	}
}

func TestAIEnv_EmptyInput(t *testing.T) {
	result := AIEnv(nil)
	// Should at least have PATH
	found := false
	for _, kv := range result {
		if strings.HasPrefix(kv, "PATH=") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected default PATH even with nil input")
	}
}

func TestAIEnv_EmptyPath(t *testing.T) {
	env := []string{
		"PATH=",
		"HOME=/home/user",
	}
	result := AIEnv(env)

	var pathVal string
	for _, kv := range result {
		if strings.HasPrefix(kv, "PATH=") {
			pathVal = kv[5:]
			break
		}
	}

	if pathVal == "" {
		t.Error("expected non-empty PATH even when input PATH is empty")
	}
}

func TestAIEnv_MaliciousPathEntries(t *testing.T) {
	env := []string{
		"PATH=/usr/bin:/bin:/tmp/evil with spaces:/home/../../../etc",
	}

	result := AIEnv(env)
	var pathVal string
	for _, kv := range result {
		if strings.HasPrefix(kv, "PATH=") {
			pathVal = kv[5:]
			break
		}
	}

	// Path traversal should be cleaned
	if strings.Contains(pathVal, "/../") {
		t.Error("PATH contains unclean traversal")
	}
}

func TestAIEnv_DuplicateKeys(t *testing.T) {
	env := []string{
		"HOME=/home/user1",
		"HOME=/home/user2",
	}

	result := AIEnv(env)
	homeCount := 0
	for _, kv := range result {
		if strings.HasPrefix(kv, "HOME=") {
			homeCount++
		}
	}
	if homeCount != 1 {
		t.Errorf("expected exactly 1 HOME entry, got %d", homeCount)
	}
}

func TestAIEnv_MalformedEntries(t *testing.T) {
	env := []string{
		"NOEQUALSSIGN",
		"=NOKEY",
		"VALID=value",
		"OPENAI_API_KEY=test-key",
	}

	result := AIEnv(env)
	for _, kv := range result {
		if kv == "NOEQUALSSIGN" || kv == "=NOKEY" {
			t.Errorf("malformed entry leaked: %q", kv)
		}
	}
}

func TestAIEnv_Deterministic(t *testing.T) {
	env := []string{
		"OPENAI_API_KEY=key1",
		"HOME=/home/user",
		"PATH=/usr/bin",
		"ANTHROPIC_API_KEY=key2",
	}

	r1 := AIEnv(env)
	r2 := AIEnv(env)

	if len(r1) != len(r2) {
		t.Fatal("expected deterministic output length")
	}
	for i := range r1 {
		if r1[i] != r2[i] {
			t.Errorf("non-deterministic output at %d: %q vs %q", i, r1[i], r2[i])
		}
	}
}

func TestAIEnv_AllAllowedKeys(t *testing.T) {
	// Verify all keys in the allowlist are actually forwarded
	env := make([]string, 0, len(aiAllowedEnv))
	for key := range aiAllowedEnv {
		env = append(env, key+"=test-value")
	}

	result := AIEnv(env)
	resultMap := make(map[string]string)
	for _, kv := range result {
		parts := strings.SplitN(kv, "=", 2)
		resultMap[parts[0]] = parts[1]
	}

	for key := range aiAllowedEnv {
		if _, ok := resultMap[key]; !ok {
			// PATH might be sanitized to something different
			if key == "PATH" {
				continue
			}
			t.Errorf("allowed key %q not present in output", key)
		}
	}
}

func TestCodexEnv_CompatibilityWrapper(t *testing.T) {
	env := []string{"HOME=/home/user"}
	r1 := AIEnv(env)
	r2 := CodexEnv(env)
	if len(r1) != len(r2) {
		t.Fatal("CodexEnv and AIEnv should produce same output")
	}
	for i := range r1 {
		if r1[i] != r2[i] {
			t.Errorf("mismatch at %d: %q vs %q", i, r1[i], r2[i])
		}
	}
}
