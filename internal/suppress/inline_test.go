package suppress

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseSuppressionComment(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantID  string
		wantMsg string
		wantOK  bool
	}{
		{
			name:   "go comment",
			line:   "// governor:suppress hardcoded_credentials -- test fixture",
			wantID: "hardcoded_credentials", wantMsg: "test fixture", wantOK: true,
		},
		{
			name:   "python comment",
			line:   "# governor:suppress secrets_check -- placeholder values",
			wantID: "secrets_check", wantMsg: "placeholder values", wantOK: true,
		},
		{
			name:   "html comment",
			line:   "<!-- governor:suppress xss_check -- template -->",
			wantID: "xss_check", wantMsg: "template", wantOK: true,
		},
		{
			name:   "no reason",
			line:   "// governor:suppress my_check",
			wantID: "my_check", wantMsg: "", wantOK: true,
		},
		{
			name:   "not a comment",
			line:   "const x = 42",
			wantID: "", wantMsg: "", wantOK: false,
		},
		{
			name:   "comment without suppress",
			line:   "// just a regular comment",
			wantID: "", wantMsg: "", wantOK: false,
		},
		{
			name:   "block comment",
			line:   "/* governor:suppress block_check -- block reason */",
			wantID: "block_check", wantMsg: "block reason", wantOK: true,
		},
		{
			name:   "sql comment",
			line:   "-- governor:suppress sql_check",
			wantID: "sql_check", wantMsg: "", wantOK: true,
		},
		{
			name:   "empty suppress marker",
			line:   "// governor:suppress",
			wantID: "", wantMsg: "", wantOK: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id, msg, ok := parseSuppressionComment(tc.line)
			if ok != tc.wantOK {
				t.Errorf("parseSuppressionComment(%q) ok=%v, want %v", tc.line, ok, tc.wantOK)
			}
			if id != tc.wantID {
				t.Errorf("parseSuppressionComment(%q) id=%q, want %q", tc.line, id, tc.wantID)
			}
			if msg != tc.wantMsg {
				t.Errorf("parseSuppressionComment(%q) msg=%q, want %q", tc.line, msg, tc.wantMsg)
			}
		})
	}
}

func TestScanInline(t *testing.T) {
	dir := t.TempDir()

	// Create a Go file with a suppression annotation.
	goFile := filepath.Join(dir, "main.go")
	goContent := `package main

// governor:suppress hardcoded_credentials -- test fixture
const testKey = "sk-test-1234"

func main() {}
`
	if err := os.WriteFile(goFile, []byte(goContent), 0o600); err != nil {
		t.Fatal(err)
	}

	// Create a Python file with a suppression.
	pyFile := filepath.Join(dir, "script.py")
	pyContent := `# governor:suppress secrets_check -- placeholder
API_KEY = "test-key"
`
	if err := os.WriteFile(pyFile, []byte(pyContent), 0o600); err != nil {
		t.Fatal(err)
	}

	// Create a file without suppressions.
	plainFile := filepath.Join(dir, "clean.go")
	if err := os.WriteFile(plainFile, []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := ScanInline(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("expected 2 files with suppressions, got %d", len(result))
	}

	goSuppressions, ok := result["main.go"]
	if !ok {
		t.Fatal("expected suppressions in main.go")
	}
	if len(goSuppressions) != 1 {
		t.Fatalf("expected 1 suppression in main.go, got %d", len(goSuppressions))
	}
	if goSuppressions[0].CheckID != "hardcoded_credentials" {
		t.Errorf("expected check=hardcoded_credentials, got %q", goSuppressions[0].CheckID)
	}
	if goSuppressions[0].Reason != "test fixture" {
		t.Errorf("expected reason='test fixture', got %q", goSuppressions[0].Reason)
	}
	if goSuppressions[0].Line != 3 {
		t.Errorf("expected line 3, got %d", goSuppressions[0].Line)
	}

	pySuppressions, ok := result["script.py"]
	if !ok {
		t.Fatal("expected suppressions in script.py")
	}
	if len(pySuppressions) != 1 {
		t.Fatalf("expected 1 suppression in script.py, got %d", len(pySuppressions))
	}
}

func TestScanInline_SkipsDotGit(t *testing.T) {
	dir := t.TempDir()

	// Create a .git directory with a file containing suppress marker.
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gitDir, 0o700); err != nil {
		t.Fatal(err)
	}
	gitFile := filepath.Join(gitDir, "config")
	if err := os.WriteFile(gitFile, []byte("// governor:suppress test\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := ScanInline(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("expected 0 files (skipped .git), got %d", len(result))
	}
}
