// Package detect provides project type auto-detection by inspecting
// well-known files and dependency manifests in a source directory.
package detect

import (
	"bufio"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"strings"
)

// Result holds the detected project type.
// Type is a machine-readable identifier (e.g. "nextjs", "express", "go").
// Label is a human-readable name (e.g. "Next.js", "Express", "Go").
// Both fields are empty strings when the project type is unknown.
type Result struct {
	Type  string
	Label string
}

// Project inspects the directory at root and returns the detected project type.
// Detection signals are checked in priority order; the first match wins.
func Project(root string) Result {
	// 1. Next.js — config file presence
	for _, name := range []string{"next.config.js", "next.config.mjs", "next.config.ts"} {
		if fileExists(root, name) {
			return Result{Type: "nextjs", Label: "Next.js"}
		}
	}

	// 2. Supabase — supabase/config.toml
	if fileExists(root, filepath.Join("supabase", "config.toml")) {
		return Result{Type: "supabase", Label: "Supabase"}
	}

	// 3–4. Node framework detection via package.json deps
	deps := readPackageJSONDeps(root)
	if _, ok := deps["express"]; ok {
		return Result{Type: "express", Label: "Express"}
	}
	if _, ok := deps["fastify"]; ok {
		return Result{Type: "fastify", Label: "Fastify"}
	}

	// 5–7. Python framework detection via requirements.txt
	reqLines := readFileLines(root, "requirements.txt")
	for _, line := range reqLines {
		pkg := extractPythonPackage(line)
		switch pkg {
		case "fastapi":
			return Result{Type: "fastapi", Label: "FastAPI"}
		case "flask":
			return Result{Type: "flask", Label: "Flask"}
		case "django":
			return Result{Type: "django", Label: "Django"}
		}
	}

	// 8. Go — go.mod
	if fileExists(root, "go.mod") {
		return Result{Type: "go", Label: "Go"}
	}

	// 9. Rust — Cargo.toml
	if fileExists(root, "Cargo.toml") {
		return Result{Type: "rust", Label: "Rust"}
	}

	// 10. Node.js fallback — package.json exists
	if fileExists(root, "package.json") {
		return Result{Type: "node", Label: "Node.js"}
	}

	// 11. Python fallback — requirements.txt, pyproject.toml, or setup.py
	for _, name := range []string{"requirements.txt", "pyproject.toml", "setup.py"} {
		if fileExists(root, name) {
			return Result{Type: "python", Label: "Python"}
		}
	}

	// 12. Unknown
	return Result{}
}

// fileExists reports whether a regular file (or symlink to one) exists at
// dir/name.
func fileExists(dir, name string) bool {
	info, err := os.Stat(filepath.Join(dir, name))
	return err == nil && !info.IsDir()
}

// readPackageJSONDeps reads package.json from root and returns the merged
// map of dependencies and devDependencies. Returns nil if the file is
// absent or unparseable.
func readPackageJSONDeps(root string) map[string]string {
	data, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		return nil
	}

	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}

	merged := make(map[string]string, len(pkg.Dependencies)+len(pkg.DevDependencies))
	maps.Copy(merged, pkg.Dependencies)
	maps.Copy(merged, pkg.DevDependencies)
	return merged
}

// readFileLines reads root/name and returns non-empty, non-comment lines
// with surrounding whitespace trimmed. Returns nil if the file cannot be read.
func readFileLines(root, name string) []string {
	f, err := os.Open(filepath.Join(root, name))
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

// extractPythonPackage returns the lowercased package name from a pip
// requirements line, stripping version specifiers and extras.
// For example, "FastAPI>=0.100" → "fastapi", "flask[async]==3.0" → "flask".
func extractPythonPackage(line string) string {
	// Strip extras like [async]
	if idx := strings.IndexByte(line, '['); idx != -1 {
		line = line[:idx]
	}
	// Strip version specifiers: ==, >=, <=, ~=, !=, <, >
	for _, sep := range []string{"==", ">=", "<=", "~=", "!=", "<", ">"} {
		if idx := strings.Index(line, sep); idx != -1 {
			line = line[:idx]
		}
	}
	return strings.ToLower(strings.TrimSpace(line))
}
