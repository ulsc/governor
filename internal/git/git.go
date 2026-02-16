package git

import (
	"fmt"
	"os/exec"
	"strings"
)

// RepoRoot returns the git repository root for the given path,
// or an error if the path is not inside a git repository.
func RepoRoot(path string) (string, error) {
	cmd := exec.Command("git", "-C", path, "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("not a git repository (or git not installed): %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// ChangedFiles returns file paths changed between ref and the working tree.
// If ref is empty, defaults to HEAD. Only existing (non-deleted) files are
// returned. Paths are relative to the repository root.
func ChangedFiles(repoRoot, ref string) ([]string, error) {
	if ref == "" {
		ref = "HEAD"
	}
	cmd := exec.Command("git", "-C", repoRoot, "diff", "--name-only", "--diff-filter=d", ref)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git diff --name-only %s: %w", ref, err)
	}
	return parseLines(string(out)), nil
}

// StagedFiles returns file paths staged in the git index.
// Only existing (non-deleted) files are returned.
// Paths are relative to the repository root.
func StagedFiles(repoRoot string) ([]string, error) {
	cmd := exec.Command("git", "-C", repoRoot, "diff", "--cached", "--name-only", "--diff-filter=d")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git diff --cached --name-only: %w", err)
	}
	return parseLines(string(out)), nil
}

func parseLines(s string) []string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}
