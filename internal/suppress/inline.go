package suppress

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// commentPrefixes are the language-agnostic comment markers we recognize.
var commentPrefixes = []string{"//", "#", "--", "/*", "<!--", "*"}

// ScanInline walks the workspace directory and collects all governor:suppress annotations.
// Returns a map from relative file path to the inline suppressions found in that file.
func ScanInline(workspacePath string) (map[string][]InlineSuppression, error) {
	result := make(map[string][]InlineSuppression)

	err := filepath.Walk(workspacePath, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return nil // skip errors
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == ".git" || base == "node_modules" || base == "vendor" || base == ".governor" {
				return filepath.SkipDir
			}
			return nil
		}
		// Skip binary and very large files
		if info.Size() > 1*1024*1024 { // 1MB limit for inline scanning
			return nil
		}

		rel, relErr := filepath.Rel(workspacePath, path)
		if relErr != nil {
			return nil
		}

		suppressions := scanFile(path, rel)
		if len(suppressions) > 0 {
			result[rel] = suppressions
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// scanFile reads a single file and extracts governor:suppress annotations.
func scanFile(absPath, relPath string) []InlineSuppression {
	f, err := os.Open(absPath)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var result []InlineSuppression
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		checkID, reason, ok := parseSuppressionComment(line)
		if !ok {
			continue
		}
		result = append(result, InlineSuppression{
			CheckID: checkID,
			Reason:  reason,
			File:    relPath,
			Line:    lineNum,
		})
	}
	return result
}

// parseSuppressionComment extracts the check ID and optional reason from a line
// containing "governor:suppress <check-id>" or "governor:suppress <check-id> -- reason".
func parseSuppressionComment(line string) (checkID, reason string, ok bool) {
	line = strings.TrimSpace(line)

	// Strip comment prefix
	commentBody := ""
	for _, prefix := range commentPrefixes {
		if strings.HasPrefix(line, prefix) {
			commentBody = strings.TrimSpace(line[len(prefix):])
			break
		}
	}
	if commentBody == "" {
		return "", "", false
	}

	// Strip trailing comment closers
	commentBody = strings.TrimSuffix(commentBody, "*/")
	commentBody = strings.TrimSuffix(commentBody, "-->")
	commentBody = strings.TrimSpace(commentBody)

	const marker = "governor:suppress"
	idx := strings.Index(strings.ToLower(commentBody), marker)
	if idx < 0 {
		return "", "", false
	}

	rest := strings.TrimSpace(commentBody[idx+len(marker):])
	if rest == "" {
		return "", "", false
	}

	// Split on " -- " for optional reason
	if dashIdx := strings.Index(rest, " -- "); dashIdx >= 0 {
		checkID = strings.TrimSpace(rest[:dashIdx])
		reason = strings.TrimSpace(rest[dashIdx+4:])
	} else {
		checkID = strings.TrimSpace(rest)
	}

	// Check ID should be a single token (no spaces unless it's a glob)
	if checkID == "" {
		return "", "", false
	}
	// Reject standalone wildcard — use specific check IDs.
	if checkID == "*" {
		fmt.Fprintf(os.Stderr, "[governor] warning: ignoring wildcard suppression 'governor:suppress *' — use specific check IDs\n")
		return "", "", false
	}
	return checkID, reason, true
}
