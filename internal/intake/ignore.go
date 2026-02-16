package intake

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// IgnoreRules holds compiled patterns from a .governorignore file.
type IgnoreRules struct {
	patterns []ignorePattern
}

type ignorePattern struct {
	negated  bool
	dirOnly  bool
	regex    *regexp.Regexp
	original string
}

// LoadIgnoreFile reads and parses a .governorignore file. Returns nil rules
// (not an error) if the file does not exist.
func LoadIgnoreFile(path string) (*IgnoreRules, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return ParseIgnorePatterns(lines), nil
}

// ParseIgnorePatterns parses gitignore-style pattern lines into IgnoreRules.
func ParseIgnorePatterns(lines []string) *IgnoreRules {
	rules := &IgnoreRules{}
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		p := ignorePattern{original: line}

		if strings.HasPrefix(line, "!") {
			p.negated = true
			line = line[1:]
		}

		if strings.HasSuffix(line, "/") {
			p.dirOnly = true
			line = strings.TrimSuffix(line, "/")
		}

		re, err := regexp.Compile(ignoreGlobToRegex(line))
		if err != nil {
			continue
		}
		p.regex = re
		rules.patterns = append(rules.patterns, p)
	}
	return rules
}

// ShouldIgnore returns true if the given path should be excluded.
// isDir should be true when the path is a directory.
// nil receiver is safe and always returns false.
func (r *IgnoreRules) ShouldIgnore(relPath string, isDir bool) bool {
	if r == nil || len(r.patterns) == 0 {
		return false
	}
	relPath = filepath.ToSlash(strings.TrimSpace(relPath))
	if relPath == "" {
		return false
	}

	// Last matching pattern wins (standard gitignore semantics).
	ignored := false
	for _, p := range r.patterns {
		if p.dirOnly && !isDir {
			continue
		}
		if p.regex.MatchString(relPath) {
			ignored = !p.negated
		}
	}
	return ignored
}

// ignoreGlobToRegex converts a gitignore-style glob to a regex.
func ignoreGlobToRegex(glob string) string {
	var b strings.Builder
	b.WriteString("^")
	r := []rune(filepath.ToSlash(glob))

	// If the pattern has no slash, match against the basename anywhere.
	hasSlash := false
	for _, ch := range r {
		if ch == '/' {
			hasSlash = true
			break
		}
	}
	if !hasSlash {
		b.WriteString("(?:.*/)?")
	}

	for i := 0; i < len(r); i++ {
		switch r[i] {
		case '*':
			if i+1 < len(r) && r[i+1] == '*' {
				if i+2 < len(r) && r[i+2] == '/' {
					b.WriteString("(?:.*/)?")
					i += 2
					continue
				}
				b.WriteString(".*")
				i++
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		case '.', '+', '(', ')', '[', ']', '{', '}', '^', '$', '|', '\\':
			b.WriteString("\\")
			b.WriteRune(r[i])
		default:
			b.WriteRune(r[i])
		}
	}
	b.WriteString("$")
	return b.String()
}
