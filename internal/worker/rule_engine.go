package worker

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"governor/internal/checks"
	"governor/internal/model"
)

const (
	defaultDetectorMaxMatches = 5
	defaultRuleConfidence     = 0.7
	maxRuleFileBytes          = 2 * 1024 * 1024
	regexMatchTimeout         = 5 * time.Second
)

type compiledDetector struct {
	detector checks.RuleDetector
	pattern  string
	regex    *regexp.Regexp
}

type ruleExecResult struct {
	payload workerOutput
	logText string
	err     error
}

func executeRuleCheck(ctx context.Context, workspace string, manifest model.InputManifest, checkDef checks.Definition) ruleExecResult {
	checkDef = checks.NormalizeDefinition(checkDef)
	compiled, compileErr := compileDetectors(checkDef.Rule.Detectors)
	if compileErr != nil {
		return ruleExecResult{err: compileErr}
	}

	findings := make([]model.Finding, 0, 16)
	notes := make([]string, 0, 8)
	var log strings.Builder
	log.WriteString("[governor] deterministic rule engine\n")
	log.WriteString(fmt.Sprintf("[governor] track=%s detectors=%d\n", checkDef.ID, len(compiled)))

	scannedFiles := 0
	skippedLarge := 0
	skippedScope := 0
	matchedFiles := 0
	now := time.Now().UTC()

	for _, file := range manifest.Files {
		select {
		case <-ctx.Done():
			return ruleExecResult{
				payload: workerOutput{
					Summary:  "deterministic rule scan interrupted by context",
					Notes:    append(notes, "scan interrupted"),
					Findings: findings,
				},
				logText: log.String(),
				err:     ctx.Err(),
			}
		default:
		}

		rel := filepath.ToSlash(strings.TrimSpace(file.Path))
		if rel == "" {
			continue
		}
		if !scopeAllows(rel, checkDef.Scope) {
			skippedScope++
			continue
		}
		abs := filepath.Join(workspace, filepath.FromSlash(rel))
		contentBytes, err := os.ReadFile(abs)
		if err != nil {
			notes = append(notes, fmt.Sprintf("read %s: %v", rel, err))
			continue
		}
		if len(contentBytes) > maxRuleFileBytes {
			skippedLarge++
			notes = append(notes, fmt.Sprintf("skipped %s (size=%d exceeds %d)", rel, len(contentBytes), maxRuleFileBytes))
			continue
		}

		content := string(contentBytes)
		scannedFiles++
		fileMatched := false
		for _, detector := range compiled {
			maxMatches := detector.detector.MaxMatches
			if maxMatches <= 0 {
				maxMatches = defaultDetectorMaxMatches
			}
			matchRanges := detectorMatches(detector, content, maxMatches)
			if len(matchRanges) == 0 {
				continue
			}
			fileMatched = true
			for idx, pair := range matchRanges {
				finding := buildRuleFinding(checkDef, detector.detector, rel, content, pair[0], pair[1], idx+1, now)
				findings = append(findings, finding)
				log.WriteString(fmt.Sprintf("[match] file=%s detector=%s finding=%s\n", rel, detector.detector.ID, finding.ID))
			}
		}
		if fileMatched {
			matchedFiles++
		}
	}

	summary := fmt.Sprintf(
		"deterministic rule scan completed: findings=%d files_scanned=%d files_matched=%d",
		len(findings),
		scannedFiles,
		matchedFiles,
	)
	notes = append(notes,
		fmt.Sprintf("files_scanned=%d", scannedFiles),
		fmt.Sprintf("files_scope_skipped=%d", skippedScope),
		fmt.Sprintf("files_large_skipped=%d", skippedLarge),
	)
	payload := workerOutput{
		Summary:  summary,
		Notes:    notes,
		Findings: findings,
	}
	return ruleExecResult{
		payload: payload,
		logText: log.String(),
	}
}

func compileDetectors(detectors []checks.RuleDetector) ([]compiledDetector, error) {
	out := make([]compiledDetector, 0, len(detectors))
	for _, detector := range detectors {
		item := compiledDetector{
			detector: detector,
			pattern:  detector.Pattern,
		}
		switch detector.Kind {
		case checks.RuleDetectorContains, checks.RuleDetectorRegex:
		default:
			return nil, fmt.Errorf("unsupported detector kind %q for %q", detector.Kind, detector.ID)
		}
		if !detector.CaseSensitive {
			item.pattern = strings.ToLower(item.pattern)
		}
		if detector.Kind == checks.RuleDetectorRegex {
			pattern := detector.Pattern
			if !detector.CaseSensitive {
				pattern = "(?i)" + pattern
			}
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("compile detector %q regex: %w", detector.ID, err)
			}
			item.regex = re
		}
		out = append(out, item)
	}
	return out, nil
}

func detectorMatches(detector compiledDetector, content string, maxMatches int) [][2]int {
	switch detector.detector.Kind {
	case checks.RuleDetectorRegex:
		return regexMatchesWithTimeout(detector.regex, content, maxMatches, detector.detector.ID)
	case checks.RuleDetectorContains:
		return containsMatches(content, detector.pattern, detector.detector.CaseSensitive, maxMatches)
	default:
		return nil
	}
}

func regexMatchesWithTimeout(re *regexp.Regexp, content string, maxMatches int, detectorID string) [][2]int {
	type result struct {
		matches [][2]int
	}
	ch := make(chan result, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "[governor] warning: regex panic in detector %s: %v\n", detectorID, r)
				ch <- result{matches: nil}
			}
		}()
		raw := re.FindAllStringIndex(content, maxMatches)
		out := make([][2]int, 0, len(raw))
		for _, pair := range raw {
			if len(pair) != 2 {
				continue
			}
			out = append(out, [2]int{pair[0], pair[1]})
		}
		ch <- result{matches: out}
	}()

	select {
	case res := <-ch:
		return res.matches
	case <-time.After(regexMatchTimeout):
		fmt.Fprintf(os.Stderr, "[governor] warning: regex match timed out after %s for detector %s\n", regexMatchTimeout, detectorID)
		return nil
	}
}

func containsMatches(content string, needle string, caseSensitive bool, maxMatches int) [][2]int {
	if strings.TrimSpace(needle) == "" || maxMatches <= 0 {
		return nil
	}
	haystack := content
	if !caseSensitive {
		haystack = strings.ToLower(content)
	}
	out := make([][2]int, 0, maxMatches)
	offset := 0
	for len(out) < maxMatches && offset <= len(haystack)-len(needle) {
		idx := strings.Index(haystack[offset:], needle)
		if idx < 0 {
			break
		}
		start := offset + idx
		end := start + len(needle)
		out = append(out, [2]int{start, end})
		offset = end
	}
	return out
}

func buildRuleFinding(checkDef checks.Definition, detector checks.RuleDetector, filePath string, content string, start int, end int, index int, now time.Time) model.Finding {
	confidence := detector.Confidence
	if confidence <= 0 {
		confidence = checkDef.ConfidenceHint
	}
	if confidence <= 0 {
		confidence = defaultRuleConfidence
	}
	severity := strings.ToLower(strings.TrimSpace(detector.Severity))
	if severity == "" {
		severity = strings.ToLower(strings.TrimSpace(checkDef.SeverityHint))
	}
	if severity == "" {
		severity = "medium"
	}
	category := strings.ToLower(strings.TrimSpace(detector.Category))
	if category == "" && len(checkDef.CategoriesHint) > 0 {
		category = strings.ToLower(strings.TrimSpace(checkDef.CategoriesHint[0]))
	}
	if category == "" {
		category = "input_validation"
	}
	title := strings.TrimSpace(detector.Title)
	if title == "" {
		title = fmt.Sprintf("Rule detector %s matched", detector.ID)
	}
	remediation := strings.TrimSpace(detector.Remediation)
	if remediation == "" {
		remediation = "Review prompt handling boundaries and reject instruction override/jailbreak content before model invocation."
	}
	evidence := buildEvidenceSnippet(content, start, end)
	if evidence == "" {
		evidence = "(matched indicator, no snippet available)"
	}
	return model.Finding{
		ID:          fmt.Sprintf("%s-%s-%03d", checkDef.ID, detector.ID, index),
		Title:       title,
		Severity:    severity,
		Category:    category,
		Evidence:    evidence,
		Impact:      "Potential prompt injection or instruction override behavior may weaken model safety and policy controls.",
		Remediation: remediation,
		FileRefs:    []string{filePath},
		Confidence:  confidence,
		SourceTrack: checkDef.ID,
		CreatedAt:   now,
	}
}

func buildEvidenceSnippet(content string, start int, end int) string {
	if start < 0 || end < start || start > len(content) {
		return ""
	}
	if end > len(content) {
		end = len(content)
	}
	left := start - 80
	right := end + 80
	if left < 0 {
		left = 0
	}
	if right > len(content) {
		right = len(content)
	}
	snippet := strings.TrimSpace(content[left:right])
	snippet = strings.ReplaceAll(snippet, "\r", " ")
	snippet = strings.ReplaceAll(snippet, "\n", " ")
	snippet = strings.ReplaceAll(snippet, "\t", " ")
	if left > 0 {
		snippet = "..." + snippet
	}
	if right < len(content) {
		snippet = snippet + "..."
	}
	return strings.TrimSpace(snippet)
}

func scopeAllows(path string, scope checks.Scope) bool {
	path = filepath.ToSlash(strings.TrimSpace(path))
	if path == "" {
		return false
	}

	includes := scope.IncludeGlobs
	if len(includes) == 0 {
		includes = []string{"**/*"}
	}
	includeMatch := false
	for _, glob := range includes {
		if globMatch(glob, path) {
			includeMatch = true
			break
		}
	}
	if !includeMatch {
		return false
	}
	for _, glob := range scope.ExcludeGlobs {
		if globMatch(glob, path) {
			return false
		}
	}
	return true
}

func globMatch(glob string, value string) bool {
	glob = strings.TrimSpace(glob)
	if glob == "" {
		return false
	}
	re, err := regexp.Compile(globToRegex(glob))
	if err != nil {
		return false
	}
	return re.MatchString(value)
}

func globToRegex(glob string) string {
	var b strings.Builder
	b.WriteString("^")
	r := []rune(filepath.ToSlash(glob))
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
