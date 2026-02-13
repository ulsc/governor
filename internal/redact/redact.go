package redact

import "regexp"

var (
	privateKeyPattern = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	bearerPattern     = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}`)
	tokenAssign       = regexp.MustCompile(`(?i)\b(api[_-]?key|secret|token|password|passwd|pwd)\b(\s*[:=]\s*)(["']?)([A-Za-z0-9._~+/=-]{8,})(["']?)`)
	awsAccessKey      = regexp.MustCompile(`\b(A3T|AKIA|ASIA|AGPA|AIDA|ANPA|ANVA|AROA|AIPA)[0-9A-Z]{16}\b`)
	githubToken       = regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`)
)

// Text masks common secret/token patterns before logs or artifacts are persisted.
func Text(in string) string {
	out := in
	out = privateKeyPattern.ReplaceAllString(out, "[REDACTED PRIVATE KEY]")
	out = bearerPattern.ReplaceAllString(out, "Bearer [REDACTED]")
	out = tokenAssign.ReplaceAllString(out, `${1}${2}${3}[REDACTED]${5}`)
	out = awsAccessKey.ReplaceAllString(out, "[REDACTED_AWS_ACCESS_KEY]")
	out = githubToken.ReplaceAllString(out, "[REDACTED_GITHUB_TOKEN]")
	return out
}

func Strings(in []string) []string {
	if len(in) == 0 {
		return in
	}
	out := make([]string, 0, len(in))
	for _, item := range in {
		out = append(out, Text(item))
	}
	return out
}
