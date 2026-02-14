package redact

import "regexp"

var (
	privateKeyPattern = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	bearerPattern     = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}`)
	tokenAssign       = regexp.MustCompile(`(?i)\b(api[_-]?key|secret|token|password|passwd|pwd)\b(\s*[:=]\s*)(["']?)([A-Za-z0-9._~+/=-]{8,})(["']?)`)
	awsAccessKey      = regexp.MustCompile(`\b(A3T|AKIA|ASIA|AGPA|AIDA|ANPA|ANVA|AROA|AIPA)[0-9A-Z]{16}\b`)
	githubToken       = regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`)

	slackWebhook   = regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+`)
	discordWebhook = regexp.MustCompile(`https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+`)
	anthropicKey   = regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}\b`)
	jwtToken       = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)
	sqlConnString  = regexp.MustCompile(`(?i)\b(mysql|postgres|postgresql|mongodb|mongodb\+srv|mssql|sqlserver)://[^\s"'` + "`" + `]{8,}`)
	npmToken       = regexp.MustCompile(`\bnpm_[A-Za-z0-9]{20,}\b`)
	genericBase64  = regexp.MustCompile(`(?i)\b(secret|private[_-]?key)\s*=\s*["']?[A-Za-z0-9+/]{40,}={0,2}["']?`)
)

// Text masks common secret/token patterns before logs or artifacts are persisted.
func Text(in string) string {
	out := in
	out = privateKeyPattern.ReplaceAllString(out, "[REDACTED PRIVATE KEY]")
	out = bearerPattern.ReplaceAllString(out, "Bearer [REDACTED]")
	out = awsAccessKey.ReplaceAllString(out, "[REDACTED_AWS_ACCESS_KEY]")
	out = githubToken.ReplaceAllString(out, "[REDACTED_GITHUB_TOKEN]")
	out = slackWebhook.ReplaceAllString(out, "[REDACTED_SLACK_WEBHOOK]")
	out = discordWebhook.ReplaceAllString(out, "[REDACTED_DISCORD_WEBHOOK]")
	out = anthropicKey.ReplaceAllString(out, "[REDACTED_ANTHROPIC_KEY]")
	out = jwtToken.ReplaceAllString(out, "[REDACTED_JWT]")
	out = sqlConnString.ReplaceAllString(out, "[REDACTED_CONNECTION_STRING]")
	out = npmToken.ReplaceAllString(out, "[REDACTED_NPM_TOKEN]")
	out = genericBase64.ReplaceAllString(out, "[REDACTED_BASE64_SECRET]")
	// tokenAssign is applied last — more specific patterns above take precedence.
	out = tokenAssign.ReplaceAllString(out, `${1}${2}${3}[REDACTED]${5}`)
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
