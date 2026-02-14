package redact

import (
	"strings"
	"testing"
)

func TestText_RedactsCommonSecrets(t *testing.T) {
	in := strings.Join([]string{
		`token=sk_live_abcdefghijklmnopqrstuvwxyz`,
		`Authorization: Bearer abcdefghijklmnopqrstuvwxyz`,
		`aws=AKIAABCDEFGHIJKLMNOP`,
		`ghp_abcdefghijklmnopqrstuvwxyz0123456789`,
	}, "\n")

	out := Text(in)
	for _, needle := range []string{
		"sk_live_abcdefghijklmnopqrstuvwxyz",
		"Bearer abcdefghijklmnopqrstuvwxyz",
		"AKIAABCDEFGHIJKLMNOP",
		"ghp_abcdefghijklmnopqrstuvwxyz0123456789",
	} {
		if strings.Contains(out, needle) {
			t.Fatalf("expected output to redact %q", needle)
		}
	}
}

func TestText_RedactsExpandedPatterns(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		secret string
		marker string
	}{
		{
			name:   "slack webhook",
			input:  `url: https://hooks.slack.com/services/T0ABC1234/B0DEF5678/abcdefghijklmnop`,
			secret: "hooks.slack.com/services/T0ABC1234",
			marker: "[REDACTED_SLACK_WEBHOOK]",
		},
		{
			name:   "discord webhook",
			input:  `https://discord.com/api/webhooks/123456789012345678/abcdefghij_KLMNOPQRSTUV-wxyz0123456789`,
			secret: "discord.com/api/webhooks/123456789012345678",
			marker: "[REDACTED_DISCORD_WEBHOOK]",
		},
		{
			name:   "discordapp webhook",
			input:  `https://discordapp.com/api/webhooks/123456789012345678/abcdefghij_KLMNOPQRSTUV-wxyz0123456789`,
			secret: "discordapp.com/api/webhooks/123456789012345678",
			marker: "[REDACTED_DISCORD_WEBHOOK]",
		},
		{
			name:   "anthropic key",
			input:  `key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789`,
			secret: "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789",
			marker: "[REDACTED_ANTHROPIC_KEY]",
		},
		{
			name:   "jwt token",
			input:  `token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U`,
			secret: "eyJhbGciOiJIUzI1NiJ9",
			marker: "[REDACTED_JWT]",
		},
		{
			name:   "postgres connection string",
			input:  `dsn: postgres://user:secretpass@db.example.com:5432/mydb?sslmode=require`,
			secret: "postgres://user:secretpass@db.example.com",
			marker: "[REDACTED_CONNECTION_STRING]",
		},
		{
			name:   "mysql connection string",
			input:  `dsn: mysql://root:password123@localhost:3306/app`,
			secret: "mysql://root:password123@localhost",
			marker: "[REDACTED_CONNECTION_STRING]",
		},
		{
			name:   "mongodb connection string",
			input:  `MONGO_URI=mongodb+srv://user:pass@cluster0.example.net/db`,
			secret: "mongodb+srv://user:pass@cluster0",
			marker: "[REDACTED_CONNECTION_STRING]",
		},
		{
			name:   "npm token",
			input:  `//registry.npmjs.org/:_authToken=npm_abcdefghijklmnopqrstuvwxyz0123`,
			secret: "npm_abcdefghijklmnopqrstuvwxyz0123",
			marker: "[REDACTED_NPM_TOKEN]",
		},
		{
			name:   "generic base64 secret",
			input:  `secret=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw`,
			secret: "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw",
			marker: "[REDACTED_BASE64_SECRET]",
		},
		{
			name:   "generic base64 private_key",
			input:  `private_key="YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw"`,
			secret: "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw",
			marker: "[REDACTED_BASE64_SECRET]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := Text(tt.input)
			if strings.Contains(out, tt.secret) {
				t.Fatalf("expected %q to be redacted, got: %s", tt.secret, out)
			}
			if !strings.Contains(out, tt.marker) {
				t.Fatalf("expected marker %q in output, got: %s", tt.marker, out)
			}
		})
	}
}

func TestText_FalsePositiveGuards(t *testing.T) {
	safe := []string{
		`The word "secret" is not a secret value`,
		`token=abc`,
		`password=short`,
		`This is a normal URL: https://example.com/path`,
		`eyJh.short.tok`,
		`npm_short`,
	}
	for _, input := range safe {
		out := Text(input)
		if out != input {
			t.Fatalf("expected no change for safe input %q, got %q", input, out)
		}
	}
}
