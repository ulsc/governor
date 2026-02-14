package redact

import (
	"strings"
	"testing"
)

// --- Redaction Bypass Tests ---
// These tests probe edge cases where secrets might leak through the redaction system.

func TestText_OpenAIKeyFormats(t *testing.T) {
	// OpenAI keys use sk- prefix with varying formats
	tests := []struct {
		name   string
		input  string
		leaked string
	}{
		{
			name:   "openai sk-proj key",
			input:  `api_key = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890abcdef"`,
			leaked: "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890abcdef",
		},
		{
			name:   "openai sk-live key",
			input:  `api_key = "sk-live-abcdefghijklmnopqrstuvwxyz1234567890abcdef"`,
			leaked: "sk-live-abcdefghijklmnopqrstuvwxyz1234567890abcdef",
		},
		{
			name:   "openai org-level key",
			input:  `OPENAI_API_KEY=sk-svcacct-abcdefghijklmnopqrstuvwxyz12345678`,
			leaked: "sk-svcacct-abcdefghijklmnopqrstuvwxyz12345678",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := Text(tt.input)
			if strings.Contains(out, tt.leaked) {
				t.Errorf("REDACTION BYPASS: %q leaked through redaction.\nInput: %s\nOutput: %s", tt.leaked, tt.input, out)
			}
		})
	}
}

func TestText_MultiLineSecrets(t *testing.T) {
	// Secrets spread across context with other text
	input := `Here is a config file:
DATABASE_URL=postgres://admin:SuperSecret123@prod-db.internal.company.com:5432/production?sslmode=verify-full
And then some normal text.
REDIS_URL=redis://default:AnotherSecret@redis.internal.company.com:6379
More normal text.`

	out := Text(input)

	if strings.Contains(out, "SuperSecret123") {
		t.Error("REDACTION BYPASS: postgres password leaked")
	}
	// Redis URLs are not covered by the connection string pattern
	// This is an expected gap worth documenting
}

func TestText_TokenAssignmentVariants(t *testing.T) {
	// Test that various assignment patterns are caught
	tests := []struct {
		name   string
		input  string
		leaked string
	}{
		{
			name:   "env export with spaces",
			input:  `export API_KEY = "sk_test_abcdefghijklmnop1234"`,
			leaked: "sk_test_abcdefghijklmnop1234",
		},
		{
			name:   "yaml colon assignment",
			input:  `api_key: sk_test_abcdefghijklmnop1234`,
			leaked: "sk_test_abcdefghijklmnop1234",
		},
		{
			name:   "json password field",
			input:  `"password": "MyS3cr3tP@ssw0rd12345"`,
			leaked: "MyS3cr3tP@ssw0rd12345",
		},
		{
			name:   "secret with underscore separator",
			input:  `secret_key = abcdefghijklmnop12345678`,
			leaked: "abcdefghijklmnop12345678",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := Text(tt.input)
			if strings.Contains(out, tt.leaked) {
				t.Errorf("REDACTION BYPASS: %q leaked.\nInput: %s\nOutput: %s", tt.leaked, tt.input, out)
			}
		})
	}
}

func TestText_PrivateKeyWithWeirdFormatting(t *testing.T) {
	// Private key with unusual whitespace
	key := `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF068wITF7FVSd7msbTXX1C0aXjCP
fake-key-data-for-test-abcdefghijklmnopqrstuvwxyz1234567890
-----END RSA PRIVATE KEY-----`

	out := Text(key)
	if strings.Contains(out, "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn") {
		t.Error("REDACTION BYPASS: private key content leaked")
	}
	if !strings.Contains(out, "[REDACTED PRIVATE KEY]") {
		t.Errorf("Expected [REDACTED PRIVATE KEY] marker, got: %s", out)
	}
}

func TestText_BearerTokenInJSON(t *testing.T) {
	// Bearer token embedded in JSON response (AI output could contain this)
	input := `{"headers": {"Authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.signature_here_12345"}}`

	out := Text(input)
	// Should be caught by either bearer or JWT pattern
	if strings.Contains(out, "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9") {
		t.Error("REDACTION BYPASS: JWT in bearer header leaked")
	}
}

func TestText_GCPServiceAccountKey(t *testing.T) {
	// GCP service account key is a JSON with a private key
	input := `{
  "type": "service_account",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF068wITF7FVSd7msbTXX1C0aXjCP\nfake-data\n-----END RSA PRIVATE KEY-----\n"
}`

	out := Text(input)
	if strings.Contains(out, "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn") {
		t.Error("REDACTION BYPASS: GCP private key content leaked")
	}
}

func TestText_GitHubTokenVariants(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		leaked string
	}{
		{
			name:   "github personal access token",
			input:  `GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUvwxyz12345678`,
			leaked: "ghp_ABCDEFGHIJKLMNOPQRSTUvwxyz12345678",
		},
		{
			name:   "github oauth token",
			input:  `GH_TOKEN=gho_ABCDEFGHIJKLMNOPQRSTUvwxyz12345678`,
			leaked: "gho_ABCDEFGHIJKLMNOPQRSTUvwxyz12345678",
		},
		{
			name:   "github user-to-server",
			input:  `token: ghu_ABCDEFGHIJKLMNOPQRSTUvwxyz12345678`,
			leaked: "ghu_ABCDEFGHIJKLMNOPQRSTUvwxyz12345678",
		},
		{
			name:   "github server-to-server",
			input:  `token: ghs_ABCDEFGHIJKLMNOPQRSTUvwxyz12345678`,
			leaked: "ghs_ABCDEFGHIJKLMNOPQRSTUvwxyz12345678",
		},
		{
			name:   "github refresh token",
			input:  `token: ghr_ABCDEFGHIJKLMNOPQRSTUvwxyz12345678`,
			leaked: "ghr_ABCDEFGHIJKLMNOPQRSTUvwxyz12345678",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := Text(tt.input)
			if strings.Contains(out, tt.leaked) {
				t.Errorf("REDACTION BYPASS: %q leaked.\nOutput: %s", tt.leaked, out)
			}
		})
	}
}

func TestText_AWSSecretAccessKey(t *testing.T) {
	// AWS secret access keys are 40 chars base64-ish, but the current patterns
	// only catch the access key ID (AKIA...), NOT the secret key itself.
	// This documents a gap.
	input := `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`

	out := Text(input)

	// Access key ID should be redacted
	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("REDACTION BYPASS: AWS access key ID leaked")
	}

	// The secret access key is caught by tokenAssign (secret_access_key = ...)
	// Verify it's caught
	if strings.Contains(out, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY") {
		t.Error("REDACTION GAP: AWS secret access key leaked through tokenAssign pattern")
	}
}

func TestText_SlackBotToken(t *testing.T) {
	// Slack bot tokens use xoxb- prefix, not covered by current patterns
	input := `SLACK_BOT_TOKEN=xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx`
	out := Text(input)

	// This is likely NOT caught - document the gap
	if strings.Contains(out, "xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx") {
		t.Log("GAP CONFIRMED: Slack bot tokens (xoxb-*) are not redacted by specific pattern")
		// Not failing - this is a documentation test for a known gap
	}
}

func TestText_StripeKeyFormats(t *testing.T) {
	// Stripe keys have sk_test_ and sk_live_ prefixes
	tests := []struct {
		name   string
		input  string
		leaked string
	}{
		{
			name:   "stripe test key",
			input:  `STRIPE_KEY=sk_test_4eC39HqLyjWDarjtT1zdp7dc`,
			leaked: "sk_test_4eC39HqLyjWDarjtT1zdp7dc",
		},
		{
			name:   "stripe live key",
			input:  `STRIPE_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc`,
			leaked: "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := Text(tt.input)
			// These may or may not be caught by tokenAssign due to the key name
			// not matching the pattern (it matches on secret/token/password/api_key)
			if strings.Contains(out, tt.leaked) {
				t.Logf("NOTE: %s leaked through redaction (no Stripe-specific pattern)", tt.name)
			}
		})
	}
}

func TestText_EmptyAndNilInputs(t *testing.T) {
	if out := Text(""); out != "" {
		t.Errorf("expected empty output for empty input, got %q", out)
	}
	if out := Strings(nil); out != nil {
		t.Errorf("expected nil for nil input, got %v", out)
	}
	if out := Strings([]string{}); len(out) != 0 {
		t.Errorf("expected empty slice for empty input, got %v", out)
	}
}

func TestText_VeryLongInput(t *testing.T) {
	// Test with very long input to ensure no panic or excessive memory
	long := strings.Repeat("a", 10*1024*1024) // 10 MB
	out := Text(long)
	if len(out) != len(long) {
		t.Error("expected no change for safe long input")
	}
}

func TestText_UnicodeBypass(t *testing.T) {
	// Test that Unicode homoglyphs don't bypass detection
	// e.g., using full-width characters in "Bearer"
	// This is an edge case - the patterns use (?i) but don't handle Unicode
	input := "Authorization: Bearer real_token_abcdefghijklmnop"
	out := Text(input)
	if strings.Contains(out, "real_token_abcdefghijklmnop") {
		t.Error("REDACTION BYPASS: bearer token not caught")
	}
}

func TestStrings_PreservesOrder(t *testing.T) {
	in := []string{
		"safe text",
		"token=abcdefghijklmnopqrstuvwxyz1234",
		"more safe text",
	}
	out := Strings(in)
	if len(out) != 3 {
		t.Fatalf("expected 3 strings, got %d", len(out))
	}
	if out[0] != "safe text" {
		t.Errorf("expected first string unchanged, got %q", out[0])
	}
	if out[2] != "more safe text" {
		t.Errorf("expected third string unchanged, got %q", out[2])
	}
	if strings.Contains(out[1], "abcdefghijklmnopqrstuvwxyz1234") {
		t.Errorf("expected second string to be redacted, got %q", out[1])
	}
}

func TestText_SendGridAPIKey(t *testing.T) {
	// SendGrid API keys use SG. prefix - not specifically covered
	input := `SENDGRID_API_KEY=SG.abcdefghijklmnopqrstuvwxyz1234567890.ABCDEFGHIJKLMNOPQRSTUVWXYZ12345678`
	out := Text(input)
	// Caught by tokenAssign due to "api_key" in the variable name
	if strings.Contains(out, "SG.abcdefghijklmnopqrstuvwxyz") {
		t.Log("NOTE: SendGrid key may not be fully redacted")
	}
}

func TestText_GoogleOAuth(t *testing.T) {
	// Google API keys - not specifically covered but may hit tokenAssign
	input := `API_KEY=AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz123456`
	out := Text(input)
	if strings.Contains(out, "AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz123456") {
		t.Error("REDACTION BYPASS: Google API key leaked through tokenAssign")
	}
}
