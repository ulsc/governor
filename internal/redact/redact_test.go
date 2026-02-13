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
