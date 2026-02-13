package sanitize

import (
	"strings"
	"unicode/utf8"
)

const maxInlinePathLen = 240

// PathInline sanitizes potentially hostile filename/path text before embedding
// it into natural-language prompts.
func PathInline(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}

	var b strings.Builder
	b.Grow(len(path))

	for _, r := range path {
		switch r {
		case '\n', '\r', '\t':
			b.WriteRune(' ')
		default:
			if r < 0x20 || r == 0x7f {
				// Drop control characters.
				continue
			}
			if !utf8.ValidRune(r) {
				continue
			}
			b.WriteRune(r)
		}
	}

	out := strings.TrimSpace(b.String())
	if len(out) > maxInlinePathLen {
		out = out[:maxInlinePathLen] + "..."
	}
	return out
}
