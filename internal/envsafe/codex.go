package envsafe

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var aiAllowedEnv = map[string]struct{}{
	"PATH":            {},
	"HOME":            {},
	"USER":            {},
	"LOGNAME":         {},
	"SHELL":           {},
	"TERM":            {},
	"LANG":            {},
	"LC_ALL":          {},
	"LC_CTYPE":        {},
	"TMPDIR":          {},
	"TMP":             {},
	"TEMP":            {},
	"XDG_CONFIG_HOME": {},
	"XDG_CACHE_HOME":  {},
	"XDG_DATA_HOME":   {},
	"SSL_CERT_FILE":   {},
	"SSL_CERT_DIR":    {},
	"HTTP_PROXY":      {},
	"HTTPS_PROXY":     {},
	"NO_PROXY":        {},
	"http_proxy":      {},
	"https_proxy":     {},
	"no_proxy":        {},

	// Explicit model auth/config variables (no broad prefix forwarding).
	"OPENAI_API_KEY":           {},
	"OPENAI_BASE_URL":          {},
	"OPENAI_ORG_ID":            {},
	"OPENAI_PROJECT":           {},
	"AZURE_OPENAI_API_KEY":     {},
	"AZURE_OPENAI_ENDPOINT":    {},
	"AZURE_OPENAI_API_VERSION": {},
	"CODEX_API_KEY":            {},
	"CODEX_BASE_URL":           {},
	"CODEX_HOME":               {},
	"CODEX_CONFIG":             {},
	"CODEX_PROFILE":            {},
	"AI_API_KEY":               {},
	"AI_BASE_URL":              {},
	"AI_MODEL":                 {},
	"AI_PROVIDER":              {},
	"AI_PROFILE":               {},
	"ANTHROPIC_API_KEY":        {},
	"ANTHROPIC_BASE_URL":       {},
	"GEMINI_API_KEY":           {},
	"GOOGLE_API_KEY":           {},
	"OPENROUTER_API_KEY":       {},
	"MISTRAL_API_KEY":          {},
	"DEEPSEEK_API_KEY":         {},
	"MINIMAX_API_KEY":          {},
	"XAI_API_KEY":              {},
	"PERPLEXITY_API_KEY":       {},
	"CHATGLM_API_KEY":          {},
	"HUGGINGFACEHUB_API_TOKEN": {},
	"HF_TOKEN":                 {},
	"OLLAMA_HOST":              {},
}

// AIEnv returns a deterministic, explicit env allowlist for AI subprocesses.
func AIEnv(in []string) []string {
	outMap := make(map[string]string, len(aiAllowedEnv))
	for _, kv := range in {
		idx := -1
		for i := 0; i < len(kv); i++ {
			if kv[i] == '=' {
				idx = i
				break
			}
		}
		if idx <= 0 {
			continue
		}
		key := kv[:idx]
		val := kv[idx+1:]
		if _, ok := aiAllowedEnv[key]; ok {
			if key == "PATH" {
				val = sanitizePathValue(val)
			}
			outMap[key] = val
		}
	}
	if v, ok := outMap["PATH"]; !ok || strings.TrimSpace(v) == "" {
		outMap["PATH"] = defaultSafePath()
	}

	keys := make([]string, 0, len(outMap))
	for k := range outMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+outMap[k])
	}
	return out
}

// CodexEnv is kept as a compatibility wrapper and forwards to AIEnv.
func CodexEnv(in []string) []string {
	return AIEnv(in)
}

func sanitizePathValue(in string) string {
	if strings.TrimSpace(in) == "" {
		return defaultSafePath()
	}

	parts := strings.Split(in, string(os.PathListSeparator))
	seen := map[string]struct{}{}
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || part == "." || part == ".." {
			continue
		}
		if !filepath.IsAbs(part) {
			continue
		}
		clean := filepath.Clean(part)
		if clean == "" || clean == "." {
			continue
		}
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		out = append(out, clean)
	}
	if len(out) == 0 {
		return defaultSafePath()
	}
	return strings.Join(out, string(os.PathListSeparator))
}

func defaultSafePath() string {
	return "/usr/bin:/bin:/usr/sbin:/sbin"
}
