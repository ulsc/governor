package ai

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	ProviderCodexCLI         = "codex-cli"
	ProviderOpenAICompatible = "openai-compatible"

	AuthAuto    = "auto"
	AuthAccount = "account"
	AuthAPIKey  = "api-key"

	defaultCodexBin        = "codex"
	defaultOpenAIBaseURL   = "https://api.openai.com/v1"
	defaultOpenAIModel     = "gpt-4o-mini"
	defaultOpenAIAPIKeyEnv = "OPENAI_API_KEY"

	profilesAPIVersion = "governor/ai/v1"
)

type Runtime struct {
	Profile string

	Provider string
	Model    string
	AuthMode string

	Bin       string
	BaseURL   string
	APIKeyEnv string
	Headers   map[string]string

	ExecutionMode string
	SandboxMode   string

	AccountHome string
}

type Profile struct {
	Name string `yaml:"name"`

	Provider string `yaml:"provider"`
	Model    string `yaml:"model,omitempty"`
	AuthMode string `yaml:"auth_mode,omitempty"`

	Bin       string            `yaml:"bin,omitempty"`
	BaseURL   string            `yaml:"base_url,omitempty"`
	APIKeyEnv string            `yaml:"api_key_env,omitempty"`
	Headers   map[string]string `yaml:"headers,omitempty"`

	AccountHome string `yaml:"account_home,omitempty"`
}

type profileFile struct {
	APIVersion string    `yaml:"api_version"`
	Profiles   []Profile `yaml:"profiles"`
}

type ResolveOptions struct {
	Profile string

	Provider string
	Model    string
	AuthMode string

	Bin       string
	BaseURL   string
	APIKeyEnv string
	Headers   map[string]string

	ExecutionMode string
	SandboxMode   string
	AccountHome   string
}

func ResolveRuntime(opts ResolveOptions) (Runtime, error) {
	catalog, err := mergedCatalog()
	if err != nil {
		return Runtime{}, err
	}

	profileName := strings.TrimSpace(opts.Profile)
	if profileName == "" {
		profileName = "codex"
	}
	base, ok := catalog[profileName]
	if !ok {
		available := make([]string, 0, len(catalog))
		for name := range catalog {
			available = append(available, name)
		}
		sort.Strings(available)
		return Runtime{}, fmt.Errorf("unknown ai profile %q (available: %s)", profileName, strings.Join(available, ", "))
	}

	rt := runtimeFromProfile(base)
	rt.Profile = profileName

	if v := strings.TrimSpace(opts.Provider); v != "" {
		rt.Provider = v
	}
	if v := strings.TrimSpace(opts.Model); v != "" {
		rt.Model = v
	}
	if v := strings.TrimSpace(opts.AuthMode); v != "" {
		rt.AuthMode = v
	}
	if v := strings.TrimSpace(opts.Bin); v != "" {
		rt.Bin = v
	}
	if v := strings.TrimSpace(opts.BaseURL); v != "" {
		rt.BaseURL = strings.TrimRight(v, "/")
	}
	if v := strings.TrimSpace(opts.APIKeyEnv); v != "" {
		rt.APIKeyEnv = v
	}
	if len(opts.Headers) > 0 {
		if rt.Headers == nil {
			rt.Headers = map[string]string{}
		}
		for k, v := range opts.Headers {
			k = strings.TrimSpace(k)
			v = strings.TrimSpace(v)
			if k == "" || v == "" {
				continue
			}
			rt.Headers[k] = v
		}
	}
	if v := strings.TrimSpace(opts.ExecutionMode); v != "" {
		rt.ExecutionMode = v
	}
	if v := strings.TrimSpace(opts.SandboxMode); v != "" {
		rt.SandboxMode = v
	}
	if v := strings.TrimSpace(opts.AccountHome); v != "" {
		rt.AccountHome = v
	}

	rt = normalizeRuntime(rt)
	if err := validateRuntime(rt); err != nil {
		return Runtime{}, err
	}
	return rt, nil
}

func normalizeRuntime(rt Runtime) Runtime {
	rt.Provider = strings.ToLower(strings.TrimSpace(rt.Provider))
	if rt.Provider == "" {
		rt.Provider = ProviderCodexCLI
	}
	if rt.AuthMode == "" {
		rt.AuthMode = AuthAuto
	}
	rt.AuthMode = strings.ToLower(strings.TrimSpace(rt.AuthMode))
	rt.Model = strings.TrimSpace(rt.Model)
	rt.Bin = strings.TrimSpace(rt.Bin)
	rt.BaseURL = strings.TrimRight(strings.TrimSpace(rt.BaseURL), "/")
	rt.APIKeyEnv = strings.TrimSpace(rt.APIKeyEnv)
	rt.ExecutionMode = strings.TrimSpace(rt.ExecutionMode)
	rt.SandboxMode = strings.TrimSpace(rt.SandboxMode)
	rt.AccountHome = strings.TrimSpace(rt.AccountHome)

	switch rt.Provider {
	case ProviderCodexCLI:
		if rt.Bin == "" {
			rt.Bin = defaultCodexBin
		}
		if rt.APIKeyEnv == "" {
			rt.APIKeyEnv = "CODEX_API_KEY"
		}
		if rt.AccountHome == "" {
			rt.AccountHome = "~/.codex"
		}
	case ProviderOpenAICompatible:
		if rt.BaseURL == "" {
			rt.BaseURL = defaultOpenAIBaseURL
		}
		if rt.Model == "" {
			rt.Model = defaultOpenAIModel
		}
		if rt.APIKeyEnv == "" {
			rt.APIKeyEnv = defaultOpenAIAPIKeyEnv
		}
	}
	return rt
}

func validateRuntime(rt Runtime) error {
	switch rt.Provider {
	case ProviderCodexCLI, ProviderOpenAICompatible:
	default:
		return fmt.Errorf("unsupported ai provider %q (supported: %s, %s)", rt.Provider, ProviderCodexCLI, ProviderOpenAICompatible)
	}
	switch rt.AuthMode {
	case AuthAuto, AuthAccount, AuthAPIKey:
	default:
		return fmt.Errorf("unsupported ai auth mode %q (supported: %s, %s, %s)", rt.AuthMode, AuthAuto, AuthAccount, AuthAPIKey)
	}
	if rt.Provider == ProviderCodexCLI && rt.Bin == "" {
		return fmt.Errorf("ai binary is required for provider %q", ProviderCodexCLI)
	}
	if rt.Provider == ProviderOpenAICompatible {
		if strings.TrimSpace(rt.BaseURL) == "" {
			return fmt.Errorf("ai base URL is required for provider %q", ProviderOpenAICompatible)
		}
		if strings.TrimSpace(rt.Model) == "" {
			return fmt.Errorf("ai model is required for provider %q", ProviderOpenAICompatible)
		}
	}
	return nil
}

func (rt Runtime) UsesCLI() bool {
	return strings.EqualFold(strings.TrimSpace(rt.Provider), ProviderCodexCLI)
}

func (rt Runtime) UsesOpenAICompatibleAPI() bool {
	return strings.EqualFold(strings.TrimSpace(rt.Provider), ProviderOpenAICompatible)
}

func runtimeFromProfile(p Profile) Runtime {
	h := map[string]string{}
	for k, v := range p.Headers {
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" || v == "" {
			continue
		}
		h[k] = v
	}
	return Runtime{
		Provider:    p.Provider,
		Model:       p.Model,
		AuthMode:    p.AuthMode,
		Bin:         p.Bin,
		BaseURL:     p.BaseURL,
		APIKeyEnv:   p.APIKeyEnv,
		Headers:     h,
		AccountHome: p.AccountHome,
	}
}

func mergedCatalog() (map[string]Profile, error) {
	catalog := map[string]Profile{}
	for _, p := range defaultProfiles() {
		catalog[p.Name] = p
	}

	paths, err := defaultProfilePaths()
	if err != nil {
		return nil, err
	}
	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		profiles, err := loadProfiles(path)
		if err != nil {
			return nil, err
		}
		for _, p := range profiles {
			catalog[p.Name] = p
		}
	}
	return catalog, nil
}

func defaultProfilePaths() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve home for ai profiles: %w", err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("resolve cwd for ai profiles: %w", err)
	}
	return []string{
		filepath.Join(home, ".governor", "ai", "profiles.yaml"),
		filepath.Join(home, ".governor", "ai", "profiles.yml"),
		filepath.Join(cwd, ".governor", "ai", "profiles.yaml"),
		filepath.Join(cwd, ".governor", "ai", "profiles.yml"),
	}, nil
}

func loadProfiles(path string) ([]Profile, error) {
	info, err := os.Stat(path)
	if err != nil {
		if errorsIsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat ai profiles %s: %w", path, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("ai profiles path is a directory: %s", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ai profiles %s: %w", path, err)
	}
	var parsed profileFile
	if err := yaml.Unmarshal(b, &parsed); err != nil {
		return nil, fmt.Errorf("parse ai profiles %s: %w", path, err)
	}
	if strings.TrimSpace(parsed.APIVersion) != "" && strings.TrimSpace(parsed.APIVersion) != profilesAPIVersion {
		return nil, fmt.Errorf("unsupported ai profile api_version %q in %s", parsed.APIVersion, path)
	}
	out := make([]Profile, 0, len(parsed.Profiles))
	for _, p := range parsed.Profiles {
		p.Name = strings.TrimSpace(p.Name)
		if p.Name == "" {
			return nil, fmt.Errorf("invalid ai profile in %s: name is required", path)
		}
		p.Provider = strings.ToLower(strings.TrimSpace(p.Provider))
		if p.Provider == "" {
			p.Provider = ProviderOpenAICompatible
		}
		out = append(out, p)
	}
	return out, nil
}

func defaultProfiles() []Profile {
	return []Profile{
		{
			Name:       "codex",
			Provider:   ProviderCodexCLI,
			AuthMode:   AuthAccount,
			Bin:        defaultCodexBin,
			APIKeyEnv:  "CODEX_API_KEY",
			AccountHome: "~/.codex",
		},
		{
			Name:       "codex-api",
			Provider:   ProviderCodexCLI,
			AuthMode:   AuthAPIKey,
			Bin:        defaultCodexBin,
			APIKeyEnv:  "CODEX_API_KEY",
			AccountHome: "~/.codex",
		},
		{
			Name:      "openai",
			Provider:  ProviderOpenAICompatible,
			AuthMode:  AuthAPIKey,
			BaseURL:   defaultOpenAIBaseURL,
			Model:     defaultOpenAIModel,
			APIKeyEnv: defaultOpenAIAPIKeyEnv,
		},
		{
			Name:      "openrouter",
			Provider:  ProviderOpenAICompatible,
			AuthMode:  AuthAPIKey,
			BaseURL:   "https://openrouter.ai/api/v1",
			Model:     "openai/gpt-4o-mini",
			APIKeyEnv: "OPENROUTER_API_KEY",
		},
		{
			Name:      "claude",
			Provider:  ProviderOpenAICompatible,
			AuthMode:  AuthAPIKey,
			BaseURL:   "https://openrouter.ai/api/v1",
			Model:     "anthropic/claude-3.5-sonnet",
			APIKeyEnv: "OPENROUTER_API_KEY",
		},
		{
			Name:      "gemini",
			Provider:  ProviderOpenAICompatible,
			AuthMode:  AuthAPIKey,
			BaseURL:   "https://openrouter.ai/api/v1",
			Model:     "google/gemini-2.0-flash-001",
			APIKeyEnv: "OPENROUTER_API_KEY",
		},
		{
			Name:      "minimax",
			Provider:  ProviderOpenAICompatible,
			AuthMode:  AuthAPIKey,
			BaseURL:   "https://openrouter.ai/api/v1",
			Model:     "minimax/minimax-01",
			APIKeyEnv: "OPENROUTER_API_KEY",
		},
		{
			Name:      "chatglm",
			Provider:  ProviderOpenAICompatible,
			AuthMode:  AuthAPIKey,
			BaseURL:   "https://openrouter.ai/api/v1",
			Model:     "zhipuai/glm-4.5",
			APIKeyEnv: "OPENROUTER_API_KEY",
		},
		{
			Name:      "vercel-ai-gateway",
			Provider:  ProviderOpenAICompatible,
			AuthMode:  AuthAPIKey,
			BaseURL:   "https://ai-gateway.vercel.sh/v1",
			Model:     "openai/gpt-4o-mini",
			APIKeyEnv: "AI_GATEWAY_API_KEY",
		},
		{
			Name:      "mistral",
			Provider:  ProviderOpenAICompatible,
			AuthMode:  AuthAPIKey,
			BaseURL:   "https://api.mistral.ai/v1",
			Model:     "mistral-large-latest",
			APIKeyEnv: "MISTRAL_API_KEY",
		},
		{
			Name:      "deepseek",
			Provider:  ProviderOpenAICompatible,
			AuthMode:  AuthAPIKey,
			BaseURL:   "https://api.deepseek.com/v1",
			Model:     "deepseek-chat",
			APIKeyEnv: "DEEPSEEK_API_KEY",
		},
		{
			Name:      "grok",
			Provider:  ProviderOpenAICompatible,
			AuthMode:  AuthAPIKey,
			BaseURL:   "https://api.x.ai/v1",
			Model:     "grok-2-latest",
			APIKeyEnv: "XAI_API_KEY",
		},
		{
			Name:      "perplexity",
			Provider:  ProviderOpenAICompatible,
			AuthMode:  AuthAPIKey,
			BaseURL:   "https://api.perplexity.ai",
			Model:     "sonar-pro",
			APIKeyEnv: "PERPLEXITY_API_KEY",
		},
		{
			Name:      "huggingface",
			Provider:  ProviderOpenAICompatible,
			AuthMode:  AuthAPIKey,
			BaseURL:   "https://router.huggingface.co/v1",
			Model:     "openai/gpt-oss-120b",
			APIKeyEnv: "HUGGINGFACEHUB_API_TOKEN",
		},
		{
			Name:      "local-openai",
			Provider:  ProviderOpenAICompatible,
			AuthMode:  AuthAuto,
			BaseURL:   "http://127.0.0.1:11434/v1",
			Model:     "llama3.1",
			APIKeyEnv: "LOCAL_AI_API_KEY",
		},
	}
}

func errorsIsNotExist(err error) bool {
	return err != nil && os.IsNotExist(err)
}
