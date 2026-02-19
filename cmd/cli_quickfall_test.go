package cmd

import (
	"testing"

	"governor/internal/config"
)

func TestShouldAutoQuick(t *testing.T) {
	tests := []struct {
		name          string
		explicitQuick bool
		cfg           config.Config
		setFlags      map[string]struct{}
		want          bool
	}{
		{
			name:          "no config no flags",
			explicitQuick: false,
			cfg:           config.Config{},
			setFlags:      map[string]struct{}{},
			want:          true,
		},
		{
			name:          "explicit quick flag",
			explicitQuick: true,
			cfg:           config.Config{},
			setFlags:      map[string]struct{}{"quick": {}},
			want:          false,
		},
		{
			name:          "ai-profile set via flag",
			explicitQuick: false,
			cfg:           config.Config{},
			setFlags:      map[string]struct{}{"ai-profile": {}},
			want:          false,
		},
		{
			name:          "ai_profile set via config",
			explicitQuick: false,
			cfg:           config.Config{AIProfile: "openai"},
			setFlags:      map[string]struct{}{},
			want:          false,
		},
		{
			name:          "ai-provider set via flag",
			explicitQuick: false,
			cfg:           config.Config{},
			setFlags:      map[string]struct{}{"ai-provider": {}},
			want:          false,
		},
		{
			name:          "ai_api_key_env set via config",
			explicitQuick: false,
			cfg:           config.Config{AIAPIKeyEnv: "MY_KEY"},
			setFlags:      map[string]struct{}{},
			want:          false,
		},
		{
			name:          "ai-model set via flag",
			explicitQuick: false,
			cfg:           config.Config{},
			setFlags:      map[string]struct{}{"ai-model": {}},
			want:          false,
		},
		{
			name:          "ai-auth-mode set via flag",
			explicitQuick: false,
			cfg:           config.Config{},
			setFlags:      map[string]struct{}{"ai-auth-mode": {}},
			want:          false,
		},
		{
			name:          "ai-base-url set via flag",
			explicitQuick: false,
			cfg:           config.Config{},
			setFlags:      map[string]struct{}{"ai-base-url": {}},
			want:          false,
		},
		{
			name:          "ai-api-key-env set via flag",
			explicitQuick: false,
			cfg:           config.Config{},
			setFlags:      map[string]struct{}{"ai-api-key-env": {}},
			want:          false,
		},
		{
			name:          "ai-bin set via flag",
			explicitQuick: false,
			cfg:           config.Config{},
			setFlags:      map[string]struct{}{"ai-bin": {}},
			want:          false,
		},
		{
			name:          "ai_provider set via config",
			explicitQuick: false,
			cfg:           config.Config{AIProvider: "openai-compatible"},
			setFlags:      map[string]struct{}{},
			want:          false,
		},
		{
			name:          "ai_model set via config",
			explicitQuick: false,
			cfg:           config.Config{AIModel: "gpt-4"},
			setFlags:      map[string]struct{}{},
			want:          false,
		},
		{
			name:          "ai_auth_mode set via config",
			explicitQuick: false,
			cfg:           config.Config{AIAuthMode: "api-key"},
			setFlags:      map[string]struct{}{},
			want:          false,
		},
		{
			name:          "ai_base_url set via config",
			explicitQuick: false,
			cfg:           config.Config{AIBaseURL: "https://api.example.com"},
			setFlags:      map[string]struct{}{},
			want:          false,
		},
		{
			name:          "ai_bin set via config",
			explicitQuick: false,
			cfg:           config.Config{AIBin: "/usr/local/bin/codex"},
			setFlags:      map[string]struct{}{},
			want:          false,
		},
		{
			name:          "non-ai flag does not affect result",
			explicitQuick: false,
			cfg:           config.Config{},
			setFlags:      map[string]struct{}{"verbose": {}, "workers": {}},
			want:          true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldAutoQuick(tt.explicitQuick, tt.cfg, tt.setFlags)
			if got != tt.want {
				t.Errorf("shouldAutoQuick() = %v, want %v", got, tt.want)
			}
		})
	}
}
