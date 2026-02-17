package taps

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// DefaultConfigPath returns the default path for taps.yaml.
func DefaultConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".governor", "taps.yaml")
}

// DefaultTapsDir returns the directory where taps are cloned.
func DefaultTapsDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".governor", "taps")
}

// LoadConfig reads the taps config file. Returns an empty config if the file doesn't exist.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, fmt.Errorf("read taps config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse taps config: %w", err)
	}
	return &cfg, nil
}

// SaveConfig writes the taps config to disk.
func SaveConfig(path string, cfg *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal taps config: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// ResolveSource takes user input (GitHub shorthand or full URL) and returns
// a normalized name and git-clonable URL.
func ResolveSource(input string) (name, url string) {
	input = strings.TrimSpace(input)

	// Full URL: git@, https://, http://, ssh://
	if strings.Contains(input, "://") || strings.HasPrefix(input, "git@") {
		name = extractNameFromURL(input)
		return name, input
	}

	// GitHub shorthand: owner/repo
	parts := strings.SplitN(input, "/", 2)
	if len(parts) == 2 {
		return input, fmt.Sprintf("https://github.com/%s/%s.git", parts[0], parts[1])
	}

	return input, input
}

func extractNameFromURL(url string) string {
	// git@github.com:owner/repo.git -> owner/repo
	if strings.HasPrefix(url, "git@") {
		parts := strings.SplitN(url, ":", 2)
		if len(parts) == 2 {
			path := strings.TrimSuffix(parts[1], ".git")
			return path
		}
	}
	// https://github.com/owner/repo.git -> owner/repo
	cleaned := strings.TrimSuffix(url, ".git")
	parts := strings.Split(cleaned, "/")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "/" + parts[len(parts)-1]
	}
	return url
}

// FindTap looks up a tap by name (case-insensitive).
func FindTap(cfg *Config, name string) (Tap, bool) {
	for _, t := range cfg.Taps {
		if strings.EqualFold(t.Name, name) {
			return t, true
		}
	}
	return Tap{}, false
}

// RemoveTap removes a tap by name and returns whether it was found.
func RemoveTap(cfg *Config, name string) bool {
	for i, t := range cfg.Taps {
		if strings.EqualFold(t.Name, name) {
			cfg.Taps = append(cfg.Taps[:i], cfg.Taps[i+1:]...)
			return true
		}
	}
	return false
}
