package checks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

func ResolveDir(raw string) (string, error) {
	return ResolveWriteDir(raw)
}

func ResolveReadDirs(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw != "" {
		dir, err := resolvePath(raw)
		if err != nil {
			return nil, err
		}
		return []string{dir}, nil
	}

	dirs := make([]string, 0, 2)
	repoRoot, err := findRepoRootFromCWD()
	if err != nil {
		return nil, err
	}
	if repoRoot != "" {
		dirs = append(dirs, filepath.Join(repoRoot, ".governor", "checks"))
	}

	homeDir, err := resolvePath("~/.governor/checks")
	if err != nil {
		return nil, err
	}
	dirs = append(dirs, homeDir)

	return uniquePaths(dirs), nil
}

func ResolveWriteDir(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw != "" {
		return resolvePath(raw)
	}

	repoRoot, err := findRepoRootFromCWD()
	if err != nil {
		return "", err
	}
	if repoRoot != "" {
		return filepath.Join(repoRoot, ".governor", "checks"), nil
	}
	return resolvePath("~/.governor/checks")
}

func EnsureDir(dir string) error {
	return os.MkdirAll(dir, 0o700)
}

func CheckFilePath(dir string, id string) string {
	return filepath.Join(dir, id+".check.yaml")
}

func ReadDefinition(path string) (Definition, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Definition{}, fmt.Errorf("read check %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return Definition{}, fmt.Errorf("refusing symlinked check file: %s", path)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return Definition{}, fmt.Errorf("read check %s: %w", path, err)
	}

	var def Definition
	if err := yaml.Unmarshal(b, &def); err != nil {
		return Definition{}, fmt.Errorf("parse check %s: %w", path, err)
	}

	def = NormalizeDefinition(def)
	if err := ValidateDefinition(def); err != nil {
		return Definition{}, fmt.Errorf("invalid check %s: %w", path, err)
	}
	return def, nil
}

func WriteDefinition(dir string, def Definition, overwrite bool) (string, error) {
	def = NormalizeDefinition(def)
	now := time.Now().UTC()
	if def.CreatedAt.IsZero() {
		def.CreatedAt = now
	}
	def.UpdatedAt = now

	if err := ValidateDefinition(def); err != nil {
		return "", err
	}

	if err := EnsureDir(dir); err != nil {
		return "", fmt.Errorf("create checks dir: %w", err)
	}

	path := CheckFilePath(dir, def.ID)
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("refusing symlinked check file: %s", path)
		}
	}
	if !overwrite {
		if _, err := os.Stat(path); err == nil {
			return "", fmt.Errorf("check %q already exists at %s", def.ID, path)
		}
	}

	b, err := yaml.Marshal(def)
	if err != nil {
		return "", fmt.Errorf("marshal check %q: %w", def.ID, err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return "", fmt.Errorf("write check %s: %w", path, err)
	}
	return path, nil
}

func UpdateStatus(dir string, id string, status Status) (string, error) {
	id, err := normalizeAndValidateCheckID(id)
	if err != nil {
		return "", err
	}
	if err := validateStatus(status); err != nil {
		return "", err
	}

	path, err := resolveExistingCheckPath(dir, id)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("read check %s: %w", CheckFilePath(dir, id), err)
		}
		return "", err
	}
	return updateStatusAtPath(path, status)
}

func UpdateStatusInDirs(dirs []string, id string, status Status) (string, error) {
	id, err := normalizeAndValidateCheckID(id)
	if err != nil {
		return "", err
	}
	if err := validateStatus(status); err != nil {
		return "", err
	}

	searched := make([]string, 0, len(dirs))
	for _, dir := range uniquePaths(dirs) {
		path, pathErr := resolveExistingCheckPath(dir, id)
		if pathErr == nil {
			return updateStatusAtPath(path, status)
		}
		if errors.Is(pathErr, os.ErrNotExist) {
			searched = append(searched, dir)
			continue
		}
		return "", pathErr
	}

	if len(searched) == 0 {
		return "", fmt.Errorf("check %q not found (no directories searched)", id)
	}
	return "", fmt.Errorf("check %q not found in: %s", id, strings.Join(searched, ", "))
}

func LoadCustomDir(dir string) ([]Definition, []string, error) {
	items, warnings, err := loadCustomDirWithPaths(dir)
	if err != nil {
		return nil, nil, err
	}
	out := make([]Definition, 0, len(items))
	for _, item := range items {
		out = append(out, item.def)
	}
	return out, warnings, nil
}

func LoadCustomDirs(dirs []string) ([]Definition, []string, error) {
	out := make([]Definition, 0, 16)
	warnings := make([]string, 0, 8)
	seen := make(map[string]string, 16)

	for _, dir := range uniquePaths(dirs) {
		items, itemWarnings, err := loadCustomDirWithPaths(dir)
		if err != nil {
			return nil, nil, err
		}
		warnings = append(warnings, itemWarnings...)

		for _, item := range items {
			if loadedFrom, exists := seen[item.def.ID]; exists {
				warnings = append(warnings, fmt.Sprintf(
					"duplicate custom check id %q at %s ignored (already loaded from %s)",
					item.def.ID,
					item.path,
					loadedFrom,
				))
				continue
			}
			seen[item.def.ID] = item.path
			out = append(out, item.def)
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, warnings, nil
}

type loadedCheck struct {
	def  Definition
	path string
}

func loadCustomDirWithPaths(dir string) ([]loadedCheck, []string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("read checks dir: %w", err)
	}

	out := make([]loadedCheck, 0, len(entries))
	warnings := make([]string, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".check.yaml") && !strings.HasSuffix(name, ".check.yml") {
			continue
		}

		path := filepath.Join(dir, name)
		def, loadErr := ReadDefinition(path)
		if loadErr != nil {
			warnings = append(warnings, loadErr.Error())
			continue
		}

		def.Source = SourceCustom
		out = append(out, loadedCheck{
			def:  def,
			path: path,
		})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].def.ID < out[j].def.ID })
	return out, warnings, nil
}

func resolvePath(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home dir: %w", err)
		}
		switch raw {
		case "~":
			raw = home
		case "~/":
			raw = home + string(os.PathSeparator)
		default:
			raw = filepath.Join(home, strings.TrimPrefix(raw, "~/"))
		}
	}
	abs, err := filepath.Abs(raw)
	if err != nil {
		return "", fmt.Errorf("resolve checks dir: %w", err)
	}
	return abs, nil
}

func findRepoRootFromCWD() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("resolve cwd: %w", err)
	}
	return findRepoRoot(cwd)
}

func findRepoRoot(start string) (string, error) {
	current, err := filepath.Abs(strings.TrimSpace(start))
	if err != nil {
		return "", fmt.Errorf("resolve path: %w", err)
	}
	for {
		gitPath := filepath.Join(current, ".git")
		_, statErr := os.Stat(gitPath)
		if statErr == nil {
			return current, nil
		} else if !os.IsNotExist(statErr) {
			return "", fmt.Errorf("read git metadata %s: %w", gitPath, statErr)
		}

		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	return "", nil
}

func uniquePaths(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, path := range in {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		path = filepath.Clean(path)
		if _, exists := seen[path]; exists {
			continue
		}
		seen[path] = struct{}{}
		out = append(out, path)
	}
	return out
}

func normalizeAndValidateCheckID(id string) (string, error) {
	id = strings.ToLower(strings.TrimSpace(id))
	if id == "" {
		return "", fmt.Errorf("id is required")
	}
	if !idPattern.MatchString(id) {
		return "", fmt.Errorf("id must match ^[a-z0-9][a-z0-9_-]{1,63}$")
	}
	return id, nil
}

func validateStatus(status Status) error {
	switch status {
	case StatusDraft, StatusEnabled, StatusDisabled:
		return nil
	default:
		return fmt.Errorf("invalid status %q", status)
	}
}

func resolveExistingCheckPath(dir string, id string) (string, error) {
	candidates := []string{
		filepath.Join(dir, id+".check.yaml"),
		filepath.Join(dir, id+".check.yml"),
	}
	for _, path := range candidates {
		info, err := os.Lstat(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", fmt.Errorf("read check %s: %w", path, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("refusing symlinked check file: %s", path)
		}
		if info.IsDir() {
			return "", fmt.Errorf("check path is a directory: %s", path)
		}
		return path, nil
	}
	return "", os.ErrNotExist
}

func updateStatusAtPath(path string, status Status) (string, error) {
	def, err := ReadDefinition(path)
	if err != nil {
		return "", err
	}
	def.Status = status
	def.UpdatedAt = time.Now().UTC()
	def = NormalizeDefinition(def)
	if err := ValidateDefinition(def); err != nil {
		return "", err
	}

	b, err := yaml.Marshal(def)
	if err != nil {
		return "", fmt.Errorf("marshal check %q: %w", def.ID, err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return "", fmt.Errorf("write check %s: %w", path, err)
	}
	return path, nil
}
