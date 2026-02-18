package taps

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"governor/internal/safefile"

	"gopkg.in/yaml.v3"
)

const LockAPIVersion = "governor/checks-lock/v1"

type LockedPack struct {
	Name      string    `yaml:"name" json:"name"`
	Source    string    `yaml:"source" json:"source"`
	SourceURL string    `yaml:"source_url,omitempty" json:"source_url,omitempty"`
	Version   string    `yaml:"version,omitempty" json:"version,omitempty"`
	Digest    string    `yaml:"digest,omitempty" json:"digest,omitempty"`
	LockedAt  time.Time `yaml:"locked_at,omitempty" json:"locked_at,omitempty"`
}

type LockFile struct {
	APIVersion string       `yaml:"api_version" json:"api_version"`
	Packs      []LockedPack `yaml:"packs" json:"packs"`
}

type LocatedPack struct {
	Name        string
	Description string
	Version     string
	Digest      string
	TapName     string
	TapURL      string
	Dir         string
}

func DefaultLockPath() string {
	return filepath.Join(".governor", "checks.lock.yaml")
}

func LoadLock(path string) (LockFile, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		path = DefaultLockPath()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return LockFile{APIVersion: LockAPIVersion, Packs: nil}, nil
		}
		return LockFile{}, fmt.Errorf("read checks lock file: %w", err)
	}
	var lock LockFile
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return LockFile{}, fmt.Errorf("parse checks lock file: %w", err)
	}
	if lock.APIVersion != "" && strings.TrimSpace(lock.APIVersion) != LockAPIVersion {
		return LockFile{}, fmt.Errorf("unsupported checks lock api_version %q", lock.APIVersion)
	}
	lock = NormalizeLock(lock)
	return lock, nil
}

func SaveLock(path string, lock LockFile) error {
	path = strings.TrimSpace(path)
	if path == "" {
		path = DefaultLockPath()
	}
	lock = NormalizeLock(lock)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create checks lock dir: %w", err)
	}
	b, err := yaml.Marshal(lock)
	if err != nil {
		return fmt.Errorf("marshal checks lock file: %w", err)
	}
	if err := safefile.WriteFileAtomic(path, b, 0o600); err != nil {
		return fmt.Errorf("write checks lock file: %w", err)
	}
	return nil
}

func NormalizeLock(lock LockFile) LockFile {
	lock.APIVersion = LockAPIVersion
	if len(lock.Packs) == 0 {
		return lock
	}
	seen := map[string]struct{}{}
	out := make([]LockedPack, 0, len(lock.Packs))
	for _, pack := range lock.Packs {
		pack.Name = strings.TrimSpace(pack.Name)
		if pack.Name == "" {
			continue
		}
		pack.Source = strings.TrimSpace(pack.Source)
		pack.SourceURL = strings.TrimSpace(pack.SourceURL)
		pack.Version = strings.TrimSpace(pack.Version)
		pack.Digest = strings.TrimSpace(pack.Digest)
		key := strings.ToLower(pack.Name)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, pack)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	lock.Packs = out
	return lock
}

func FindLockedPack(lock LockFile, name string) (LockedPack, bool) {
	name = strings.TrimSpace(name)
	for _, pack := range lock.Packs {
		if strings.EqualFold(pack.Name, name) {
			return pack, true
		}
	}
	return LockedPack{}, false
}

func UpsertLockedPack(lock *LockFile, pack LockedPack) {
	if lock == nil {
		return
	}
	pack.Name = strings.TrimSpace(pack.Name)
	if pack.Name == "" {
		return
	}
	for i := range lock.Packs {
		if strings.EqualFold(lock.Packs[i].Name, pack.Name) {
			lock.Packs[i] = pack
			*lock = NormalizeLock(*lock)
			return
		}
	}
	lock.Packs = append(lock.Packs, pack)
	*lock = NormalizeLock(*lock)
}

func DiscoverPacks(cfg *Config) ([]LocatedPack, error) {
	if cfg == nil {
		return nil, nil
	}
	out := make([]LocatedPack, 0, 16)
	for _, tap := range cfg.Taps {
		packs, err := ListPacks(tap.Path)
		if err != nil {
			return nil, fmt.Errorf("list packs for %s: %w", tap.Name, err)
		}
		for _, p := range packs {
			if strings.TrimSpace(p.Name) == "" {
				continue
			}
			dir, ok := FindPack(tap.Path, p.Name)
			if !ok {
				continue
			}
			digest, err := ComputePackDigest(dir)
			if err != nil {
				return nil, err
			}
			out = append(out, LocatedPack{
				Name:        strings.TrimSpace(p.Name),
				Description: strings.TrimSpace(p.Description),
				Version:     strings.TrimSpace(p.Version),
				Digest:      digest,
				TapName:     strings.TrimSpace(tap.Name),
				TapURL:      strings.TrimSpace(tap.URL),
				Dir:         dir,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		ni := strings.ToLower(out[i].Name)
		nj := strings.ToLower(out[j].Name)
		if ni != nj {
			return ni < nj
		}
		if cmp := CompareVersion(out[i].Version, out[j].Version); cmp != 0 {
			return cmp > 0
		}
		return strings.ToLower(out[i].TapName) < strings.ToLower(out[j].TapName)
	})
	return out, nil
}

func FindPackCandidates(packs []LocatedPack, name string) []LocatedPack {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	out := make([]LocatedPack, 0, 4)
	for _, pack := range packs {
		if strings.EqualFold(pack.Name, name) {
			out = append(out, pack)
		}
	}
	return out
}

func SelectLatestPack(candidates []LocatedPack) (LocatedPack, error) {
	if len(candidates) == 0 {
		return LocatedPack{}, fmt.Errorf("no candidates")
	}
	best := candidates[0]
	for _, cand := range candidates[1:] {
		cmp := CompareVersion(cand.Version, best.Version)
		if cmp > 0 || (cmp == 0 && strings.ToLower(cand.TapName) < strings.ToLower(best.TapName)) {
			best = cand
		}
	}
	return best, nil
}

func ResolveLockedPack(candidates []LocatedPack, lock LockedPack) (LocatedPack, error) {
	filtered := make([]LocatedPack, 0, len(candidates))
	for _, cand := range candidates {
		if lock.Source != "" && !strings.EqualFold(lock.Source, cand.TapName) {
			continue
		}
		if lock.Version != "" && strings.TrimSpace(lock.Version) != strings.TrimSpace(cand.Version) {
			continue
		}
		if lock.Digest != "" && strings.TrimSpace(lock.Digest) != strings.TrimSpace(cand.Digest) {
			continue
		}
		filtered = append(filtered, cand)
	}
	if len(filtered) == 0 {
		return LocatedPack{}, fmt.Errorf("locked pack %q (%s %s) not found", lock.Name, lock.Source, lock.Version)
	}
	return SelectLatestPack(filtered)
}

func LockedPackFromLocated(pack LocatedPack, now time.Time) LockedPack {
	return LockedPack{
		Name:      pack.Name,
		Source:    pack.TapName,
		SourceURL: pack.TapURL,
		Version:   pack.Version,
		Digest:    pack.Digest,
		LockedAt:  now.UTC(),
	}
}

func ComputePackDigest(packDir string) (string, error) {
	entries, err := os.ReadDir(packDir)
	if err != nil {
		return "", fmt.Errorf("read pack dir %s: %w", packDir, err)
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if name == "pack.yaml" || strings.HasSuffix(name, ".check.yaml") || strings.HasSuffix(name, ".check.yml") {
			files = append(files, name)
		}
	}
	if len(files) == 0 {
		return "", fmt.Errorf("pack %s has no lockable files", packDir)
	}
	sort.Strings(files)
	h := sha256.New()
	for _, name := range files {
		b, err := os.ReadFile(filepath.Join(packDir, name))
		if err != nil {
			return "", fmt.Errorf("read %s: %w", name, err)
		}
		_, _ = h.Write([]byte(name))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write(b)
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func CompareVersion(a, b string) int {
	pa := parseVersion(a)
	pb := parseVersion(b)
	if pa.valid && pb.valid {
		if pa.major != pb.major {
			if pa.major > pb.major {
				return 1
			}
			return -1
		}
		if pa.minor != pb.minor {
			if pa.minor > pb.minor {
				return 1
			}
			return -1
		}
		if pa.patch != pb.patch {
			if pa.patch > pb.patch {
				return 1
			}
			return -1
		}
		if pa.prerelease == "" && pb.prerelease != "" {
			return 1
		}
		if pa.prerelease != "" && pb.prerelease == "" {
			return -1
		}
		if pa.prerelease > pb.prerelease {
			return 1
		}
		if pa.prerelease < pb.prerelease {
			return -1
		}
		return 0
	}
	if pa.valid && !pb.valid {
		return 1
	}
	if !pa.valid && pb.valid {
		return -1
	}
	ac := strings.TrimSpace(a)
	bc := strings.TrimSpace(b)
	if ac > bc {
		return 1
	}
	if ac < bc {
		return -1
	}
	return 0
}

func IsMajorUpgrade(from, to string) bool {
	pf := parseVersion(from)
	pt := parseVersion(to)
	if !pf.valid || !pt.valid {
		return false
	}
	return pt.major > pf.major
}

type parsedVersion struct {
	major      int
	minor      int
	patch      int
	prerelease string
	valid      bool
}

func parseVersion(raw string) parsedVersion {
	raw = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(raw), "v"))
	if raw == "" {
		return parsedVersion{}
	}
	buildParts := strings.SplitN(raw, "+", 2)
	raw = buildParts[0]
	parts := strings.SplitN(raw, "-", 2)
	core := parts[0]
	pre := ""
	if len(parts) == 2 {
		pre = parts[1]
	}
	coreParts := strings.Split(core, ".")
	if len(coreParts) == 0 {
		return parsedVersion{}
	}
	vals := []int{0, 0, 0}
	for i := 0; i < len(coreParts) && i < 3; i++ {
		n, err := strconv.Atoi(coreParts[i])
		if err != nil || n < 0 {
			return parsedVersion{}
		}
		vals[i] = n
	}
	return parsedVersion{
		major:      vals[0],
		minor:      vals[1],
		patch:      vals[2],
		prerelease: pre,
		valid:      true,
	}
}
