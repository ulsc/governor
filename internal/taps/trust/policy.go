package trust

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"governor/internal/safefile"

	"gopkg.in/yaml.v3"
)

func DefaultPath() string {
	return filepath.Join(".governor", "check-trust.yaml")
}

func Load(path string) (Policy, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		path = DefaultPath()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Policy{}, os.ErrNotExist
		}
		return Policy{}, fmt.Errorf("read trust policy: %w", err)
	}
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return Policy{}, fmt.Errorf("parse trust policy: %w", err)
	}
	p = Normalize(p)
	if err := Validate(p); err != nil {
		return Policy{}, err
	}
	return p, nil
}

func Save(path string, p Policy) error {
	path = strings.TrimSpace(path)
	if path == "" {
		path = DefaultPath()
	}
	p = Normalize(p)
	if err := Validate(p); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create trust policy dir: %w", err)
	}
	data, err := yaml.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshal trust policy: %w", err)
	}
	if err := safefile.WriteFileAtomic(path, data, 0o600); err != nil {
		return fmt.Errorf("write trust policy: %w", err)
	}
	return nil
}

func Normalize(p Policy) Policy {
	p.APIVersion = strings.TrimSpace(p.APIVersion)
	if p.APIVersion == "" {
		p.APIVersion = APIVersion
	}
	if p.Mode == "" {
		p.Mode = ModeWarn
	}
	p.Mode = Mode(strings.ToLower(strings.TrimSpace(string(p.Mode))))

	for i := range p.TrustedSources {
		p.TrustedSources[i].Name = strings.TrimSpace(p.TrustedSources[i].Name)
		p.TrustedSources[i].URL = strings.TrimSpace(p.TrustedSources[i].URL)
	}
	for i := range p.PinnedPacks {
		p.PinnedPacks[i].Pack = strings.TrimSpace(p.PinnedPacks[i].Pack)
		p.PinnedPacks[i].Source = strings.TrimSpace(p.PinnedPacks[i].Source)
		p.PinnedPacks[i].Version = strings.TrimSpace(p.PinnedPacks[i].Version)
		p.PinnedPacks[i].Digest = strings.TrimSpace(p.PinnedPacks[i].Digest)
		p.PinnedPacks[i].Commit = strings.TrimSpace(p.PinnedPacks[i].Commit)
	}
	return p
}

func Validate(p Policy) error {
	if p.APIVersion != APIVersion {
		return fmt.Errorf("unsupported trust policy api_version %q", p.APIVersion)
	}
	switch p.Mode {
	case ModeOff, ModeWarn, ModeStrict:
	default:
		return fmt.Errorf("trust mode must be off|warn|strict")
	}
	for i, source := range p.TrustedSources {
		if source.Name == "" {
			return fmt.Errorf("trusted_sources[%d].name is required", i)
		}
		if source.URL == "" {
			return fmt.Errorf("trusted_sources[%d].url is required", i)
		}
	}
	for i, pinned := range p.PinnedPacks {
		if pinned.Pack == "" {
			return fmt.Errorf("pinned_packs[%d].pack is required", i)
		}
	}
	return nil
}

func FindPinnedPack(p Policy, pack string) (PinnedPack, bool) {
	pack = strings.TrimSpace(pack)
	for _, pinned := range p.PinnedPacks {
		if strings.EqualFold(pinned.Pack, pack) {
			return pinned, true
		}
	}
	return PinnedPack{}, false
}

func UpsertPinnedPack(p *Policy, pinned PinnedPack) {
	if p == nil {
		return
	}
	for i := range p.PinnedPacks {
		if strings.EqualFold(p.PinnedPacks[i].Pack, pinned.Pack) {
			p.PinnedPacks[i] = pinned
			*p = Normalize(*p)
			return
		}
	}
	p.PinnedPacks = append(p.PinnedPacks, pinned)
	*p = Normalize(*p)
}
