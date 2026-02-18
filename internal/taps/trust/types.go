package trust

const APIVersion = "governor/check-trust/v1"

type Mode string

const (
	ModeOff    Mode = "off"
	ModeWarn   Mode = "warn"
	ModeStrict Mode = "strict"
)

type Policy struct {
	APIVersion     string          `yaml:"api_version" json:"api_version"`
	Mode           Mode            `yaml:"mode" json:"mode"`
	TrustedSources []TrustedSource `yaml:"trusted_sources,omitempty" json:"trusted_sources,omitempty"`
	PinnedPacks    []PinnedPack    `yaml:"pinned_packs,omitempty" json:"pinned_packs,omitempty"`
	Requirements   Requirements    `yaml:"requirements,omitempty" json:"requirements,omitempty"`
}

type TrustedSource struct {
	Name            string   `yaml:"name" json:"name"`
	URL             string   `yaml:"url" json:"url"`
	AllowedBranches []string `yaml:"allowed_branches,omitempty" json:"allowed_branches,omitempty"`
	AllowedSigners  []string `yaml:"allowed_signers,omitempty" json:"allowed_signers,omitempty"`
}

type PinnedPack struct {
	Pack    string `yaml:"pack" json:"pack"`
	Source  string `yaml:"source,omitempty" json:"source,omitempty"`
	Version string `yaml:"version,omitempty" json:"version,omitempty"`
	Digest  string `yaml:"digest,omitempty" json:"digest,omitempty"`
	Commit  string `yaml:"commit,omitempty" json:"commit,omitempty"`
}

type Requirements struct {
	RequireDigest      bool `yaml:"require_digest" json:"require_digest"`
	RequireLockEntry   bool `yaml:"require_lock_entry" json:"require_lock_entry"`
	AllowMajorUpgrades bool `yaml:"allow_major_updates" json:"allow_major_updates"`
}

type ValidationResult struct {
	Passed   bool
	Warnings []string
	Errors   []string
}
