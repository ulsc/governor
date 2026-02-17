package taps

import "time"

// Tap represents a registered check pack source.
type Tap struct {
	Name    string    `yaml:"name" json:"name"`
	URL     string    `yaml:"url" json:"url"`
	Path    string    `yaml:"path,omitempty" json:"path,omitempty"`
	AddedAt time.Time `yaml:"added_at,omitempty" json:"added_at,omitempty"`
}

// Config holds the list of registered taps.
type Config struct {
	Taps []Tap `yaml:"taps" json:"taps"`
}

// PackMeta describes a check pack.
type PackMeta struct {
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
	Version     string `yaml:"version,omitempty" json:"version,omitempty"`
	Author      string `yaml:"author,omitempty" json:"author,omitempty"`
}
