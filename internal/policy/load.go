package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

func DefaultPath(root string) string {
	return filepath.Join(root, ".governor", "policy.yaml")
}

func Load(path string) (Policy, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return Policy{}, fmt.Errorf("policy path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Policy{}, fmt.Errorf("read policy file: %w", err)
	}
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return Policy{}, fmt.Errorf("parse policy file: %w", err)
	}
	p = Normalize(p)
	if err := Validate(p); err != nil {
		return Policy{}, err
	}
	return p, nil
}

func Normalize(in Policy) Policy {
	in.APIVersion = strings.TrimSpace(in.APIVersion)
	if in.APIVersion == "" {
		in.APIVersion = APIVersion
	}
	in.Defaults = normalizeGate(in.Defaults)
	if in.Defaults.MaxSuppressionRatio == nil {
		value := -1.0
		in.Defaults.MaxSuppressionRatio = &value
	}
	if in.Defaults.MaxNewFindings == nil {
		value := -1
		in.Defaults.MaxNewFindings = &value
	}

	rules := make([]Rule, 0, len(in.Rules))
	for _, rule := range in.Rules {
		rule.Name = strings.TrimSpace(rule.Name)
		rule.When = normalizeMatchSpec(rule.When)
		rule.Enforce = normalizeGate(rule.Enforce)
		rules = append(rules, rule)
	}
	in.Rules = rules

	waivers := make([]Waiver, 0, len(in.Waivers))
	for _, waiver := range in.Waivers {
		waiver.ID = strings.TrimSpace(waiver.ID)
		waiver.Reason = strings.TrimSpace(waiver.Reason)
		waiver.Expires = strings.TrimSpace(waiver.Expires)
		waiver.Approver = strings.TrimSpace(waiver.Approver)
		waiver.Match = normalizeMatchSpec(waiver.Match)
		waivers = append(waivers, waiver)
	}
	in.Waivers = waivers
	return in
}

func normalizeGate(g Gate) Gate {
	g.FailOnSeverity = strings.ToLower(strings.TrimSpace(g.FailOnSeverity))
	g.RequireChecks = normalizeStringList(g.RequireChecks)
	g.ForbidChecks = normalizeStringList(g.ForbidChecks)
	return g
}

func normalizeMatchSpec(m MatchSpec) MatchSpec {
	m.Paths = normalizeStringList(m.Paths)
	m.Categories = normalizeStringList(m.Categories)
	for i := range m.Categories {
		m.Categories[i] = strings.ToLower(m.Categories[i])
	}
	m.Checks = normalizeStringList(m.Checks)
	return m
}

func normalizeStringList(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		key := strings.ToLower(item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}
