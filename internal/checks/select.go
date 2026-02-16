package checks

import (
	"fmt"
	"sort"
	"strings"
)

type SelectionOptions struct {
	IncludeBuiltins bool
	IncludeCustom   bool
	IncludeDraft    bool
	OnlyIDs         []string
	SkipIDs         []string
	EngineFilter    Engine
}

type SelectionResult struct {
	Checks   []Definition
	Warnings []string
}

func BuildSelection(builtins []Definition, custom []Definition, opts SelectionOptions) (SelectionResult, error) {
	if !opts.IncludeBuiltins && !opts.IncludeCustom {
		return SelectionResult{}, fmt.Errorf("selection disabled both built-in and custom checks")
	}

	onlySet := make(map[string]struct{}, len(opts.OnlyIDs))
	skipSet := make(map[string]struct{}, len(opts.SkipIDs))
	for _, id := range opts.OnlyIDs {
		id = normalizeID(id)
		if id != "" {
			onlySet[id] = struct{}{}
		}
	}
	for _, id := range opts.SkipIDs {
		id = normalizeID(id)
		if id != "" {
			skipSet[id] = struct{}{}
		}
	}

	warnings := make([]string, 0, 8)
	selected := make([]Definition, 0, len(builtins)+len(custom))
	seen := make(map[string]struct{}, len(builtins)+len(custom))
	usedOnlyIDs := make(map[string]struct{}, len(onlySet))

	appendIfSelected := func(def Definition) {
		def = NormalizeDefinition(def)

		if _, dup := seen[def.ID]; dup {
			warnings = append(warnings, fmt.Sprintf("duplicate check id %q; later definition skipped", def.ID))
			return
		}
		if _, skip := skipSet[def.ID]; skip {
			return
		}
		if len(onlySet) > 0 {
			if _, ok := onlySet[def.ID]; !ok {
				return
			}
			usedOnlyIDs[def.ID] = struct{}{}
		}
		if def.Status == StatusDisabled {
			return
		}
		if def.Status == StatusDraft && !opts.IncludeDraft {
			return
		}
		if opts.EngineFilter != "" && def.Engine != opts.EngineFilter {
			return
		}

		selected = append(selected, def)
		seen[def.ID] = struct{}{}
	}

	if opts.IncludeBuiltins {
		for _, def := range builtins {
			appendIfSelected(def)
		}
	}
	if opts.IncludeCustom {
		sort.Slice(custom, func(i, j int) bool { return custom[i].ID < custom[j].ID })
		for _, def := range custom {
			appendIfSelected(def)
		}
	}

	if len(onlySet) > 0 {
		missing := make([]string, 0)
		for id := range onlySet {
			if _, ok := usedOnlyIDs[id]; !ok {
				missing = append(missing, id)
			}
		}
		sort.Strings(missing)
		for _, id := range missing {
			warnings = append(warnings, fmt.Sprintf("--only-check requested unknown or filtered check %q", id))
		}
	}

	if len(selected) == 0 {
		return SelectionResult{Warnings: warnings}, fmt.Errorf("no checks selected for execution")
	}
	return SelectionResult{Checks: selected, Warnings: warnings}, nil
}

func ValidateUniqueIDs(defs []Definition) error {
	seen := map[string]string{}
	for _, def := range defs {
		def = NormalizeDefinition(def)
		if existing, ok := seen[def.ID]; ok {
			return fmt.Errorf("duplicate check id %q in %s and %s", def.ID, existing, string(def.Source))
		}
		seen[def.ID] = string(def.Source)
	}
	return nil
}

func normalizeID(id string) string {
	return strings.TrimSpace(strings.ToLower(id))
}
