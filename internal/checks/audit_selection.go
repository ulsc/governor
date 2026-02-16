package checks

type AuditSelectionOptions struct {
	ChecksDir      string
	NoCustomChecks bool
	OnlyIDs        []string
	SkipIDs        []string
	EngineFilter   Engine
}

type AuditSelection struct {
	SearchedDirs []string
	Checks       []Definition
	Warnings     []string
}

func ResolveAuditSelection(opts AuditSelectionOptions) (AuditSelection, error) {
	dirs, err := ResolveReadDirs(opts.ChecksDir)
	if err != nil {
		return AuditSelection{}, err
	}
	customDefs, warnings, err := LoadCustomDirs(dirs)
	if err != nil {
		return AuditSelection{}, err
	}

	selection, err := BuildSelection(Builtins(), customDefs, SelectionOptions{
		IncludeBuiltins: true,
		IncludeCustom:   !opts.NoCustomChecks,
		OnlyIDs:         opts.OnlyIDs,
		SkipIDs:         opts.SkipIDs,
		EngineFilter:    opts.EngineFilter,
	})
	if err != nil {
		return AuditSelection{}, err
	}
	combinedWarnings := make([]string, 0, len(warnings)+len(selection.Warnings))
	combinedWarnings = append(combinedWarnings, warnings...)
	combinedWarnings = append(combinedWarnings, selection.Warnings...)
	return AuditSelection{
		SearchedDirs: dirs,
		Checks:       selection.Checks,
		Warnings:     combinedWarnings,
	}, nil
}

func CountChecksBySource(defs []Definition) (builtinCount int, customCount int) {
	for _, def := range defs {
		switch NormalizeDefinition(def).Source {
		case SourceBuiltin:
			builtinCount++
		default:
			customCount++
		}
	}
	return
}

func CountChecksByEngine(defs []Definition) (aiCount int, ruleCount int) {
	for _, def := range defs {
		switch NormalizeDefinition(def).Engine {
		case EngineRule:
			ruleCount++
		default:
			aiCount++
		}
	}
	return
}

func SelectionRequiresAI(defs []Definition) bool {
	for _, def := range defs {
		if NormalizeDefinition(def).Engine == EngineAI {
			return true
		}
	}
	return false
}
