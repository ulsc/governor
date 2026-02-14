package checks

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{1,63}$`)

func ValidateDefinition(def Definition) error {
	var errs []string

	if strings.TrimSpace(def.APIVersion) == "" {
		errs = append(errs, "api_version is required")
	} else if strings.TrimSpace(def.APIVersion) != APIVersion {
		errs = append(errs, fmt.Sprintf("api_version must be %q", APIVersion))
	}

	id := strings.TrimSpace(def.ID)
	if id == "" {
		errs = append(errs, "id is required")
	} else if !idPattern.MatchString(id) {
		errs = append(errs, "id must match ^[a-z0-9][a-z0-9_-]{1,63}$")
	}

	switch strings.ToLower(strings.TrimSpace(string(def.Status))) {
	case string(StatusDraft), string(StatusEnabled), string(StatusDisabled):
	default:
		errs = append(errs, "status must be draft|enabled|disabled")
	}

	switch strings.ToLower(strings.TrimSpace(string(def.Source))) {
	case string(SourceBuiltin), string(SourceCustom):
	default:
		errs = append(errs, "source must be builtin|custom")
	}
	switch strings.ToLower(strings.TrimSpace(string(def.Engine))) {
	case "", string(EngineAI), string(EngineRule):
	default:
		errs = append(errs, "engine must be ai|rule")
	}

	if sev := strings.ToLower(strings.TrimSpace(def.SeverityHint)); sev != "" {
		switch sev {
		case "critical", "high", "medium", "low", "info":
		default:
			errs = append(errs, "severity_hint must be critical|high|medium|low|info")
		}
	}

	if def.ConfidenceHint < 0 || def.ConfidenceHint > 1 {
		errs = append(errs, "confidence_hint must be between 0 and 1")
	}

	def = NormalizeDefinition(def)
	if def.Engine == EngineAI {
		if strings.TrimSpace(def.Instructions) == "" {
			errs = append(errs, "instructions is required for engine=ai")
		}
	}
	if def.Engine == EngineRule {
		if strings.TrimSpace(string(def.Rule.Target)) == "" {
			errs = append(errs, "rule.target is required for engine=rule")
		} else if def.Rule.Target != RuleTargetFileContent {
			errs = append(errs, "rule.target must be file_content")
		}
		if len(def.Rule.Detectors) == 0 {
			errs = append(errs, "rule.detectors must contain at least one detector")
		}
		for i, detector := range def.Rule.Detectors {
			pathPrefix := fmt.Sprintf("rule.detectors[%d]", i)
			if strings.TrimSpace(detector.ID) == "" {
				errs = append(errs, pathPrefix+".id is required")
			} else if !idPattern.MatchString(strings.ToLower(strings.TrimSpace(detector.ID))) {
				errs = append(errs, pathPrefix+".id must match ^[a-z0-9][a-z0-9_-]{1,63}$")
			}
			switch detector.Kind {
			case RuleDetectorContains, RuleDetectorRegex:
			default:
				errs = append(errs, pathPrefix+".kind must be contains|regex")
			}
			if strings.TrimSpace(detector.Pattern) == "" {
				errs = append(errs, pathPrefix+".pattern is required")
			}
			if detector.Kind == RuleDetectorRegex && strings.TrimSpace(detector.Pattern) != "" {
				if _, err := regexp.Compile(detector.Pattern); err != nil {
					errs = append(errs, pathPrefix+".pattern must compile as regex")
				}
			}
			if sev := strings.ToLower(strings.TrimSpace(detector.Severity)); sev != "" {
				switch sev {
				case "critical", "high", "medium", "low", "info":
				default:
					errs = append(errs, pathPrefix+".severity must be critical|high|medium|low|info")
				}
			}
			if detector.Confidence < 0 || detector.Confidence > 1 {
				errs = append(errs, pathPrefix+".confidence must be between 0 and 1")
			}
			if detector.MaxMatches < 0 {
				errs = append(errs, pathPrefix+".max_matches must be >= 0")
			}
		}
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func NormalizeDefinition(def Definition) Definition {
	def.APIVersion = strings.TrimSpace(def.APIVersion)
	if def.APIVersion == "" {
		def.APIVersion = APIVersion
	}

	def.ID = strings.TrimSpace(strings.ToLower(def.ID))
	def.Name = strings.TrimSpace(def.Name)
	if def.Name == "" {
		def.Name = def.ID
	}

	status := strings.ToLower(strings.TrimSpace(string(def.Status)))
	if status == "" {
		def.Status = StatusDraft
	} else {
		def.Status = Status(status)
	}

	src := strings.ToLower(strings.TrimSpace(string(def.Source)))
	if src == "" {
		def.Source = SourceCustom
	} else {
		def.Source = Source(src)
	}

	engine := strings.ToLower(strings.TrimSpace(string(def.Engine)))
	if engine == "" {
		def.Engine = EngineAI
	} else {
		def.Engine = Engine(engine)
	}

	def.Description = strings.TrimSpace(def.Description)
	def.Instructions = strings.TrimSpace(def.Instructions)
	def.SeverityHint = strings.ToLower(strings.TrimSpace(def.SeverityHint))

	cats := make([]string, 0, len(def.CategoriesHint))
	for _, cat := range def.CategoriesHint {
		cat = strings.ToLower(strings.TrimSpace(cat))
		if cat != "" {
			cats = append(cats, cat)
		}
	}
	sort.Strings(cats)
	def.CategoriesHint = cats

	def.Scope.IncludeGlobs = sanitizeGlobs(def.Scope.IncludeGlobs)
	def.Scope.ExcludeGlobs = sanitizeGlobs(def.Scope.ExcludeGlobs)
	def.Origin.Method = strings.TrimSpace(strings.ToLower(def.Origin.Method))
	def.Origin.Inputs = sanitizePaths(def.Origin.Inputs)

	def.Rule.Target = RuleTarget(strings.ToLower(strings.TrimSpace(string(def.Rule.Target))))
	def.Rule.Notes = sanitizePaths(def.Rule.Notes)
	detectors := make([]RuleDetector, 0, len(def.Rule.Detectors))
	for _, detector := range def.Rule.Detectors {
		detector.ID = strings.ToLower(strings.TrimSpace(detector.ID))
		detector.Kind = RuleDetectorKind(strings.ToLower(strings.TrimSpace(string(detector.Kind))))
		detector.Pattern = strings.TrimSpace(detector.Pattern)
		detector.Title = strings.TrimSpace(detector.Title)
		detector.Category = strings.ToLower(strings.TrimSpace(detector.Category))
		detector.Severity = strings.ToLower(strings.TrimSpace(detector.Severity))
		detector.Remediation = strings.TrimSpace(detector.Remediation)
		detectors = append(detectors, detector)
	}
	sort.Slice(detectors, func(i, j int) bool { return detectors[i].ID < detectors[j].ID })
	def.Rule.Detectors = detectors

	return def
}

func sanitizeGlobs(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func sanitizePaths(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}
