package checks

import (
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

	if strings.TrimSpace(def.Instructions) == "" {
		errs = append(errs, "instructions is required")
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

	if len(errs) > 0 {
		return fmt.Errorf(strings.Join(errs, "; "))
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
