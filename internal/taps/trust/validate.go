package trust

import (
	"fmt"
	"strings"

	"governor/internal/taps"
)

func ValidatePack(lock taps.LockedPack, hasLock bool, candidate taps.LocatedPack, p Policy) ValidationResult {
	res := ValidationResult{Passed: true, Warnings: []string{}, Errors: []string{}}

	if p.Requirements.RequireLockEntry && !hasLock {
		res.Errors = append(res.Errors, fmt.Sprintf("pack %q has no lock entry", candidate.Name))
	}
	if p.Requirements.RequireDigest {
		if strings.TrimSpace(candidate.Digest) == "" {
			res.Errors = append(res.Errors, fmt.Sprintf("pack %q has empty digest", candidate.Name))
		}
		if hasLock && strings.TrimSpace(lock.Digest) != "" && !strings.EqualFold(strings.TrimSpace(lock.Digest), strings.TrimSpace(candidate.Digest)) {
			res.Errors = append(res.Errors, fmt.Sprintf("pack %q digest mismatch: lock=%s candidate=%s", candidate.Name, lock.Digest, candidate.Digest))
		}
	}

	if hasLock {
		if strings.TrimSpace(lock.Source) != "" && !strings.EqualFold(lock.Source, candidate.TapName) {
			res.Errors = append(res.Errors, fmt.Sprintf("pack %q source mismatch: lock=%s candidate=%s", candidate.Name, lock.Source, candidate.TapName))
		}
		if strings.TrimSpace(lock.Version) != "" && !strings.EqualFold(lock.Version, candidate.Version) {
			if !p.Requirements.AllowMajorUpgrades && taps.IsMajorUpgrade(lock.Version, candidate.Version) {
				res.Errors = append(res.Errors, fmt.Sprintf("pack %q major upgrade blocked: %s -> %s", candidate.Name, lock.Version, candidate.Version))
			} else {
				res.Warnings = append(res.Warnings, fmt.Sprintf("pack %q version differs from lock: %s -> %s", candidate.Name, lock.Version, candidate.Version))
			}
		}
		if strings.TrimSpace(lock.Commit) != "" && strings.TrimSpace(candidate.Commit) != "" && !strings.EqualFold(lock.Commit, candidate.Commit) {
			res.Warnings = append(res.Warnings, fmt.Sprintf("pack %q commit differs from lock: %s -> %s", candidate.Name, lock.Commit, candidate.Commit))
		}
	}

	if len(p.TrustedSources) > 0 {
		if !matchesTrustedSource(candidate, p.TrustedSources) {
			res.Errors = append(res.Errors, fmt.Sprintf("pack %q source %q is not trusted", candidate.Name, candidate.TapName))
		}
	}

	if pinned, ok := FindPinnedPack(p, candidate.Name); ok {
		if strings.TrimSpace(pinned.Source) != "" && !strings.EqualFold(pinned.Source, candidate.TapName) {
			res.Errors = append(res.Errors, fmt.Sprintf("pack %q source mismatch with pin", candidate.Name))
		}
		if strings.TrimSpace(pinned.Version) != "" && !strings.EqualFold(pinned.Version, candidate.Version) {
			res.Errors = append(res.Errors, fmt.Sprintf("pack %q version mismatch with pin", candidate.Name))
		}
		if strings.TrimSpace(pinned.Digest) != "" && !strings.EqualFold(pinned.Digest, candidate.Digest) {
			res.Errors = append(res.Errors, fmt.Sprintf("pack %q digest mismatch with pin", candidate.Name))
		}
		if strings.TrimSpace(pinned.Commit) != "" && strings.TrimSpace(candidate.Commit) != "" && !strings.EqualFold(pinned.Commit, candidate.Commit) {
			res.Errors = append(res.Errors, fmt.Sprintf("pack %q commit mismatch with pin", candidate.Name))
		}
	}

	res.Passed = len(res.Errors) == 0
	return res
}

func matchesTrustedSource(candidate taps.LocatedPack, trusted []TrustedSource) bool {
	for _, source := range trusted {
		if source.Name != "" && strings.EqualFold(source.Name, candidate.TapName) {
			return true
		}
		if source.URL != "" && strings.EqualFold(source.URL, candidate.TapURL) {
			return true
		}
	}
	return false
}

func ShouldBlock(mode Mode, strictOverride bool, result ValidationResult) bool {
	effectiveMode := mode
	if strictOverride {
		effectiveMode = ModeStrict
	}
	switch effectiveMode {
	case ModeOff:
		return false
	case ModeWarn:
		return false
	default:
		return len(result.Errors) > 0
	}
}
