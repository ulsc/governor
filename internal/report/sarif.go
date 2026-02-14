package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"governor/internal/model"
	"governor/internal/safefile"
)

// SARIF v2.1.0 types — minimal subset for GitHub Code Scanning / Azure DevOps.

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Version        string      `json:"version"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name,omitempty"`
	ShortDescription sarifMessage        `json:"shortDescription,omitempty"`
	DefaultConfig    *sarifDefaultConfig `json:"defaultConfiguration,omitempty"`
}

type sarifDefaultConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID    string           `json:"ruleId"`
	Level     string           `json:"level"`
	Message   sarifMessage     `json:"message"`
	Locations []sarifLocation  `json:"locations,omitempty"`
	Properties *sarifProperties `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifProperties struct {
	Severity   string  `json:"severity,omitempty"`
	Category   string  `json:"category,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
	Impact     string  `json:"impact,omitempty"`
}

func WriteSARIF(path string, report model.AuditReport) error {
	report = redactReport(report)
	log := buildSARIF(report)
	b, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal sarif report: %w", err)
	}
	if err := safefile.WriteFileAtomic(path, b, 0o600); err != nil {
		return fmt.Errorf("write sarif report: %w", err)
	}
	return nil
}

func buildSARIF(report model.AuditReport) sarifLog {
	ruleIndex := map[string]int{}
	var rules []sarifRule
	var results []sarifResult

	for _, f := range report.Findings {
		ruleID := f.ID
		if ruleID == "" {
			ruleID = "governor-finding"
		}

		if _, seen := ruleIndex[ruleID]; !seen {
			ruleIndex[ruleID] = len(rules)
			rules = append(rules, sarifRule{
				ID:               ruleID,
				Name:             f.Title,
				ShortDescription: sarifMessage{Text: f.Title},
				DefaultConfig:    &sarifDefaultConfig{Level: mapSeverityToSARIF(f.Severity)},
			})
		}

		level := mapSeverityToSARIF(f.Severity)

		messageText := f.Evidence
		if messageText == "" {
			messageText = f.Title
		}

		var locations []sarifLocation
		for _, ref := range f.FileRefs {
			ref = strings.TrimSpace(ref)
			if ref == "" {
				continue
			}
			locations = append(locations, sarifLocation{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{
						URI: ref,
					},
				},
			})
		}

		results = append(results, sarifResult{
			RuleID:    ruleID,
			Level:     level,
			Message:   sarifMessage{Text: messageText},
			Locations: locations,
			Properties: &sarifProperties{
				Severity:   f.Severity,
				Category:   f.Category,
				Confidence: f.Confidence,
				Impact:     f.Impact,
			},
		})
	}

	return sarifLog{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{
				Driver: sarifDriver{
					Name:           "governor",
					InformationURI: "https://github.com/anthropics/governor",
					Version:        report.RunMetadata.PromptVersion,
					Rules:          rules,
				},
			},
			Results: results,
		}},
	}
}

func mapSeverityToSARIF(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	case "low", "info":
		return "note"
	default:
		return "note"
	}
}
