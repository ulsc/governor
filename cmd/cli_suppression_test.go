package cmd

import (
	"testing"

	"governor/internal/model"
)

func TestCheckSuppressionRatioCI(t *testing.T) {
	tests := []struct {
		name     string
		maxRatio float64
		report   model.AuditReport
		wantErr  bool
	}{
		{
			"disabled (1.0)",
			1.0,
			model.AuditReport{
				Findings:        make([]model.Finding, 0),
				SuppressedCount: 100,
			},
			false,
		},
		{
			"below threshold",
			0.5,
			model.AuditReport{
				Findings:        make([]model.Finding, 8),
				SuppressedCount: 2,
			},
			false,
		},
		{
			"exceeds threshold",
			0.3,
			model.AuditReport{
				Findings:        make([]model.Finding, 2),
				SuppressedCount: 8,
			},
			true,
		},
		{
			"no findings at all",
			0.5,
			model.AuditReport{
				Findings:        nil,
				SuppressedCount: 0,
			},
			false,
		},
		{
			"at exact threshold",
			0.5,
			model.AuditReport{
				Findings:        make([]model.Finding, 5),
				SuppressedCount: 5,
			},
			false, // 0.5 is not > 0.5
		},
		{
			"just above threshold",
			0.5,
			model.AuditReport{
				Findings:        make([]model.Finding, 4),
				SuppressedCount: 6,
			},
			true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkSuppressionRatioCI(tc.maxRatio, tc.report)
			if (err != nil) != tc.wantErr {
				t.Errorf("checkSuppressionRatioCI(%f, ...) err=%v, wantErr=%v", tc.maxRatio, err, tc.wantErr)
			}
		})
	}
}
