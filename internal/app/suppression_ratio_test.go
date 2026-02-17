package app

import "testing"

func TestCheckSuppressionRatio(t *testing.T) {
	tests := []struct {
		name        string
		active      int
		suppressed  int
		wantWarning bool
	}{
		{"no findings", 0, 0, false},
		{"all active", 10, 0, false},
		{"below threshold", 8, 2, false},
		{"at threshold 50%", 5, 5, true},
		{"above threshold", 2, 8, true},
		{"100% suppressed", 0, 10, true},
		{"high ratio but low count", 1, 3, false},
		{"exactly 5 suppressed at 50%", 5, 5, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			warning := checkSuppressionRatio(tc.active, tc.suppressed)
			if (warning != "") != tc.wantWarning {
				t.Errorf("checkSuppressionRatio(%d, %d) warning=%q, wantWarning=%v",
					tc.active, tc.suppressed, warning, tc.wantWarning)
			}
		})
	}
}
