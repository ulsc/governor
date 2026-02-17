package badge

import "testing"

func TestGrade(t *testing.T) {
	tests := []struct {
		name     string
		critical int
		high     int
		medium   int
		low      int
		want     string
		color    string
	}{
		{"zero findings", 0, 0, 0, 0, "A+", "brightgreen"},
		{"only low", 0, 0, 0, 5, "A", "green"},
		{"only medium", 0, 0, 3, 0, "A", "green"},
		{"one high", 0, 1, 0, 0, "B", "yellowgreen"},
		{"three high", 0, 3, 0, 0, "B", "yellowgreen"},
		{"four high", 0, 4, 0, 0, "C", "yellow"},
		{"ten high", 0, 10, 0, 0, "C", "yellow"},
		{"one critical", 1, 0, 0, 0, "D", "orange"},
		{"three critical", 3, 0, 0, 0, "D", "orange"},
		{"four critical", 4, 0, 0, 0, "F", "red"},
		{"mixed high severity", 0, 2, 5, 3, "B", "yellowgreen"},
		{"mixed with critical", 2, 5, 3, 1, "D", "orange"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			counts := map[string]int{
				"critical": tt.critical,
				"high":     tt.high,
				"medium":   tt.medium,
				"low":      tt.low,
			}
			grade, color := Grade(counts)
			if grade != tt.want {
				t.Errorf("Grade() = %q, want %q", grade, tt.want)
			}
			if color != tt.color {
				t.Errorf("Color() = %q, want %q", color, tt.color)
			}
		})
	}
}
