package badge

// Grade computes a letter grade and badge color from finding severity counts.
// Only the grade and color are returned — no finding details leak into the badge.
func Grade(countsBySeverity map[string]int) (grade string, color string) {
	critical := countsBySeverity["critical"]
	high := countsBySeverity["high"]
	total := 0
	for _, c := range countsBySeverity {
		total += c
	}

	switch {
	case total == 0:
		return "A+", "brightgreen"
	case critical == 0 && high == 0:
		return "A", "green"
	case critical == 0 && high <= 3:
		return "B", "yellowgreen"
	case critical == 0:
		return "C", "yellow"
	case critical <= 3:
		return "D", "orange"
	default:
		return "F", "red"
	}
}
