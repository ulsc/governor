package badge

import "fmt"

// Style controls the badge visual style.
type Style string

const (
	StyleFlat       Style = "flat"
	StyleFlatSquare Style = "flat-square"
)

// ParseStyle parses a style string, defaulting to flat.
func ParseStyle(s string) Style {
	if s == "flat-square" {
		return StyleFlatSquare
	}
	return StyleFlat
}

// hexForColor maps color names to hex values used in the badge.
var hexForColor = map[string]string{
	"brightgreen": "#4c1",
	"green":       "#97ca00",
	"yellowgreen": "#a4a61d",
	"yellow":      "#dfb317",
	"orange":      "#fe7d37",
	"red":         "#e05d44",
}

// RenderSVG generates a self-contained SVG badge string.
func RenderSVG(label, grade, color string, style Style) string {
	hex, ok := hexForColor[color]
	if !ok {
		hex = "#9f9f9f"
	}

	labelWidth := float64(len(label))*6.5 + 10
	gradeWidth := float64(len(grade))*7.5 + 10
	totalWidth := labelWidth + gradeWidth

	rx := 3
	if style == StyleFlatSquare {
		rx = 0
	}

	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%.0f" height="20">
  <linearGradient id="b" x2="0" y2="100%%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="a">
    <rect width="%.0f" height="20" rx="%d" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#a)">
    <path fill="#555" d="M0 0h%.0fv20H0z"/>
    <path fill="%s" d="M%.0f 0h%.0fv20H%.0fz"/>
    <path fill="url(#b)" d="M0 0h%.0fv20H0z"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="%.1f" y="15" fill="#010101" fill-opacity=".3">%s</text>
    <text x="%.1f" y="14">%s</text>
    <text x="%.1f" y="15" fill="#010101" fill-opacity=".3">%s</text>
    <text x="%.1f" y="14">%s</text>
  </g>
</svg>`,
		totalWidth,
		totalWidth,
		rx,
		labelWidth,
		hex,
		labelWidth, gradeWidth, labelWidth,
		totalWidth,
		labelWidth/2, label,
		labelWidth/2, label,
		labelWidth+gradeWidth/2, grade,
		labelWidth+gradeWidth/2, grade,
	)
}
