package badge

import (
	"strings"
	"testing"
)

func TestRenderSVG(t *testing.T) {
	svg := RenderSVG("governor", "A+", "brightgreen", StyleFlat)

	if !strings.Contains(svg, "<svg") {
		t.Error("expected SVG output to contain <svg tag")
	}
	if !strings.Contains(svg, "governor") {
		t.Error("expected SVG to contain label text")
	}
	if !strings.Contains(svg, "A+") {
		t.Error("expected SVG to contain grade text")
	}
	if !strings.Contains(svg, "</svg>") {
		t.Error("expected SVG to be properly closed")
	}
}

func TestRenderSVG_FlatSquare(t *testing.T) {
	svg := RenderSVG("governor", "F", "red", StyleFlatSquare)

	if !strings.Contains(svg, "<svg") {
		t.Error("expected SVG output")
	}
	if !strings.Contains(svg, `rx="0"`) {
		t.Error("flat-square style should have rx=0")
	}
}

func TestRenderSVG_CustomLabel(t *testing.T) {
	svg := RenderSVG("security", "B", "yellowgreen", StyleFlat)

	if !strings.Contains(svg, "security") {
		t.Error("expected SVG to contain custom label")
	}
}
