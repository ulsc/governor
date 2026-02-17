package badge

import (
	"encoding/json"
	"testing"
)

func TestShieldsJSON(t *testing.T) {
	out := ShieldsJSON("governor", "A", "green")

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("expected valid JSON, got error: %v", err)
	}

	if result["schemaVersion"] != float64(1) {
		t.Errorf("schemaVersion = %v, want 1", result["schemaVersion"])
	}
	if result["label"] != "governor" {
		t.Errorf("label = %v, want governor", result["label"])
	}
	if result["message"] != "A" {
		t.Errorf("message = %v, want A", result["message"])
	}
	if result["color"] != "green" {
		t.Errorf("color = %v, want green", result["color"])
	}
}
