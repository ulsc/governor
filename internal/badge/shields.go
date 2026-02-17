package badge

import "encoding/json"

type shieldsEndpoint struct {
	SchemaVersion int    `json:"schemaVersion"`
	Label         string `json:"label"`
	Message       string `json:"message"`
	Color         string `json:"color"`
}

// ShieldsJSON returns a shields.io endpoint JSON string.
func ShieldsJSON(label, grade, color string) string {
	data := shieldsEndpoint{
		SchemaVersion: 1,
		Label:         label,
		Message:       grade,
		Color:         color,
	}
	b, _ := json.MarshalIndent(data, "", "  ")
	return string(b)
}
