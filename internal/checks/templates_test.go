package checks

import "testing"

func TestLookupTemplate_BlankExists(t *testing.T) {
	template, ok := LookupTemplate("blank")
	if !ok {
		t.Fatal("expected blank template to exist")
	}
	if template.ID != "blank" {
		t.Fatalf("unexpected template id: %s", template.ID)
	}
	if template.Instructions == "" {
		t.Fatal("expected blank template instructions")
	}
}

func TestParseStatus(t *testing.T) {
	cases := []struct {
		in      string
		want    Status
		wantErr bool
	}{
		{in: "", want: StatusDraft},
		{in: "draft", want: StatusDraft},
		{in: "enabled", want: StatusEnabled},
		{in: "disabled", want: StatusDisabled},
		{in: "invalid", wantErr: true},
	}

	for _, tc := range cases {
		got, err := ParseStatus(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("ParseStatus(%q): expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseStatus(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("ParseStatus(%q): got %s want %s", tc.in, got, tc.want)
		}
	}
}
