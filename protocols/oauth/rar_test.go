package oauth

import (
	"encoding/json"
	"testing"
)

func TestCloneRawJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  json.RawMessage
	}{
		{name: "object", raw: json.RawMessage(`{"type":"payment","amount":100}`)},
		{name: "array", raw: json.RawMessage(`[{"type":"a"},{"type":"b"}]`)},
		{name: "empty", raw: json.RawMessage(nil)},
		{name: "empty slice", raw: json.RawMessage{}},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cloned := CloneRawJSON(tc.raw)
			if len(tc.raw) == 0 {
				if cloned != nil {
					t.Errorf("CloneRawJSON(nil) should return nil, got %v", cloned)
				}
				return
			}
			if string(cloned) != string(tc.raw) {
				t.Errorf("CloneRawJSON = %q, want %q", cloned, tc.raw)
			}
			// Mutating original should not affect clone
			if len(tc.raw) > 0 {
				tc.raw[0] = 'X'
				if cloned[0] == 'X' {
					t.Error("CloneRawJSON should not alias original")
				}
			}
		})
	}
}

func TestValidateAuthorizationDetails(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     json.RawMessage
		allowed []string
		wantOK  bool
		wantLen int
	}{
		{name: "empty", raw: nil, allowed: nil, wantOK: true, wantLen: 0},
		{name: "single valid", raw: json.RawMessage(`[{"type":"payment"}]`), allowed: []string{"payment"}, wantOK: true, wantLen: 1},
		{name: "multiple valid", raw: json.RawMessage(`[{"type":"a"},{"type":"b"}]`), allowed: []string{"a", "b"}, wantOK: true, wantLen: 2},
		{name: "empty allowlist", raw: json.RawMessage(`[{"type":"anything"}]`), allowed: nil, wantOK: true, wantLen: 1},
		{name: "type not allowed", raw: json.RawMessage(`[{"type":"unknown"}]`), allowed: []string{"known"}, wantOK: false},
		{name: "missing type", raw: json.RawMessage(`[{"notype":true}]`), allowed: nil, wantOK: false},
		{name: "not an array", raw: json.RawMessage(`{"type":"payment"}`), allowed: nil, wantOK: false},
		{name: "invalid JSON", raw: json.RawMessage(`{invalid`), allowed: nil, wantOK: false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			details, err := ValidateAuthorizationDetails(tc.raw, tc.allowed)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("ValidateAuthorizationDetails() unexpected error: %v", err)
				}
				if len(details) != tc.wantLen {
					t.Errorf("got %d details, want %d", len(details), tc.wantLen)
				}
			} else {
				if err == nil {
					t.Error("ValidateAuthorizationDetails() expected error, got nil")
				}
			}
		})
	}
}
