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
			details, err := ValidateAuthorizationDetails(tc.raw, tc.allowed, RARLimits{})
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

// TestValidateAuthorizationDetails_Limits covers the RARLimits shape gate:
// unconfigured (zero-value) limits must stay unbounded (today's behavior);
// configured limits must reject BEFORE the type-allowlist check ever runs
// (allowed is nil in every case below — a limit violation must fire on its
// own, not depend on an allowlist rejection happening to also match).
func TestValidateAuthorizationDetails_Limits(t *testing.T) {
	t.Parallel()

	deepArray := func(n int) string {
		s := ""
		for i := 0; i < n; i++ {
			s += "["
		}
		s += "1"
		for i := 0; i < n; i++ {
			s += "]"
		}
		return s
	}

	tests := []struct {
		name    string
		raw     json.RawMessage
		limits  RARLimits
		wantErr bool
	}{
		{name: "unbounded default allows large payload", raw: json.RawMessage(`[{"type":"a"},{"type":"b"},{"type":"c"}]`), limits: RARLimits{}, wantErr: false},
		{name: "max bytes ok", raw: json.RawMessage(`[{"type":"a"}]`), limits: RARLimits{MaxBytes: 1024}, wantErr: false},
		{name: "max bytes exceeded", raw: json.RawMessage(`[{"type":"a"}]`), limits: RARLimits{MaxBytes: 5}, wantErr: true},
		{name: "max elements ok", raw: json.RawMessage(`[{"type":"a"},{"type":"b"}]`), limits: RARLimits{MaxElements: 2}, wantErr: false},
		{name: "max elements exceeded", raw: json.RawMessage(`[{"type":"a"},{"type":"b"},{"type":"c"}]`), limits: RARLimits{MaxElements: 2}, wantErr: true},
		{name: "max depth ok (array+object=2)", raw: json.RawMessage(`[{"type":"a"}]`), limits: RARLimits{MaxDepth: 2}, wantErr: false},
		{name: "max depth exceeded by nested object", raw: json.RawMessage(`[{"type":"a","nested":{"x":{"y":1}}}]`), limits: RARLimits{MaxDepth: 2}, wantErr: true},
		{name: "max depth exceeded by adversarial nesting", raw: json.RawMessage(deepArray(500)), limits: RARLimits{MaxDepth: 10}, wantErr: true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := ValidateAuthorizationDetails(tc.raw, nil, tc.limits)
			if tc.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
