package core

import (
	"testing"
)

func TestErrorBody(t *testing.T) {
	t.Parallel()

	m := ErrorBody("invalid_grant")
	if m == nil {
		t.Fatal("expected non-nil map")
	}
	if m[KeyError] != "invalid_grant" {
		t.Errorf("ErrorBody() = %v, want error=invalid_grant", m)
	}
	if _, ok := m[KeyErrorDescription]; ok {
		t.Errorf("ErrorBody() should not include error_description")
	}
}

func TestErrorBodyDesc(t *testing.T) {
	t.Parallel()

	m := ErrorBodyDesc("invalid_request", "missing parameter")
	if m == nil {
		t.Fatal("expected non-nil map")
	}
	if m[KeyError] != "invalid_request" {
		t.Errorf("ErrorBodyDesc().error = %q, want invalid_request", m[KeyError])
	}
	if m[KeyErrorDescription] != "missing parameter" {
		t.Errorf("ErrorBodyDesc().error_description = %q, want missing parameter", m[KeyErrorDescription])
	}
}

func TestErrorBodyEmptyCode(t *testing.T) {
	t.Parallel()

	m := ErrorBody("")
	if m[KeyError] != "" {
		t.Errorf("ErrorBody(\"\") should allow empty code, got %q", m[KeyError])
	}
}

func TestErrorBodyDescSpecialChars(t *testing.T) {
	t.Parallel()

	desc := "invalid\n\tutf8:\u00e9"
	m := ErrorBodyDesc("server_error", desc)
	if m[KeyErrorDescription] != desc {
		t.Errorf("ErrorBodyDesc description roundtrip = %q, want %q", m[KeyErrorDescription], desc)
	}
}
