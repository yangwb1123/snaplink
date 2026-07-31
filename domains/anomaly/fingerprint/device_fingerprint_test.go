package fingerprint

import (
	"testing"
)

func TestDerive_NilInput(t *testing.T) {
	if got := Derive(nil); got != "" {
		t.Errorf("Derive(nil) = %q, want empty", got)
	}
}

func TestDerive_EmptyInput(t *testing.T) {
	in := &Input{}
	if got := Derive(in); got != "" {
		t.Errorf("Derive(empty) = %q, want empty", got)
	}
}

func TestDerive_Deterministic(t *testing.T) {
	in := &Input{
		UserAgent:       "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
		AcceptLanguage:  "en-US,en;q=0.9",
		SecCHUA:         `"Google Chrome";v="129"`,
		SecCHUAPlatform: "Linux",
	}
	a := Derive(in)
	b := Derive(in)
	if a != b {
		t.Errorf("deterministic fingerprint expected same, got %q vs %q", a, b)
	}
	if a == "" {
		t.Error("deterministic fingerprint should not be empty for valid input")
	}
}

func TestDerive_WhitespaceInsensitive(t *testing.T) {
	in1 := &Input{UserAgent: "Mozilla/5.0 (Linux)"}
	in2 := &Input{UserAgent: "  Mozilla/5.0 (Linux)  "}
	if got := Derive(in1); got != Derive(in2) {
		t.Error("fingerprint should be insensitive to leading/trailing whitespace")
	}
}

func TestDerive_CaseInsensitive(t *testing.T) {
	in1 := &Input{UserAgent: "Mozilla/5.0"}
	in2 := &Input{UserAgent: "mozilla/5.0"}
	if got := Derive(in1); got != Derive(in2) {
		t.Error("fingerprint should be case-insensitive")
	}
}

func TestDerive_DifferentUA_DifferentFingerprint(t *testing.T) {
	in1 := &Input{UserAgent: "Mozilla/5.0 (Linux)"}
	in2 := &Input{UserAgent: "Mozilla/5.0 (Windows NT 10.0)"}
	a, b := Derive(in1), Derive(in2)
	if a == b {
		t.Error("different UserAgents should produce different fingerprints")
	}
}

func TestDerive_SHA256Length(t *testing.T) {
	in := &Input{
		UserAgent:      "Mozilla/5.0",
		AcceptLanguage: "en-US",
	}
	got := Derive(in)
	if len(got) != 64 {
		t.Errorf("expected 64-char hex fingerprint, got %d chars: %q", len(got), got)
	}
}

func TestDerive_AcceptLanguageOnly(t *testing.T) {
	in := &Input{AcceptLanguage: "en-US,en;q=0.9,fr;q=0.8"}
	got := Derive(in)
	if got == "" {
		t.Error("AcceptLanguage alone should produce a fingerprint")
	}
}

func TestDerive_MobileHints(t *testing.T) {
	in := &Input{
		UserAgent:       "Mozilla/5.0 (Linux; Android 14)",
		SecCHUA:         `"Chrome";v="129"`,
		SecCHUAPlatform: "Android",
		SecCHUAMobile:   "?1",
	}
	got := Derive(in)
	if got == "" {
		t.Error("mobile client hints should produce a fingerprint")
	}
	withoutMobile := &Input{
		UserAgent:       in.UserAgent,
		SecCHUA:         in.SecCHUA,
		SecCHUAPlatform: in.SecCHUAPlatform,
	}
	if got == Derive(withoutMobile) {
		t.Error("mobile flag should change the fingerprint when present")
	}
}
