package oidcsupport

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestBuildSessionState_FormatAndRecompute(t *testing.T) {
	t.Parallel()
	state, err := BuildSessionState("client-1", "https://rp.example.com", "sess-abc")
	if err != nil {
		t.Fatalf("BuildSessionState: %v", err)
	}
	dot := strings.LastIndex(state, ".")
	if dot < 0 {
		t.Fatalf("session_state %q missing salt suffix", state)
	}
	hashPart, salt := state[:dot], state[dot+1:]
	if salt == "" {
		t.Fatalf("session_state %q has empty salt", state)
	}
	saltBytes, err := base64.RawURLEncoding.DecodeString(salt)
	if err != nil {
		t.Fatalf("salt not base64url: %v", err)
	}
	if len(saltBytes) != sessionStateSaltBytes {
		t.Fatalf("salt length = %d, want %d", len(saltBytes), sessionStateSaltBytes)
	}

	// Independently recompute the hash half exactly as the
	// check_session_iframe page's client-side JS would, given the salt that
	// travels in the clear — this is the actual verification contract.
	want := sessionStateHash("client-1", "https://rp.example.com", "sess-abc", salt)
	if hashPart != want {
		t.Fatalf("hash part = %q, want %q", hashPart, want)
	}
	// Sanity: matches a manual SHA-256 over the documented concatenation.
	sum := sha256.Sum256([]byte("client-1 https://rp.example.com sess-abc " + salt))
	if want != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatalf("sessionStateHash does not match the documented algorithm")
	}
}

func TestBuildSessionState_UniquePerCall(t *testing.T) {
	t.Parallel()
	a, err := BuildSessionState("client-1", "https://rp.example.com", "sess-abc")
	if err != nil {
		t.Fatalf("BuildSessionState: %v", err)
	}
	b, err := BuildSessionState("client-1", "https://rp.example.com", "sess-abc")
	if err != nil {
		t.Fatalf("BuildSessionState: %v", err)
	}
	if a == b {
		t.Fatalf("two calls with identical inputs produced the same session_state %q — salt is not random", a)
	}
}

func TestSessionStateHash_DivergesOnBrowserStateChange(t *testing.T) {
	t.Parallel()
	const salt = "fixed-salt"
	loggedIn := sessionStateHash("client-1", "https://rp.example.com", "sess-abc", salt)
	loggedOut := sessionStateHash("client-1", "https://rp.example.com", "", salt)
	if loggedIn == loggedOut {
		t.Fatalf("hash did not change when browser_state changed (login -> logout)")
	}
}

func TestOriginFromURL(t *testing.T) {
	t.Parallel()
	cases := []struct{ in, want string }{
		{"https://rp.example.com/callback", "https://rp.example.com"},
		{"https://rp.example.com:8443/callback?x=1", "https://rp.example.com:8443"},
		{"http://localhost:3000/cb", "http://localhost:3000"},
		{"not a url", ""},
		{"/relative/path", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := OriginFromURL(c.in); got != c.want {
			t.Errorf("OriginFromURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
