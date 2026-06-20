package security

import (
	"testing"

	"github.com/snaplink/sso/shared/core"
)

func TestConstantTimeStringEq(t *testing.T) {
	t.Parallel()

	tests := []struct {
		a, b string
		want int
	}{
		{"hello", "hello", 1},
		{"hello", "world", 0},
		{"hello", "HELLO", 0},
		{"", "", 1},
		{"a", "", 0},
		{"", "a", 0},
		{"abc", "abcd", 0},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.a+"=="+tc.b, func(t *testing.T) {
			t.Parallel()
			got := ConstantTimeStringEq(tc.a, tc.b)
			if got != tc.want {
				t.Errorf("ConstantTimeStringEq(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestIsJWECompact(t *testing.T) {
	t.Parallel()

	tests := []struct {
		s    string
		want bool
	}{
		{"", false},
		{"a.b.c.d.e", true},
		{"a.b", false},
		{"a.b.c.d", false},
		{"a.b.c.d.e.f", false},
		{".....", false}, // 5 dots = 6 segments, need exactly 4 dots (5 segments)
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.s, func(t *testing.T) {
			t.Parallel()
			got := isJWECompact(tc.s)
			if got != tc.want {
				t.Errorf("isJWECompact(%q) = %v, want %v", tc.s, got, tc.want)
			}
		})
	}
}

func TestLockoutKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		clientID   string
		credential map[string]string
		want       string
	}{
		{name: "username match", clientID: "c1", credential: map[string]string{"username": "alice"}, want: "c1:alice"},
		{name: "email match", clientID: "c1", credential: map[string]string{"email": "a@b.com"}, want: "c1:a@b.com"},
		{name: "phone match", clientID: "c1", credential: map[string]string{"phone": "+123"}, want: "c1:+123"},
		{name: "username before email", clientID: "c1", credential: map[string]string{"username": "alice", "email": "a@b.com"}, want: "c1:alice"},
		{name: "nil credential", clientID: "c1", credential: nil, want: ""},
		{name: "empty credential", clientID: "c1", credential: map[string]string{}, want: ""},
		{name: "unknown keys ignored", clientID: "c1", credential: map[string]string{"unknown": "val"}, want: ""},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := LockoutKey(tc.clientID, tc.credential)
			if got != tc.want {
				t.Errorf("LockoutKey(%q, %v) = %q, want %q", tc.clientID, tc.credential, got, tc.want)
			}
		})
	}
}

func TestSectorIdentifier(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		client *core.Client
		want   string
	}{
		{name: "nil client", client: nil, want: ""},
		{name: "sector identifier URI", client: &core.Client{SectorIdentifierURI: "https://sector.example.com"}, want: "sector.example.com"},
		{name: "redirect URI host", client: &core.Client{RedirectURIs: []string{"https://rp.example.com/cb"}}, want: "rp.example.com"},
		{name: "sector beats redirect", client: &core.Client{
			SectorIdentifierURI: "https://sector.example.com",
			RedirectURIs:        []string{"https://rp.example.com/cb"},
		}, want: "sector.example.com"},
		{name: "fallback to client ID", client: &core.Client{ID: "my-client"}, want: "my-client"},
		{name: "invalid sector URI falls through", client: &core.Client{
			SectorIdentifierURI: "://invalid",
			RedirectURIs:        []string{"https://rp.example.com/cb"},
		}, want: "rp.example.com"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := SectorIdentifier(tc.client)
			if got != tc.want {
				t.Errorf("SectorIdentifier(%+v) = %q, want %q", tc.client, got, tc.want)
			}
		})
	}
}

func TestComputePairwiseSubject(t *testing.T) {
	t.Parallel()

	// Deterministic
	s1 := ComputePairwiseSubject("sector", "user1", "salt1")
	s2 := ComputePairwiseSubject("sector", "user1", "salt1")
	if s1 == "" {
		t.Fatal("ComputePairwiseSubject returned empty")
	}
	if s1 != s2 {
		t.Errorf("ComputePairwiseSubject not deterministic: %q vs %q", s1, s2)
	}

	// Different user in same sector yields different sub
	s3 := ComputePairwiseSubject("sector", "user2", "salt1")
	if s1 == s3 {
		t.Error("different users should yield different pairwise subjects")
	}

	// Same user in different sector yields different sub
	s4 := ComputePairwiseSubject("other-sector", "user1", "salt1")
	if s1 == s4 {
		t.Error("different sectors should yield different pairwise subjects")
	}

	// Default salt when empty
	s5 := ComputePairwiseSubject("sector", "user1", "")
	if s5 == "" {
		t.Fatal("ComputePairwiseSubject with empty salt should use default")
	}
	s6 := ComputePairwiseSubject("sector", "user1", DefaultPairwiseSalt)
	if s5 != s6 {
		t.Errorf("empty salt should equal DefaultPairwiseSalt")
	}

	// Empty inputs
	if got := ComputePairwiseSubject("", "user1", "salt1"); got != "" {
		t.Errorf("empty sector should return empty, got %q", got)
	}
	if got := ComputePairwiseSubject("sector", "", "salt1"); got != "" {
		t.Errorf("empty localSub should return empty, got %q", got)
	}
}
