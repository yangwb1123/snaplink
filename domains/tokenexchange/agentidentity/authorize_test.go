package agentidentity

import (
	"errors"
	"testing"
	"time"
)

func TestCheckSessionLive(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		sess    *AgentSession
		wantErr error
	}{
		{"nil session", nil, ErrNoSuchSession},
		{"revoked", &AgentSession{Revoked: true}, ErrSessionRevoked},
		{"expired", &AgentSession{ExpiresAt: now.Add(-time.Minute)}, ErrSessionExpired},
		{"expires exactly now", &AgentSession{ExpiresAt: now}, ErrSessionExpired},
		{"live with future expiry", &AgentSession{ExpiresAt: now.Add(time.Minute)}, nil},
		{"live with no expiry", &AgentSession{}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkSessionLive(tt.sess, now)
			if !errors.Is(err, tt.wantErr) && !(err == nil && tt.wantErr == nil) {
				t.Fatalf("checkSessionLive() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestIntersectScopes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		sets [][]string
		want []string
	}{
		{
			name: "three-way narrowing",
			sets: [][]string{
				{"a", "b", "c"},
				{"b", "c", "d"},
				{"c", "d", "e"},
			},
			want: []string{"c"},
		},
		{
			name: "no sets",
			sets: nil,
			want: nil,
		},
		{
			name: "single set passes through de-duplicated",
			sets: [][]string{{"a", "b", "a"}},
			want: []string{"a", "b"},
		},
		{
			name: "empty set among them narrows to nil",
			sets: [][]string{{"a", "b"}, {}},
			want: nil,
		},
		{
			name: "preserves first set's order",
			sets: [][]string{{"z", "y", "x"}, {"x", "y", "z"}},
			want: []string{"z", "y", "x"},
		},
		{
			name: "disjoint sets narrow to nil",
			sets: [][]string{{"a"}, {"b"}},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IntersectScopes(tt.sets...)
			if !equalStrings(got, tt.want) {
				t.Fatalf("IntersectScopes(%v) = %v, want %v", tt.sets, got, tt.want)
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
