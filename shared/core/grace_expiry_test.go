package core

import (
	"testing"
	"time"
)

func TestRefreshGracePendingResponseRequiresBoundedEvidence(t *testing.T) {
	now := time.Now()
	original := map[string]any{KeyRefreshGracePending: true, KeyRefreshGraceDeadline: now.Add(time.Hour).Format(time.RFC3339Nano)}
	body := RefreshGracePendingResponse(original, now, time.Second)
	deadline, err := time.Parse(time.RFC3339Nano, body[KeyRefreshGraceDeadline].(string))
	if err != nil || !deadline.Equal(now.Add(time.Second)) {
		t.Fatal("pending deadline did not cap the serialized marker")
	}
	if body[KeyRefreshGraceDeadline] == original[KeyRefreshGraceDeadline] {
		t.Fatal("pending marker mutated caller evidence or retained its long deadline")
	}
	for _, invalid := range []map[string]any{
		nil,
		{KeyRefreshGracePending: true},
		{KeyRefreshGracePending: false, KeyRefreshGraceDeadline: now.Add(time.Hour).Format(time.RFC3339Nano)},
		{KeyRefreshGracePending: true, KeyRefreshGraceDeadline: "malformed"},
		{KeyRefreshGracePending: true, KeyRefreshGraceDeadline: now.Add(-time.Second).Format(time.RFC3339Nano)},
	} {
		if RefreshGracePendingResponse(invalid, now, time.Second) != nil {
			t.Fatal("invalid intent was prepared")
		}
	}
	if RefreshGracePendingResponse(original, now, 0) != nil {
		t.Fatal("disabled window prepared pending intent")
	}
}

func TestRefreshGraceExpiresAtBoundsEvidence(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name string
		resp map[string]any
		want time.Time
	}{
		{"legacy-window", nil, now.Add(time.Minute)},
		{"earlier-grant", map[string]any{KeyRefreshGraceDeadline: now.Add(time.Second).Format(time.RFC3339Nano)}, now.Add(time.Second)},
		{"earlier-window", map[string]any{KeyRefreshGraceDeadline: now.Add(time.Hour).Format(time.RFC3339Nano)}, now.Add(time.Minute)},
		{"wrong-type", map[string]any{KeyRefreshGraceDeadline: 123}, time.Time{}},
		{"malformed", map[string]any{KeyRefreshGraceDeadline: "invalid"}, time.Time{}},
		{"expired", map[string]any{KeyRefreshGraceDeadline: now.Add(-time.Second).Format(time.RFC3339Nano)}, now.Add(-time.Second)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := RefreshGraceExpiresAt(tc.resp, now, time.Minute); !got.Equal(tc.want) {
				t.Fatalf("deadline = %v, want %v", got, tc.want)
			}
		})
	}
}
