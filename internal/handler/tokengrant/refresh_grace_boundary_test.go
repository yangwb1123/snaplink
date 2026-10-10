package tokengrant

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

type graceBoundaryDeps struct {
	RefreshGrantDeps
	store RefreshGraceStore
}

func (d graceBoundaryDeps) RefreshGrace() RefreshGraceStore { return d.store }

type graceBoundaryContext struct {
	core.HandlerContext
	request *http.Request
	written bool
}

func (c *graceBoundaryContext) Request() *http.Request { return c.request }
func (c *graceBoundaryContext) JSON(int, any)          { c.written = true }

type expiryDuringWaitStore struct {
	RefreshGraceStore
	cancel context.CancelFunc
	calls  int
}

func (s *expiryDuringWaitStore) Lookup(token string, now time.Time) (map[string]any, bool) {
	body, hit := s.RefreshGraceStore.Lookup(token, now)
	s.calls++
	if s.calls == 1 {
		s.cancel()
	} else {
		body[core.KeyRefreshGraceDeadline] = now.Add(-time.Second).Format(time.RFC3339Nano)
	}
	return body, hit
}

func TestPendingRefreshGraceRechecksExpiryAfterWait(t *testing.T) {
	now := time.Now()
	memory := NewRefreshGraceCache(time.Minute)
	memory.PreparePending("original", map[string]any{
		core.KeyRefreshGracePending: true, core.KeyRefreshGraceFamilyID: "family",
		core.KeyRefreshGraceClientID: "client", core.KeyRefreshGraceJKT: "", core.KeyRefreshGraceX5T: "",
		core.KeyRefreshGraceDeadline: now.Add(time.Minute).Format(time.RFC3339Nano),
	}, now)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "/token", nil)
	if err != nil {
		t.Fatal(err)
	}
	view := &graceBoundaryContext{request: request}
	store := &expiryDuringWaitStore{RefreshGraceStore: memory, cancel: cancel}
	deps := graceBoundaryDeps{store: store}
	if awaitPendingRefreshGrace(deps, view, &core.Client{ID: "client"}, "original", "family", "", "", func() bool { return false }) {
		t.Fatal("expired final evidence suppressed family revocation")
	}
	if view.written || store.calls != 2 {
		t.Fatalf("boundary check wrote an error or skipped the final lookup: written=%v calls=%d", view.written, store.calls)
	}
}
