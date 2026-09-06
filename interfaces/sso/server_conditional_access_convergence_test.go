package sso_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/conditionalaccess"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

func TestConditionalAccessConcurrentSessionsRejectsOnlyProspectiveExcess(t *testing.T) {
	store := conditionalaccess.NewMemoryStore()
	if err := store.Put(context.Background(), conditionalaccess.Policy{Name: "one-session", Enabled: true, Conditions: conditionalaccess.Conditions{MaxConcurrentSessions: 1}, Actions: conditionalaccess.Actions{Deny: true}}); err != nil {
		t.Fatal(err)
	}
	env := rcovNewServer(t, sso.WithConditionalAccess(store, conditionalaccess.Config{Enforce: true}))
	status, out := rcovPostJSON(t, env.http.URL+"/auth/login", "", capLoginBody())
	if status != 200 {
		t.Fatalf("first login status=%d body=%v", status, out)
	}
	status, out = rcovPostJSON(t, env.http.URL+"/auth/login", "", capLoginBody())
	if status != 403 || out["error"] != core.ErrConditionalAccessDenied {
		t.Fatalf("second login status=%d body=%v", status, out)
	}
}

func TestConditionalAccessConvergenceRevokesExistingDeniedSession(t *testing.T) {
	ctx := context.Background()
	store := conditionalaccess.NewMemoryStore()
	if err := store.Put(ctx, conditionalaccess.Policy{Name: "stale", Enabled: true, Conditions: conditionalaccess.Conditions{SessionAgeSeconds: 60}, Actions: conditionalaccess.Actions{Deny: true}}); err != nil {
		t.Fatal(err)
	}
	rawMgr := defaultimpl.NewMemorySessionManager(time.Hour)
	session, err := rawMgr.CreateWithMeta(ctx, "alice", core.SessionMeta{ClientID: "client", AuthorizedScopes: []string{"openid"}, AuthTime: time.Now().Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	mgr := &agedConvergenceSessionManager{
		MemorySessionManager: rawMgr,
		createdAt:            map[string]time.Time{session.ID: time.Now().Add(-time.Hour)},
	}
	srv := sso.NewServer(sso.WithSessionManager(mgr), sso.WithConditionalAccess(store, conditionalaccess.Config{Enforce: true, SessionSweepBatchSize: 10}))
	summary, err := srv.RunConditionalAccessConvergence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Scanned != 1 || summary.Revoked != 1 || summary.Failed != 0 {
		t.Fatalf("summary=%+v", summary)
	}
	if _, err := mgr.Get(ctx, session.ID); err == nil {
		t.Fatal("denied session remained active")
	}
}

type agedConvergenceSessionManager struct {
	*defaultimpl.MemorySessionManager
	createdAt map[string]time.Time
}

func (m *agedConvergenceSessionManager) ListAll(ctx context.Context) ([]*core.Session, error) {
	sessions, err := m.MemorySessionManager.ListAll(ctx)
	if err != nil {
		return nil, err
	}
	for _, session := range sessions {
		if createdAt, ok := m.createdAt[session.ID]; ok {
			session.CreatedAt = createdAt
		}
	}
	return sessions, nil
}

func TestConditionalAccessSessionScopeCeilingCapsRefresh(t *testing.T) {
	ctx := context.Background()
	mgr := defaultimpl.NewMemorySessionManager(time.Hour)
	session, err := mgr.CreateWithMeta(ctx, "alice", core.SessionMeta{ClientID: "client", AuthorizedScopes: []string{"openid"}})
	if err != nil {
		t.Fatal(err)
	}
	srv := sso.NewServer(sso.WithSessionManager(mgr))
	rec := httptest.NewRecorder()
	hctx := core.NewContext(rec, httptest.NewRequest("POST", "/token", nil))
	got, handled := srv.EnforceRefreshConditionalAccess(hctx, &core.Client{ID: "client"}, &oauth.RefreshToken{UserID: "alice", SID: session.ID}, []string{"openid", "admin"})
	if handled || len(got) != 1 || got[0] != "openid" {
		t.Fatalf("scopes=%v handled=%v body=%s", got, handled, rec.Body.String())
	}
}

func TestConditionalAccessSessionScopeCeilingDoesNotCrossClient(t *testing.T) {
	ctx := context.Background()
	mgr := defaultimpl.NewMemorySessionManager(time.Hour)
	session, _ := mgr.CreateWithMeta(ctx, "alice", core.SessionMeta{ClientID: "client-a", AuthorizedScopes: []string{"openid"}})
	srv := sso.NewServer(sso.WithSessionManager(mgr))
	hctx := core.NewContext(httptest.NewRecorder(), httptest.NewRequest("POST", "/token", nil))
	got, handled := srv.EnforceRefreshConditionalAccess(hctx, &core.Client{ID: "client-b"}, &oauth.RefreshToken{UserID: "alice", SID: session.ID}, []string{"openid", "admin"})
	if handled || len(got) != 2 {
		t.Fatalf("cross-client scopes=%v handled=%v", got, handled)
	}
}

func TestConditionalAccessConvergenceWorkerRunsImmediatelyAndStops(t *testing.T) {
	ctx := context.Background()
	store := conditionalaccess.NewMemoryStore()
	_ = store.Put(ctx, conditionalaccess.Policy{Name: "deny", Enabled: true, Actions: conditionalaccess.Actions{Deny: true}})
	mgr := defaultimpl.NewMemorySessionManager(time.Hour)
	session, _ := mgr.CreateWithMeta(ctx, "alice", core.SessionMeta{ClientID: "client", AuthorizedScopes: []string{"openid"}})
	srv := sso.NewServer(sso.WithSessionManager(mgr), sso.WithConditionalAccess(store, conditionalaccess.Config{Enforce: true, SessionSweepInterval: time.Hour}))
	runCtx, cancel := context.WithCancel(ctx)
	done := srv.StartConditionalAccessConvergence(runCtx)
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		if _, err := mgr.Get(ctx, session.ID); err != nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := mgr.Get(ctx, session.ID); err == nil {
		t.Fatal("worker did not run immediate convergence")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop")
	}
}
