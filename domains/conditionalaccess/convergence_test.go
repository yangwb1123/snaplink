package conditionalaccess

import (
	"context"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/memorystoreidentity"
	"github.com/yangwb1123/snaplink/shared/core"
)

func TestConvergeSessionsAppliesDenyStepUpAndScopeRestriction(t *testing.T) {
	ctx := context.Background()
	mgr := memorystoreidentity.NewMemorySessionManager(time.Hour)
	deny := mustCAPSession(t, mgr, "deny", []string{"openid"}, time.Now().Add(-2*time.Hour))
	step := mustCAPSession(t, mgr, "step", []string{"openid"}, time.Now())
	scope := mustCAPSession(t, mgr, "scope", []string{"openid", "admin"}, time.Now())
	store := NewMemoryStore()
	for _, p := range []Policy{
		{Name: "deny-old", Priority: 3, Enabled: true, Conditions: Conditions{SessionAgeSeconds: 3600}, Actions: Actions{Deny: true}},
		{Name: "step", Priority: 2, Enabled: true, Conditions: Conditions{UserMemberOf: []string{"step"}}, Actions: Actions{RequireStepUp: "mfa"}},
		{Name: "scope", Priority: 1, Enabled: true, Conditions: Conditions{UserMemberOf: []string{"scope"}}, Actions: Actions{Allow: true, RestrictScopes: []string{"openid"}}},
	} {
		if err := store.Put(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	engine := NewEngine(store, Config{Enforce: true})
	summary, err := engine.ConvergeSessions(ctx, mgr, func(_ context.Context, s *core.Session, count int) AccessContext {
		return AccessContext{Subject: s.UserID, ClientID: s.ClientID, Groups: []string{s.UserID}, Now: time.Now(), SessionCreatedAt: s.CreatedAt, AuthTime: s.AuthTime, RequestedScopes: s.AuthorizedScopes, ConcurrentSessions: count, ConcurrentSessionsKnown: true}
	})
	if err != nil {
		t.Fatal(err)
	}
	if summary.Revoked != 1 || summary.StepUpMarked != 1 || summary.ScopesRestricted != 1 || summary.Failed != 0 {
		t.Fatalf("summary=%+v", summary)
	}
	if _, err := mgr.Get(ctx, deny.ID); err == nil {
		t.Fatal("deny session remains active")
	}
	gotStep, _ := mgr.Get(ctx, step.ID)
	if gotStep == nil || !gotStep.StepUpRequired {
		t.Fatal("step-up marker missing")
	}
	gotScope, _ := mgr.Get(ctx, scope.ID)
	if len(gotScope.AuthorizedScopes) != 1 || gotScope.AuthorizedScopes[0] != "openid" {
		t.Fatalf("scopes=%v", gotScope.AuthorizedScopes)
	}
}

func TestConvergeSessionsConcurrentLimitRevokesNewestExcessOnly(t *testing.T) {
	ctx := context.Background()
	mgr := memorystoreidentity.NewMemorySessionManager(time.Hour)
	for i := 0; i < 3; i++ {
		mustCAPSession(t, mgr, "alice", []string{"openid"}, time.Now())
	}
	store := NewMemoryStore()
	if err := store.Put(ctx, Policy{Name: "cap", Enabled: true, Conditions: Conditions{MaxConcurrentSessions: 2}, Actions: Actions{Deny: true}}); err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(store, Config{Enforce: true})
	summary, err := engine.ConvergeSessions(ctx, mgr, func(_ context.Context, s *core.Session, count int) AccessContext {
		return AccessContext{Subject: s.UserID, ClientID: s.ClientID, ConcurrentSessions: count, ConcurrentSessionsKnown: true}
	})
	if err != nil {
		t.Fatal(err)
	}
	remaining, _ := mgr.ListByUser(ctx, "alice")
	if summary.Revoked != 1 || len(remaining) != 2 {
		t.Fatalf("summary=%+v remaining=%d", summary, len(remaining))
	}
}

func mustCAPSession(t *testing.T, mgr *memorystoreidentity.MemorySessionManager, user string, scopes []string, authTime time.Time) *core.Session {
	t.Helper()
	session, err := mgr.CreateWithMeta(context.Background(), user, core.SessionMeta{ClientID: "client", AuthorizedScopes: scopes, AuthTime: authTime})
	if err != nil {
		t.Fatal(err)
	}
	if user == "deny" {
		session.CreatedAt = time.Now().Add(-2 * time.Hour)
	}
	return session
}
