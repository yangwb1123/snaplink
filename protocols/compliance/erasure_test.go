package compliance_test

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/protocols/compliance"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"
)

// fixture wires the four memory stores an Eraser composes, pre-seeded
// with data for two subjects so cross-subject isolation is testable.
type fixture struct {
	users    *defaultimpl.MemoryUserProvider
	sessions *defaultimpl.MemorySessionManager
	refresh  *defaultimpl.MemoryRefreshTokenStore
	clients  *defaultimpl.MemoryClientStore
	eraser   *compliance.Eraser
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	f := &fixture{
		users:    defaultimpl.NewMemoryUserProvider(),
		sessions: defaultimpl.NewMemorySessionManager(),
		refresh:  defaultimpl.NewMemoryRefreshTokenStore(),
		clients:  defaultimpl.NewMemoryClientStore(),
	}
	f.eraser = &compliance.Eraser{
		Users:    f.users,
		Sessions: f.sessions,
		Refresh:  f.refresh,
		Clients:  f.clients,
	}

	for _, id := range []string{"c1", "c2"} {
		if err := f.clients.Add(ctx, &core.Client{ID: id}); err != nil {
			t.Fatalf("add client %s: %v", id, err)
		}
	}
	for _, uid := range []string{"u1", "u2"} {
		if err := f.users.CreateOrUpdate(ctx, &core.User{ID: uid}); err != nil {
			t.Fatalf("create user %s: %v", uid, err)
		}
		if _, err := f.sessions.Create(ctx, uid); err != nil {
			t.Fatalf("create session %s: %v", uid, err)
		}
		// One refresh token per (user, client).
		for _, cid := range []string{"c1", "c2"} {
			tok := uid + "-" + cid + "-rt"
			err := f.refresh.Issue(ctx, tok, &oauth.RefreshToken{
				UserID:    uid,
				ClientID:  cid,
				ExpiresAt: time.Now().Add(time.Hour),
			})
			if err != nil {
				t.Fatalf("issue refresh %s: %v", tok, err)
			}
		}
	}
	return f
}

func TestEraseSubject_FullErasure(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	rep, err := f.eraser.EraseSubject(ctx, "u1", compliance.EraseOptions{})
	if err != nil {
		t.Fatalf("erase: %v", err)
	}
	if rep.RefreshTokensDeleted != 2 {
		t.Errorf("RefreshTokensDeleted = %d, want 2", rep.RefreshTokensDeleted)
	}
	if rep.SessionsDestroyed != 1 {
		t.Errorf("SessionsDestroyed = %d, want 1", rep.SessionsDestroyed)
	}
	if !rep.UserDeleted {
		t.Error("UserDeleted = false, want true")
	}

	// u1 fully gone.
	if s, _ := f.sessions.ListByUser(ctx, "u1"); len(s) != 0 {
		t.Errorf("u1 still has %d sessions", len(s))
	}
	if _, err := f.users.GetByID(ctx, "u1"); err == nil {
		t.Error("u1 still retrievable after erasure")
	}
	if n, _ := f.refresh.DeleteAllForSubject(ctx, "u1", "c1"); n != 0 {
		t.Errorf("u1/c1 still has %d refresh tokens", n)
	}

	// u2 untouched (cross-subject isolation).
	if s, _ := f.sessions.ListByUser(ctx, "u2"); len(s) != 1 {
		t.Errorf("u2 sessions = %d, want 1 (collateral erasure)", len(s))
	}
	if _, err := f.users.GetByID(ctx, "u2"); err != nil {
		t.Errorf("u2 wrongly erased: %v", err)
	}
	if n, _ := f.refresh.DeleteAllForSubject(ctx, "u2", "c1"); n != 1 {
		t.Errorf("u2/c1 refresh tokens = %d, want 1", n)
	}
}

func TestEraseSubject_Idempotent(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	if _, err := f.eraser.EraseSubject(ctx, "u1", compliance.EraseOptions{}); err != nil {
		t.Fatalf("first erase: %v", err)
	}
	rep, err := f.eraser.EraseSubject(ctx, "u1", compliance.EraseOptions{})
	if err != nil {
		t.Fatalf("second erase: %v", err)
	}
	if rep.RefreshTokensDeleted != 0 || rep.SessionsDestroyed != 0 {
		t.Errorf("re-run deleted refresh=%d sessions=%d, want 0/0", rep.RefreshTokensDeleted, rep.SessionsDestroyed)
	}
}

func TestEraseSubject_DryRunMutatesNothing(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	rep, err := f.eraser.EraseSubject(ctx, "u1", compliance.EraseOptions{DryRun: true})
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if rep.SessionsDestroyed != 1 {
		t.Errorf("dry-run SessionsDestroyed (projection) = %d, want 1", rep.SessionsDestroyed)
	}
	// Nothing actually removed.
	if s, _ := f.sessions.ListByUser(ctx, "u1"); len(s) != 1 {
		t.Errorf("dry-run destroyed sessions: %d remain, want 1", len(s))
	}
	if _, err := f.users.GetByID(ctx, "u1"); err != nil {
		t.Error("dry-run deleted the user")
	}
	if n, _ := f.refresh.DeleteAllForSubject(ctx, "u1", "c1"); n != 1 {
		t.Errorf("dry-run revoked refresh tokens: %d remain, want 1", n)
	}
}

func TestEraseSubject_DryRunPreviewsRefreshCount(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	// MemoryRefreshTokenStore implements RefreshTokenSubjectCounter, so a
	// dry run projects the token count without deleting (u1 has 2: c1+c2).
	rep, err := f.eraser.EraseSubject(ctx, "u1", compliance.EraseOptions{DryRun: true})
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if rep.RefreshTokensDeleted != 2 {
		t.Errorf("dry-run projected RefreshTokensDeleted = %d, want 2", rep.RefreshTokensDeleted)
	}
	// Still non-destructive.
	if n, _ := f.refresh.DeleteAllForSubject(ctx, "u1", ""); n != 2 {
		t.Errorf("dry-run revoked tokens: real delete found %d, want 2", n)
	}
}

func TestEraseSubject_SkipsUnwiredStores(t *testing.T) {
	ctx := context.Background()
	// Only a user provider wired; refresh + sessions absent.
	users := defaultimpl.NewMemoryUserProvider()
	if err := users.CreateOrUpdate(ctx, &core.User{ID: "u1"}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	e := &compliance.Eraser{Users: users}

	rep, err := e.EraseSubject(ctx, "u1", compliance.EraseOptions{})
	if err != nil {
		t.Fatalf("erase: %v", err)
	}
	if !rep.UserDeleted {
		t.Error("user not deleted")
	}
	if len(rep.Skipped) == 0 {
		t.Error("expected refresh + sessions recorded as skipped")
	}
}

func TestEraseSubject_EmptyUserID(t *testing.T) {
	f := newFixture(t)
	if _, err := f.eraser.EraseSubject(context.Background(), "", compliance.EraseOptions{}); err == nil {
		t.Fatal("expected error for empty user id")
	}
}

// --- consent + MFA-enrollment stubs for the inheritance-erasure test ---

type fakeConsentStore struct{ grants map[string][]core.ConsentGrant }

func (f *fakeConsentStore) RecordConsent(_ context.Context, g core.ConsentGrant) error {
	f.grants[g.UserID] = append(f.grants[g.UserID], g)
	return nil
}
func (f *fakeConsentStore) GetConsent(_ context.Context, _, _ string) (core.ConsentGrant, error) {
	return core.ConsentGrant{}, nil
}
func (f *fakeConsentStore) RevokeConsent(_ context.Context, userID, clientID string) error {
	kept := f.grants[userID][:0]
	for _, g := range f.grants[userID] {
		if g.ClientID != clientID {
			kept = append(kept, g)
		}
	}
	f.grants[userID] = kept
	return nil
}
func (f *fakeConsentStore) ListByUser(_ context.Context, userID string) ([]core.ConsentGrant, error) {
	return f.grants[userID], nil
}

type fakeMFAEnroll struct{ factors map[string][]core.MFAEnrolledFactor }

func (f *fakeMFAEnroll) ListFactors(_ context.Context, userID string) ([]core.MFAEnrolledFactor, error) {
	return f.factors[userID], nil
}
func (f *fakeMFAEnroll) RemoveFactor(_ context.Context, userID, factorID string) error {
	kept := f.factors[userID][:0]
	for _, fc := range f.factors[userID] {
		if fc.ID != factorID {
			kept = append(kept, fc)
		}
	}
	f.factors[userID] = kept
	return nil
}

// TestEraseSubject_ClearsConsentAndMFAEnrollments guards that an erasure also
// removes the inheritable state a re-registered account under the same id would
// otherwise pick up: recorded consent grants (which would bypass the consent
// gate) and registered second factors. Another subject's data is untouched.
func TestEraseSubject_ClearsConsentAndMFAEnrollments(t *testing.T) {
	consent := &fakeConsentStore{grants: map[string][]core.ConsentGrant{
		"alice": {{UserID: "alice", ClientID: "app1"}, {UserID: "alice", ClientID: "app2"}},
		"bob":   {{UserID: "bob", ClientID: "app1"}},
	}}
	mfa := &fakeMFAEnroll{factors: map[string][]core.MFAEnrolledFactor{
		"alice": {{ID: "totp-1"}, {ID: "passkey-1"}},
		"bob":   {{ID: "totp-9"}},
	}}
	e := &compliance.Eraser{Consent: consent, MFAEnrollments: mfa}

	rep, err := e.EraseSubject(context.Background(), "alice", compliance.EraseOptions{})
	if err != nil {
		t.Fatalf("EraseSubject: %v", err)
	}
	if rep.ConsentRevoked != 2 {
		t.Errorf("ConsentRevoked = %d, want 2", rep.ConsentRevoked)
	}
	if rep.MFAFactorsRemoved != 2 {
		t.Errorf("MFAFactorsRemoved = %d, want 2", rep.MFAFactorsRemoved)
	}
	if len(consent.grants["alice"]) != 0 {
		t.Errorf("alice consent not cleared: %v", consent.grants["alice"])
	}
	if len(mfa.factors["alice"]) != 0 {
		t.Errorf("alice MFA factors not cleared: %v", mfa.factors["alice"])
	}
	// Cross-subject isolation.
	if len(consent.grants["bob"]) != 1 || len(mfa.factors["bob"]) != 1 {
		t.Errorf("bob's data was touched: consent=%v mfa=%v", consent.grants["bob"], mfa.factors["bob"])
	}
}
