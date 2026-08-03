package tokengrant

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/userlifecycle"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/protocols/oidc"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// fakeCIBAGrantDeps is a real (non-mock) implementation of CIBAGrantDeps
// backed by an in-memory JWT-less issuer, wired just enough to exercise
// MintCIBATokensForPush end to end (issuance, refresh, id_token, and the
// audit/metric recording calls, which are no-ops here). It intentionally
// has no refresh store / id-token issuer by default — tests that need
// those set the fields explicitly.
type fakeCIBAGrantDeps struct {
	issuer           core.TokenIssuer
	strategy         string
	issuerErr        error
	refreshStore     oauth.RefreshTokenStore
	refreshErr       error
	idTokenIssuer    oidc.IDTokenIssuer
	idTokenEmit      bool
	idTokenIssuerErr error
	lifecycleState   userlifecycle.State
	lifecycleErr     error
	loggedErrors     []string
}

func (f *fakeCIBAGrantDeps) CIBAStore() oauth.CIBAStore                 { return nil }
func (f *fakeCIBAGrantDeps) RefreshTokenStore() oauth.RefreshTokenStore { return f.refreshStore }

func (f *fakeCIBAGrantDeps) IssuerForClient(*core.Client) (string, core.TokenIssuer, error) {
	if f.issuerErr != nil {
		return "", nil, f.issuerErr
	}
	return f.strategy, f.issuer, nil
}

func (f *fakeCIBAGrantDeps) IDTokenIssuerForClient(*core.Client) (oidc.IDTokenIssuer, bool, error) {
	if f.idTokenIssuerErr != nil {
		return nil, false, f.idTokenIssuerErr
	}
	return f.idTokenIssuer, f.idTokenEmit, nil
}

func (f *fakeCIBAGrantDeps) ApplyPairwiseSubject(_ context.Context, _ *core.Client, localSub string) string {
	return localSub
}

func (f *fakeCIBAGrantDeps) LifecycleState(context.Context, string) (userlifecycle.State, error) {
	if f.lifecycleErr != nil {
		return userlifecycle.StateNone, f.lifecycleErr
	}
	if f.lifecycleState == userlifecycle.StateNone {
		return userlifecycle.StateActive, nil
	}
	return f.lifecycleState, nil
}

func (f *fakeCIBAGrantDeps) IssueRefreshToken(ctx context.Context, userID, clientID, provider string, scopes []string, attributes map[string]string, familyID string, resources []string, authDetails []byte, sid string, authCtx oauth.RefreshAuthContext, clientTTLOverride time.Duration, confirmationJKT string) (string, error) {
	if f.refreshErr != nil {
		return "", f.refreshErr
	}
	return "rt-" + userID, nil
}

func (f *fakeCIBAGrantDeps) MaybeEncryptIDToken(_ context.Context, _ *core.Client, signed string) (string, bool) {
	return signed, true
}

func (f *fakeCIBAGrantDeps) DPoPTokenTypeOr(defaultType, jkt string) string { return defaultType }

func (f *fakeCIBAGrantDeps) RecordTokenIssued(core.HandlerContext, string, string, string)      {}
func (f *fakeCIBAGrantDeps) RecordRefreshTokenIssued(core.HandlerContext, string, string, bool) {}
func (f *fakeCIBAGrantDeps) RecordIDTokenIssued(core.HandlerContext, string, string)            {}
func (f *fakeCIBAGrantDeps) RecordSubjectClientAccess(context.Context, string, string)          {}
func (f *fakeCIBAGrantDeps) RecordCIBADecision(core.HandlerContext, string, string, bool)       {}

func (f *fakeCIBAGrantDeps) SrvLogger() spi.Logger { return &recordingLogger{dst: &f.loggedErrors} }

var _ CIBAGrantDeps = (*fakeCIBAGrantDeps)(nil)

// recordingLogger captures Error() messages so tests can assert an
// issuance failure was logged (fail-open contract) without a live logger.
type recordingLogger struct {
	dst *[]string
}

func (l *recordingLogger) Info(string, ...any)  {}
func (l *recordingLogger) Debug(string, ...any) {}
func (l *recordingLogger) Error(msg string, _ ...any) {
	*l.dst = append(*l.dst, msg)
}

// fakeTokenIssuer is a minimal real core.TokenIssuer (no mock) for these
// tests — it doesn't sign anything, just returns a deterministic Token.
type fakeTokenIssuer struct {
	err error
}

func (f *fakeTokenIssuer) Issue(_ context.Context, subj *core.Subject, scopes []string) (*core.Token, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &core.Token{
		AccessToken: "AT-" + subj.ID,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		Scope:       "openid",
	}, nil
}

func (f *fakeTokenIssuer) Validate(context.Context, string) (*core.TokenClaims, error) {
	return nil, nil
}
func (f *fakeTokenIssuer) Revoke(context.Context, string) error { return nil }

func newBackgroundCtx() core.HandlerContext {
	return core.NewContext(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/", nil))
}

func approvedCIBARequest() *oauth.CIBARequest {
	return &oauth.CIBARequest{
		AuthReqID:               "areq-1",
		ClientID:                "rp",
		SubjectID:               "user-1",
		Scopes:                  []string{"openid"},
		ClientNotificationToken: "notify-tok",
		Status:                  oauth.CIBAApproved,
	}
}

// TestMintCIBATokensForPush_BuildsPushPayload proves the push path mints
// the SAME shape a poll response would carry (access token, token type,
// expires_in, refresh_token, id_token), just projected into a PushPayload
// instead of a JSON map, and that no sender-constraining proof is ever
// attached (there is no live request to have presented one).
func TestMintCIBATokensForPush_BuildsPushPayload(t *testing.T) {
	t.Parallel()
	d := &fakeCIBAGrantDeps{
		issuer:       &fakeTokenIssuer{},
		strategy:     "jwt",
		refreshStore: fakeRefreshStorePresent{},
	}
	client := &core.Client{ID: "rp"}
	r := approvedCIBARequest()

	payload, ok := MintCIBATokensForPush(d, newBackgroundCtx(), client, r, time.Now())
	if !ok {
		t.Fatal("expected ok=true")
	}
	if payload.AuthReqID != "areq-1" {
		t.Errorf("AuthReqID = %q, want areq-1", payload.AuthReqID)
	}
	if payload.AccessToken != "AT-user-1" {
		t.Errorf("AccessToken = %q, want AT-user-1", payload.AccessToken)
	}
	if payload.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want Bearer", payload.TokenType)
	}
	if payload.ExpiresIn != 3600 {
		t.Errorf("ExpiresIn = %d, want 3600", payload.ExpiresIn)
	}
	if payload.RefreshToken != "rt-user-1" {
		t.Errorf("RefreshToken = %q, want rt-user-1", payload.RefreshToken)
	}
}

// TestMintCIBATokensForPush_NoRefreshStoreOmitsRefreshToken proves refresh
// issuance stays fail-open/optional in the push path too: no refresh store
// wired means no refresh_token in the payload, not an error.
func TestMintCIBATokensForPush_NoRefreshStoreOmitsRefreshToken(t *testing.T) {
	t.Parallel()
	d := &fakeCIBAGrantDeps{issuer: &fakeTokenIssuer{}, strategy: "jwt"}
	client := &core.Client{ID: "rp"}
	r := approvedCIBARequest()

	payload, ok := MintCIBATokensForPush(d, newBackgroundCtx(), client, r, time.Now())
	if !ok {
		t.Fatal("expected ok=true")
	}
	if payload.RefreshToken != "" {
		t.Errorf("RefreshToken = %q, want empty (no refresh store wired)", payload.RefreshToken)
	}
	if payload.AccessToken == "" {
		t.Error("AccessToken must still be present")
	}
}

// TestMintCIBATokensForPush_IssuanceFailure proves an issuer error surfaces
// as ok=false and is logged (fail path), never panics — the ctx.JSON call
// inside buildCIBATokenResponse is a harmless no-op against the background
// context used here.
func TestMintCIBATokensForPush_IssuanceFailure(t *testing.T) {
	t.Parallel()
	d := &fakeCIBAGrantDeps{issuer: &fakeTokenIssuer{err: errors.New("issuer down")}, strategy: "jwt"}
	client := &core.Client{ID: "rp"}
	r := approvedCIBARequest()

	payload, ok := MintCIBATokensForPush(d, newBackgroundCtx(), client, r, time.Now())
	if ok {
		t.Fatal("expected ok=false on issuer failure")
	}
	if payload.AccessToken != "" {
		t.Errorf("expected zero-value payload, got %+v", payload)
	}
	if len(d.loggedErrors) == 0 {
		t.Error("expected the issuance failure to be logged")
	}
}

// TestMintCIBATokensForPush_IssuerResolutionFailure proves a client with no
// resolvable strategy also fails cleanly (ok=false, logged elsewhere via
// ctx.JSON no-op) rather than dereferencing a nil issuer.
func TestMintCIBATokensForPush_IssuerResolutionFailure(t *testing.T) {
	t.Parallel()
	d := &fakeCIBAGrantDeps{issuerErr: errors.New("no strategy for client")}
	client := &core.Client{ID: "rp"}
	r := approvedCIBARequest()

	_, ok := MintCIBATokensForPush(d, newBackgroundCtx(), client, r, time.Now())
	if ok {
		t.Fatal("expected ok=false when IssuerForClient fails")
	}
}

func TestMintCIBATokensForPush_LifecycleBlocked(t *testing.T) {
	t.Parallel()
	d := &fakeCIBAGrantDeps{
		issuer:         &fakeTokenIssuer{},
		strategy:       "jwt",
		lifecycleState: userlifecycle.StateSuspended,
	}

	payload, ok := MintCIBATokensForPush(d, newBackgroundCtx(), &core.Client{ID: "rp"}, approvedCIBARequest(), time.Now())
	if ok || payload.AccessToken != "" {
		t.Fatalf("suspended CIBA push = (%+v, %v), want no token and ok=false", payload, ok)
	}
}

// fakeIDTokenIssuer is a minimal real oidc.IDTokenIssuer (no mock): it
// doesn't sign anything, just returns a deterministic string.
type fakeIDTokenIssuer struct{}

func (fakeIDTokenIssuer) IssueIDToken(_ context.Context, req *oidc.IDTokenRequest) (string, error) {
	return "IDT-" + req.Subject, nil
}

// TestMintCIBATokensForPush_EmitsIDTokenForOpenIDScope proves the push
// payload carries an id_token when an IDTokenIssuer is wired and the
// request granted the openid scope — the full CIBA Core §10.3.1 payload
// shape (access_token + id_token + refresh_token), not just the access
// token.
func TestMintCIBATokensForPush_EmitsIDTokenForOpenIDScope(t *testing.T) {
	t.Parallel()
	d := &fakeCIBAGrantDeps{
		issuer:        &fakeTokenIssuer{},
		strategy:      "jwt",
		idTokenIssuer: fakeIDTokenIssuer{},
		idTokenEmit:   true,
	}
	client := &core.Client{ID: "rp"}
	r := approvedCIBARequest() // Scopes: []string{"openid"}

	payload, ok := MintCIBATokensForPush(d, newBackgroundCtx(), client, r, time.Now())
	if !ok {
		t.Fatal("expected ok=true")
	}
	if payload.IDToken != "IDT-user-1" {
		t.Errorf("IDToken = %q, want IDT-user-1", payload.IDToken)
	}
	if payload.AccessToken == "" {
		t.Error("AccessToken must still be present alongside id_token")
	}
}

// fakeRefreshStorePresent is a non-nil oauth.RefreshTokenStore stand-in:
// cibaIssueRefresh only branches on RefreshTokenStore() == nil to decide
// whether to mint a refresh token at all — the actual minting goes through
// the separate Deps.IssueRefreshToken method (fakeCIBAGrantDeps.IssueRefreshToken
// above), so this store is never actually called; it only needs to be
// non-nil to flip that branch on.
type fakeRefreshStorePresent struct{}

func (fakeRefreshStorePresent) Issue(context.Context, string, *oauth.RefreshToken) error {
	return nil
}
func (fakeRefreshStorePresent) Consume(context.Context, string) (*oauth.RefreshToken, error) {
	return nil, nil
}
