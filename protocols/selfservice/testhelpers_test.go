package selfservice

// Package-local test adapter for selfservicecore.Deps, mirroring the thin
// registerDeps pattern in protocols/oauth/handle_register_test.go: real
// in-memory stores back every storage-backed method; pure config accessors
// return deterministic stubs. Not a mock of anything with a repo-wide
// Memory* default — the senders/gates/validator/rate-limiter are inherently
// pluggable strategy interfaces with no such default.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl/memorystorecredential"
	"github.com/snaplink/sso/domains/identitylink"
	identitylinkmemory "github.com/snaplink/sso/domains/identitylink/memory"
	"github.com/snaplink/sso/infrastructure/defaultimpl/memorystoreidentity"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/protocols/compliance"
	"github.com/snaplink/sso/protocols/selfservice/selfservicecore"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

// testDeps implements selfservicecore.Deps for direct, package-local handler
// tests (no HTTP server, no full *sso.Server). Fields are exported-by-
// convention-within-file (lowercase, same package as the tests) so each test
// can seed exactly the stores/stubs it needs.
type testDeps struct {
	users         *memorystoreidentity.MemoryUserProvider
	passwords     *memorystorecredential.MemoryPasswordCredentialStore
	passwordReset *memorystorecredential.MemoryPasswordResetStore
	emailChange   *memorystorecredential.MemoryEmailChangeStore
	emailVerify   *memorystorecredential.MemoryEmailVerificationStore
	sessions      *memorystoreidentity.MemorySessionManager
	consents      *memorystoreidentity.MemoryConsentStore
	tenantUsers   *memorystoreidentity.MemoryTenantUserStore
	invitations   *memorystoreidentity.MemoryInvitationStore
	identityLinks *identitylinkmemory.Store

	identityUnlinked []string

	emailChangeTTL   time.Duration
	passwordResetTTL time.Duration
	emailVerifyTTL   time.Duration

	resetResolver         func(ctx context.Context, identifier string) (string, error)
	resetDeliveryResolver func(ctx context.Context, userID string) (string, error)
	resetSender           spi.PasswordResetSender
	emailChangeSender     spi.EmailChangeSender
	emailVerifySender     spi.EmailVerificationSender
	requireVerification   bool
	registrationGates     []spi.RegistrationGate
	rateLimiter           selfservicecore.RateLimiter
	passwordPolicy        spi.PasswordPolicyValidator

	auditor *audit.Recorder

	authSubject string
	authClaims  *core.TokenClaims

	residencyAccessDeny string
	residencyWriteDeny  string
	selfEditableAttrs   map[string]struct{}

	dataExporter  *compliance.Exporter
	accountEraser *compliance.Eraser

	consentRevoked []string
	factorSeq      int

	// passwordCredentialStoreOverride, when set, is returned by
	// PasswordCredentialStore() instead of the real memory store — used only
	// by the SetPassword-failure/rollback test, which needs a store that
	// fails on demand while still delegating everything else to the real one.
	passwordCredentialStoreOverride core.PasswordCredentialStore
}

// newTestDeps wires every storage-backed dependency to a fresh real in-memory
// store and defaults the authenticated caller to "user-1" (most handlers
// require a bearer subject; tests that need the unauthenticated path clear
// authSubject/authClaims explicitly).
func newTestDeps() *testDeps {
	return &testDeps{
		users:         memorystoreidentity.NewMemoryUserProvider(),
		passwords:     memorystorecredential.NewMemoryPasswordCredentialStore(),
		passwordReset: memorystorecredential.NewMemoryPasswordResetStore(),
		emailChange:   memorystorecredential.NewMemoryEmailChangeStore(),
		emailVerify:   memorystorecredential.NewMemoryEmailVerificationStore(),
		sessions:      memorystoreidentity.NewMemorySessionManager(),
		consents:      memorystoreidentity.NewMemoryConsentStore(),
		tenantUsers:   memorystoreidentity.NewMemoryTenantUserStore(),
		invitations:   memorystoreidentity.NewMemoryInvitationStore(),
		identityLinks: identitylinkmemory.New(),
		authSubject:   "user-1",
		authClaims:    &core.TokenClaims{Subject: "user-1"},
	}
}

func (d *testDeps) UserProvider() core.UserProvider { return d.users }
func (d *testDeps) PasswordCredentialStore() core.PasswordCredentialStore {
	if d.passwordCredentialStoreOverride != nil {
		return d.passwordCredentialStoreOverride
	}
	return d.passwords
}
func (d *testDeps) PasswordResetStore() core.PasswordResetStore { return d.passwordReset }
func (d *testDeps) EmailChangeTTL() time.Duration               { return d.emailChangeTTL }
func (d *testDeps) PasswordResetTTL() time.Duration             { return d.passwordResetTTL }

func (d *testDeps) PasswordResetResolver() func(context.Context, string) (string, error) {
	return d.resetResolver
}
func (d *testDeps) PasswordResetDeliveryResolver() func(context.Context, string) (string, error) {
	return d.resetDeliveryResolver
}
func (d *testDeps) PasswordResetSender() spi.PasswordResetSender { return d.resetSender }
func (d *testDeps) EmailChangeSender() spi.EmailChangeSender     { return d.emailChangeSender }
func (d *testDeps) EmailChangeStore() core.EmailChangeStore      { return d.emailChange }

func (d *testDeps) EmailVerificationStore() core.EmailVerificationStore { return d.emailVerify }
func (d *testDeps) EmailVerificationSender() spi.EmailVerificationSender {
	return d.emailVerifySender
}
func (d *testDeps) SignupRequiresVerification() bool               { return d.requireVerification }
func (d *testDeps) EmailVerificationTTL() time.Duration            { return d.emailVerifyTTL }
func (d *testDeps) RegistrationGates() []spi.RegistrationGate      { return d.registrationGates }
func (d *testDeps) SignupRateLimiter() selfservicecore.RateLimiter { return d.rateLimiter }

func (d *testDeps) SessionManager() core.SessionManager   { return d.sessions }
func (d *testDeps) TenantUserStore() core.TenantUserStore { return d.tenantUsers }
func (d *testDeps) InvitationStore() core.InvitationStore { return d.invitations }

func (d *testDeps) Auditor() *audit.Recorder { return d.auditor }
func (d *testDeps) Logger() spi.Logger       { return spi.NopLogger{} }

func (d *testDeps) GenerateAuthCodeBytes() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func (d *testDeps) TokenNoStoreHeaders(ctx core.HandlerContext) {
	h := ctx.ResponseWriter().Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
}

func (d *testDeps) ClearSiteData(ctx core.HandlerContext) {}

func (d *testDeps) ErrorBody(code string) map[string]any {
	out := map[string]any{}
	for k, v := range core.ErrorBody(code) {
		out[k] = v
	}
	return out
}

func (d *testDeps) MeSubjectOrChallenge(ctx core.HandlerContext) (string, bool) {
	if d.authSubject == "" {
		ctx.JSON(http.StatusUnauthorized, d.ErrorBody(core.ErrInvalidToken))
		return "", false
	}
	return d.authSubject, true
}

func (d *testDeps) MeClaimsOrChallenge(ctx core.HandlerContext) (*core.TokenClaims, bool) {
	if d.authClaims == nil {
		ctx.JSON(http.StatusUnauthorized, d.ErrorBody(core.ErrInvalidToken))
		return nil, false
	}
	return d.authClaims, true
}

func (d *testDeps) ConsentStore() core.ConsentStore { return d.consents }
func (d *testDeps) RecordConsentRevoked(_ core.HandlerContext, userID, clientID string) {
	d.consentRevoked = append(d.consentRevoked, userID+":"+clientID)
}

func (d *testDeps) IdentityLinkStore() identitylink.Store { return d.identityLinks }
func (d *testDeps) RecordIdentityUnlinked(_ core.HandlerContext, userID, linkID, provider string) {
	d.identityUnlinked = append(d.identityUnlinked, userID+":"+linkID+":"+provider)
}

func (d *testDeps) ResolveIssuer(core.HandlerContext) string { return "https://issuer.test" }
func (d *testDeps) SelfEditableAttrs() map[string]struct{}   { return d.selfEditableAttrs }

func (d *testDeps) ResidencyGateAccess(core.HandlerContext, *core.TokenClaims) (string, bool) {
	if d.residencyAccessDeny != "" {
		return d.residencyAccessDeny, true
	}
	return "", false
}

func (d *testDeps) ResidencyGateWrite(core.HandlerContext, *core.TokenClaims) (string, bool) {
	if d.residencyWriteDeny != "" {
		return d.residencyWriteDeny, true
	}
	return "", false
}

// WebAuthnRegistrar / MFAEnrollmentStore / TOTPEnroller are exercised by the
// selfserviceaccount package tests, not here — nil satisfies the interface
// for the handlers this package covers (they never call these accessors).
func (d *testDeps) WebAuthnRegistrar() core.WebAuthnRegistrar   { return nil }
func (d *testDeps) MFAEnrollmentStore() core.MFAEnrollmentStore { return nil }
func (d *testDeps) TOTPEnroller() core.TOTPEnroller             { return nil }

func (d *testDeps) NewMFAFactorID() (string, error) {
	d.factorSeq++
	return "factor-" + hex.EncodeToString([]byte{byte(d.factorSeq)}), nil
}

func (d *testDeps) DataExporter() *compliance.Exporter { return d.dataExporter }
func (d *testDeps) AccountEraser() *compliance.Eraser  { return d.accountEraser }

func (d *testDeps) PasswordPolicyValidator() spi.PasswordPolicyValidator { return d.passwordPolicy }

var _ Deps = (*testDeps)(nil)

// newCtx builds a real core.Context from an httptest request/recorder pair —
// the harness pattern established in protocols/oauth/handler_harness_test.go.
func newCtx(method, contentType, body string) (*core.Context, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(method, "/", strings.NewReader(body))
	if contentType != "" {
		req.Header.Set(core.HeaderContentType, contentType)
	}
	rec := httptest.NewRecorder()
	return core.NewContext(rec, req), rec
}

// decodeBody decodes the recorder's JSON body into a generic map.
func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	out := map[string]any{}
	b, _ := io.ReadAll(rec.Body)
	if len(bytes.TrimSpace(b)) == 0 {
		return out
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("decode body %q: %v", string(b), err)
	}
	return out
}

// servePath drives handler through a real core.StdRouter so a ":param"
// pattern is extracted exactly as in production (Context.params is
// unexported — routing is the only seam that populates it), mirroring
// protocols/oauth/handle_register_test.go's serveMgmt helper.
func servePath(method, pattern, actualPath, body string, handler core.HandlerFunc) *httptest.ResponseRecorder {
	r := core.NewStdRouter()
	switch method {
	case http.MethodGet:
		r.GET(pattern, handler)
	case http.MethodDelete:
		r.DELETE(pattern, handler)
	case http.MethodPost:
		r.POST(pattern, handler)
	case http.MethodPut:
		r.PUT(pattern, handler)
	}
	req := httptest.NewRequest(method, actualPath, strings.NewReader(body))
	if body != "" {
		req.Header.Set(core.HeaderContentType, core.ContentTypeJSON)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// futureExpiry / pastExpiry are readable shorthands for token ExpiresAt
// fixtures used across the signup/verify/reset/email-change tests.
func futureExpiry() time.Time { return time.Now().Add(time.Hour) }
func pastExpiry() time.Time   { return time.Now().Add(-time.Minute) }

// policyRequiringLength builds a real spi.PasswordPolicyValidator (not a
// stub — spi.NewPasswordPolicyValidator is the production constructor) that
// rejects any password shorter than n.
func policyRequiringLength(n int) spi.PasswordPolicyValidator {
	return spi.NewPasswordPolicyValidator(spi.PasswordPolicyConfig{MinLength: n})
}

// stubResetSender records the delivery target + token it was called with, and
// returns a configurable error (spi.PasswordResetSender has no repo-wide
// Memory* default — it's a pluggable delivery strategy).
type stubResetSender struct {
	err        error
	lastTarget string
	lastToken  string
	calls      int
}

func (s *stubResetSender) SendResetToken(_ context.Context, target, token string) error {
	s.calls++
	s.lastTarget, s.lastToken = target, token
	return s.err
}

// stubEmailChangeSender is the spi.EmailChangeSender counterpart of stubResetSender.
type stubEmailChangeSender struct {
	err       error
	lastEmail string
	lastToken string
	calls     int
}

func (s *stubEmailChangeSender) SendEmailChangeToken(_ context.Context, newEmail, token string) error {
	s.calls++
	s.lastEmail, s.lastToken = newEmail, token
	return s.err
}

// stubEmailVerificationSender is the spi.EmailVerificationSender counterpart.
type stubEmailVerificationSender struct {
	err       error
	lastEmail string
	lastToken string
	calls     int
}

func (s *stubEmailVerificationSender) SendEmailVerificationToken(_ context.Context, email, token string) error {
	s.calls++
	s.lastEmail, s.lastToken = email, token
	return s.err
}

// failingPasswordStore decorates a real core.PasswordCredentialStore, forcing
// SetPassword to fail for one userID so tests can exercise a handler's
// rollback-on-store-failure path without a hand-rolled fake of a storage
// interface that already has a real Memory* implementation.
type failingPasswordStore struct {
	real    core.PasswordCredentialStore
	failFor string
}

func (f *failingPasswordStore) SetPassword(ctx context.Context, userID, newPassword string) error {
	if userID == f.failFor {
		return errors.New("forced SetPassword failure")
	}
	return f.real.SetPassword(ctx, userID, newPassword)
}

func (f *failingPasswordStore) VerifyPassword(ctx context.Context, userID, plaintext string) error {
	return f.real.VerifyPassword(ctx, userID, plaintext)
}

// stubGate is a minimal spi.RegistrationGate: reject every registration with
// err (nil allows).
type stubGate struct{ err error }

func (g stubGate) CheckRegistration(context.Context, string, string, string) error { return g.err }

// stubRateLimiter is a minimal selfservicecore.RateLimiter with a fixed
// allow/retryAfter answer, so tests can force the 429 path deterministically.
type stubRateLimiter struct {
	allow      bool
	retryAfter time.Duration
}

func (l stubRateLimiter) Allow(string) (bool, time.Duration) { return l.allow, l.retryAfter }
