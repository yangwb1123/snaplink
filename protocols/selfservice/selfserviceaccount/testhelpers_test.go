package selfserviceaccount

// Package-local test adapter for selfservicecore.Deps, mirroring the pattern
// in protocols/selfservice/testhelpers_test.go and protocols/oauth/
// handle_register_test.go: real in-memory stores back every storage-backed
// method; pure config accessors return deterministic stubs.
//
// MFA store: infrastructure/defaultimpl/defaultmfa is NOT importable here —
// its memory_totp_enrollment.go imports domains/authenticators (for the
// login-time authenticators.TOTPStore contract), which imports
// interfaces/sso, which imports protocols/selfservice, which aliases
// protocols/selfservice/selfserviceaccount — a cycle back to this package.
// protocols/oauth/handler_harness_test.go establishes the same precedent
// (a package-local memClientStore) for the identical reason. localMFAStore
// below is that same pattern: a real, working in-memory implementation of
// core.MFAEnrollmentStore + core.TOTPEnrollmentWriter, just not the
// defaultmfa one.
//
// WebAuthn registrar / TOTP enroller stubs implement pluggable crypto/
// ceremony interfaces with no reachable default here for the same reason.
// The full WebAuthn/TOTP ceremonies are already covered end-to-end by
// interfaces/sso/rootcov*_test.go and test/me_mfa_webauthn_register_test.go.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators/device"
	"github.com/yangwb1123/snaplink/domains/identitylink"
	identitylinkmemory "github.com/yangwb1123/snaplink/domains/identitylink/memory"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/memorystorecredential"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/memorystoreidentity"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/sse"
	"github.com/yangwb1123/snaplink/protocols/compliance"
	"github.com/yangwb1123/snaplink/protocols/selfservice/selfservicecore"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

type testDeps struct {
	users         *memorystoreidentity.MemoryUserProvider
	passwords     *memorystorecredential.MemoryPasswordCredentialStore
	sessions      *memorystoreidentity.MemorySessionManager
	consents      *memorystoreidentity.MemoryConsentStore
	tenantUsers   *memorystoreidentity.MemoryTenantUserStore
	invitations   *memorystoreidentity.MemoryInvitationStore
	identityLinks *identitylinkmemory.Store

	identityUnlinked []string

	mfaStore core.MFAEnrollmentStore // *localMFAStore (default) or *localMFAStorePlain (no TOTPEnrollmentWriter)
	totp     core.TOTPEnroller
	webauthn core.WebAuthnRegistrar

	passwordPolicy  spi.PasswordPolicyValidator
	passwordHistory core.PasswordHistoryStore
	auditor         *audit.Recorder

	authSubject string
	authClaims  *core.TokenClaims

	residencyAccessDeny string
	residencyWriteDeny  string
	selfEditableAttrs   map[string]struct{}

	dataExporter  *compliance.Exporter
	accountEraser *compliance.Eraser

	factorSeq int
}

// newTestDeps wires every storage-backed dependency to a fresh real in-memory
// store, authenticated by default as "user-1". The MFA store defaults to
// localMFAStore, which implements BOTH core.MFAEnrollmentStore and
// core.TOTPEnrollmentWriter — tests exercising the "store lacks
// TOTPEnrollmentWriter" 501 branch swap in newLocalMFAStorePlain instead.
func newTestDeps() *testDeps {
	return &testDeps{
		users:         memorystoreidentity.NewMemoryUserProvider(),
		passwords:     memorystorecredential.NewMemoryPasswordCredentialStore(),
		sessions:      memorystoreidentity.NewMemorySessionManager(),
		consents:      memorystoreidentity.NewMemoryConsentStore(),
		tenantUsers:   memorystoreidentity.NewMemoryTenantUserStore(),
		invitations:   memorystoreidentity.NewMemoryInvitationStore(),
		identityLinks: identitylinkmemory.New(),
		mfaStore:      newLocalMFAStore(),
		authSubject:   "user-1",
		authClaims:    &core.TokenClaims{Subject: "user-1"},
	}
}

func (d *testDeps) UserProvider() core.UserProvider                       { return d.users }
func (d *testDeps) PasswordCredentialStore() core.PasswordCredentialStore { return d.passwords }
func (d *testDeps) PasswordResetStore() core.PasswordResetStore           { return nil }
func (d *testDeps) EmailChangeTTL() time.Duration                         { return 0 }
func (d *testDeps) PasswordResetTTL() time.Duration                       { return 0 }

func (d *testDeps) PasswordResetResolver() func(context.Context, string) (string, error) { return nil }
func (d *testDeps) PasswordResetDeliveryResolver() func(context.Context, string) (string, error) {
	return nil
}
func (d *testDeps) PasswordResetSender() spi.PasswordResetSender { return nil }
func (d *testDeps) EmailChangeSender() spi.EmailChangeSender     { return nil }
func (d *testDeps) EmailChangeStore() core.EmailChangeStore      { return nil }

func (d *testDeps) EmailVerificationStore() core.EmailVerificationStore  { return nil }
func (d *testDeps) EmailVerificationSender() spi.EmailVerificationSender { return nil }
func (d *testDeps) SignupRequiresVerification() bool                     { return false }
func (d *testDeps) EmailVerificationTTL() time.Duration                  { return 0 }
func (d *testDeps) RegistrationGates() []spi.RegistrationGate            { return nil }
func (d *testDeps) SignupRateLimiter() selfservicecore.RateLimiter       { return nil }

func (d *testDeps) SessionManager() core.SessionManager          { return d.sessions }
func (d *testDeps) DeviceStore() device.Store                    { return nil }
func (d *testDeps) LoginHistoryStore() device.HistoryStore       { return nil }
func (d *testDeps) TenantUserStore() core.TenantUserStore        { return d.tenantUsers }
func (d *testDeps) InvitationStore() core.InvitationStore        { return d.invitations }
func (d *testDeps) InvitationSender() spi.InvitationSender       { return nil }
func (d *testDeps) TenantSuspended(context.Context, string) bool { return false }

func (d *testDeps) Auditor() *audit.Recorder { return d.auditor }
func (d *testDeps) Logger() spi.Logger       { return spi.NopLogger{} }

func (d *testDeps) GenerateAuthCodeBytes() (string, error) { return "test-auth-code", nil }

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

func (d *testDeps) ConsentStore() core.ConsentStore                          { return d.consents }
func (d *testDeps) RecordConsentRevoked(core.HandlerContext, string, string) {}

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

func (d *testDeps) WebAuthnRegistrar() core.WebAuthnRegistrar   { return d.webauthn }
func (d *testDeps) MFAEnrollmentStore() core.MFAEnrollmentStore { return d.mfaStore }
func (d *testDeps) TOTPEnroller() core.TOTPEnroller             { return d.totp }
func (d *testDeps) RecoveryCodeStore() core.RecoveryCodeStore   { return nil }
func (d *testDeps) TrustedDeviceStore() core.TrustedDeviceStore { return nil }
func (d *testDeps) TrustedDeviceTTL() time.Duration             { return 0 }

func (d *testDeps) NewMFAFactorID() (string, error) {
	d.factorSeq++
	return "factor-" + hex.EncodeToString([]byte{byte(d.factorSeq)}), nil
}

func (d *testDeps) DataExporter() *compliance.Exporter { return d.dataExporter }
func (d *testDeps) AccountEraser() *compliance.Eraser  { return d.accountEraser }

func (d *testDeps) PasswordPolicyValidator() spi.PasswordPolicyValidator { return d.passwordPolicy }
func (d *testDeps) PasswordHistoryStore() core.PasswordHistoryStore      { return d.passwordHistory }
func (d *testDeps) NotificationStore() core.NotificationStore            { return nil }
func (d *testDeps) NotificationPreferenceStore() core.NotificationPreferenceStore {
	return nil
}
func (d *testDeps) NotificationBroker() *sse.Broker { return nil }

var _ Deps = (*testDeps)(nil)

// newCtx / decodeBody / servePath mirror protocols/selfservice's harness
// (protocols/oauth/handler_harness_test.go established the pattern).
func newCtx(method, contentType, body string) (*core.Context, *httptest.ResponseRecorder) {
	req := httptest.NewRequest(method, "/", strings.NewReader(body))
	if contentType != "" {
		req.Header.Set(core.HeaderContentType, contentType)
	}
	rec := httptest.NewRecorder()
	return core.NewContext(rec, req), rec
}

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
// fixtures.
func futureExpiry() time.Time { return time.Now().Add(time.Hour) }
func pastExpiry() time.Time   { return time.Now().Add(-time.Minute) }

// policyRequiringLength builds a real spi.PasswordPolicyValidator (not a
// stub — spi.NewPasswordPolicyValidator is the production constructor) that
// rejects any password shorter than n.
func policyRequiringLength(n int) spi.PasswordPolicyValidator {
	return spi.NewPasswordPolicyValidator(spi.PasswordPolicyConfig{MinLength: n})
}

// stubTOTPEnroller is a deterministic core.TOTPEnroller: no real TOTP crypto,
// just enough to exercise the begin/confirm handler logic (secret/URI
// plumbing, VerifyCode branch) without depending on domains/authenticators
// (see the package doc comment for why that import would cycle).
type stubTOTPEnroller struct {
	validCode string // VerifyCode succeeds only for this code
}

func (s stubTOTPEnroller) GenerateSecret() ([]byte, error) { return []byte("fixed-test-secret"), nil }
func (s stubTOTPEnroller) EncodeSecret(secret []byte) string {
	return hex.EncodeToString(secret)
}
func (s stubTOTPEnroller) DecodeSecret(encoded string) ([]byte, error) {
	return hex.DecodeString(encoded)
}
func (s stubTOTPEnroller) OTPAuthURI(issuer, account string, secret []byte) string {
	return "otpauth://totp/" + issuer + ":" + account + "?secret=" + hex.EncodeToString(secret)
}
func (s stubTOTPEnroller) VerifyCode(_ []byte, code string) bool { return code == s.validCode }

var _ core.TOTPEnroller = stubTOTPEnroller{}

// stubWebAuthnRegistrar is a deterministic core.WebAuthnRegistrar exercising
// only the handler-side plumbing (session id / credential id passthrough,
// error propagation) — NOT a real WebAuthn attestation ceremony.
type stubWebAuthnRegistrar struct {
	beginErr  error
	finishErr error
	credID    string
}

func (s stubWebAuthnRegistrar) BeginRegistration(_ context.Context, userID, _ string) ([]byte, string, error) {
	if s.beginErr != nil {
		return nil, "", s.beginErr
	}
	return []byte(`{"publicKey":{}}`), "session-for-" + userID, nil
}

func (s stubWebAuthnRegistrar) FinishRegistration(_ context.Context, _, _ string, _ *http.Request) (string, error) {
	if s.finishErr != nil {
		return "", s.finishErr
	}
	return s.credID, nil
}

var _ core.WebAuthnRegistrar = stubWebAuthnRegistrar{}

// localMFAStore is a real, working in-memory core.MFAEnrollmentStore +
// core.TOTPEnrollmentWriter — see the package doc comment for why it's a
// package-local reimplementation of defaultmfa.MemoryTOTPEnrollmentStore
// rather than an import of that package (import cycle). One TOTP secret per
// user, mirroring defaultmfa's semantics: re-enrolling replaces the prior
// factor rather than accumulating a second one.
type localMFAStore struct {
	mu      sync.Mutex
	factors map[string]core.MFAEnrolledFactor
}

func newLocalMFAStore() *localMFAStore {
	return &localMFAStore{factors: make(map[string]core.MFAEnrolledFactor)}
}

func (s *localMFAStore) ListFactors(_ context.Context, userID string) ([]core.MFAEnrolledFactor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.factors[userID]
	if !ok {
		return []core.MFAEnrolledFactor{}, nil
	}
	return []core.MFAEnrolledFactor{f}, nil
}

func (s *localMFAStore) RemoveFactor(_ context.Context, userID, factorID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f, ok := s.factors[userID]; ok && f.ID == factorID {
		delete(s.factors, userID)
	}
	return nil
}

func (s *localMFAStore) AddTOTPFactor(_ context.Context, userID, factorID, label string, _ []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.factors[userID] = core.MFAEnrolledFactor{ID: factorID, Method: "totp", Label: label, AddedAt: time.Now()}
	return nil
}

var (
	_ core.MFAEnrollmentStore   = (*localMFAStore)(nil)
	_ core.TOTPEnrollmentWriter = (*localMFAStore)(nil)
)

// localMFAStorePlain implements core.MFAEnrollmentStore only (no
// AddTOTPFactor), backing the "store doesn't support TOTP enrollment" 501
// test path.
type localMFAStorePlain struct{}

func (localMFAStorePlain) ListFactors(context.Context, string) ([]core.MFAEnrolledFactor, error) {
	return []core.MFAEnrolledFactor{}, nil
}
func (localMFAStorePlain) RemoveFactor(context.Context, string, string) error { return nil }

var _ core.MFAEnrollmentStore = localMFAStorePlain{}
