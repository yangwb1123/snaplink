package ssotest

// MFA recovery-code redemption end-to-end. Proves that a recovery code,
// composed as a second spi.MFAProvider via defaultimpl.NewMultiMFAProvider,
// resolves the same /auth/login -> mfa_required -> /auth/mfa flow TOTP does:
//   - mfa_methods lists both "totp" and "recovery"
//   - a valid recovery code mints tokens
//   - the code is single-use (replay on a fresh challenge -> mfa_invalid)
//   - an unknown code collapses to the same mfa_invalid + a mfa_failure audit
//     (oracle-leak hardening — no branch in the server_mfa.go hot path)
//
// Reuses loginMFA / completeMFA / sinkEvents / hasEvent + totpStubStore from
// mfa_test.go (same package).

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// buildRecoveryHarness mirrors buildMFAHarness but composes TOTP + a
// RecoveryMFAProvider over one MemoryRecoveryCodeStore, and wires that same
// store via WithRecoveryCodeStore. Returns the running server, the audit sink,
// and the recovery store so the caller can mint codes for subject "alice".
func buildRecoveryHarness(t *testing.T) (*httptest.Server, *audit.MemorySink, *defaultimpl.MemoryRecoveryCodeStore) {
	t.Helper()

	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("mfa-test"))
	sessions := defaultimpl.NewMemorySessionManager()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: "alice"})

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    "mfa-app",
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt",
		Active:                true,
	})

	pwAuth := authenticators.NewPasswordAuthenticator(
		authenticators.PasswordVerifierFunc(func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == "alice" && p == "s3cret" {
				return &sso.AuthResult{UserID: "alice"}, nil
			}
			return nil, errors.New("bad creds")
		}),
	)

	totpAuth := authenticators.NewTOTPAuthenticator(&totpStubStore{secret: []byte("12345678901234567890")})
	recStore := defaultimpl.NewMemoryRecoveryCodeStore()
	recProvider, err := defaultimpl.NewRecoveryMFAProvider(recStore)
	if err != nil {
		t.Fatalf("recovery provider: %v", err)
	}
	multi, err := defaultimpl.NewMultiMFAProvider(authenticators.NewTOTPMFAProvider(totpAuth), recProvider)
	if err != nil {
		t.Fatalf("multi provider: %v", err)
	}

	sink := audit.NewMemorySink(50)
	srv := sso.NewServer(
		sso.WithIssuer("mfa-test"),
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithSessionManager(sessions),
		sso.WithAuthenticator(pwAuth),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithPermissionProvider(permissions.NewMemoryProvider()),
		sso.WithAuditRecorder(audit.New(sink)),
		sso.WithRiskScorer(newStubScorer(spi.DecisionRequireMFA)),
		sso.WithMFAProvider(multi),
		sso.WithMFAChallengeStore(defaultimpl.NewMemoryMFAChallengeStore(), 0),
		sso.WithRecoveryCodeStore(recStore),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, sink, recStore
}

// TestMFA_RecoveryCode_HappyPathAndSingleUse — recovery surfaces in mfa_methods,
// a valid code mints tokens, and a replay of that same code on a fresh challenge
// is rejected (single-use).
func TestMFA_RecoveryCode_HappyPathAndSingleUse(t *testing.T) {
	srv, _, recStore := buildRecoveryHarness(t)
	codes, err := recStore.Generate(context.Background(), "alice", 8)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	_, body := loginMFA(t, srv)
	if body["error"] != sso.ErrMFARequired {
		t.Fatalf("want mfa_required, got %v", body["error"])
	}
	methods, _ := body["mfa_methods"].([]any)
	if !containsMethod(methods, authenticators.MethodTOTP) || !containsMethod(methods, defaultimpl.MethodRecovery) {
		t.Fatalf("mfa_methods = %v, want both totp and recovery", methods)
	}
	chal := body["mfa_challenge_id"].(string)

	status, out := completeMFA(t, srv, chal, defaultimpl.MethodRecovery, codes[0])
	if status != http.StatusOK {
		t.Fatalf("recovery redeem = %d body=%v, want 200", status, out)
	}
	if _, ok := out["access_token"].(string); !ok {
		t.Fatalf("no access_token: %v", out)
	}

	// Single-use: the same code on a fresh challenge -> 400 mfa_invalid.
	_, body2 := loginMFA(t, srv)
	st2, out2 := completeMFA(t, srv, body2["mfa_challenge_id"].(string), defaultimpl.MethodRecovery, codes[0])
	if st2 != http.StatusBadRequest || out2["error"] != sso.ErrMFAInvalid {
		t.Fatalf("replay = %d %v, want 400 mfa_invalid", st2, out2)
	}
}

// TestMFA_RecoveryCode_WrongCode — an unknown code collapses to the same
// mfa_invalid response TOTP failures use, with a mfa_failure audit event.
func TestMFA_RecoveryCode_WrongCode(t *testing.T) {
	srv, sink, recStore := buildRecoveryHarness(t)
	if _, err := recStore.Generate(context.Background(), "alice", 8); err != nil {
		t.Fatalf("generate: %v", err)
	}

	_, body := loginMFA(t, srv)
	chal := body["mfa_challenge_id"].(string)

	status, out := completeMFA(t, srv, chal, defaultimpl.MethodRecovery, "ZZZZ2345")
	if status != http.StatusBadRequest || out["error"] != sso.ErrMFAInvalid {
		t.Fatalf("wrong code = %d %v, want 400 mfa_invalid", status, out)
	}
	if !hasEvent(sinkEvents(t, sink), audit.EventMFAFailure) {
		t.Errorf("missing mfa_failure audit event")
	}
}

// containsMethod reports whether the decoded mfa_methods array contains method.
func containsMethod(methods []any, method string) bool {
	for _, m := range methods {
		if s, ok := m.(string); ok && s == method {
			return true
		}
	}
	return false
}
