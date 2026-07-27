package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	sqlitestores "github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/spi"
)

const pwExpiryUserID = "u-pwexpiry-alice"
const pwExpiryPassword = "correct horse battery staple"

// newPasswordExpiryHarness wires a REAL sqlite-backed password credential
// store (so PasswordChangedAt reads the actual `updated_at` column, not a
// mock) behind authenticators.NewStoredPasswordVerifier — the same
// production wiring a real deployment uses, not a hardcoded-credential stub —
// with the given password policy. policy == nil means WithPasswordPolicy is
// never called at all (the "feature never touched" default); a non-nil
// policy is wired via WithPasswordPolicy regardless of its MaxAgeDays value,
// so a caller can also exercise "policy wired, but MaxAgeDays left at 0."
//
// Returns the running server plus the credential store's *sql.DB (via its
// already-exported DB() accessor) so a test can backdate the stamped
// updated_at column to simulate an aged-out password — there is no
// production API for "set the clock back"; this pokes the real column
// directly, the same way an operator's own migration/backfill script would.
func newPasswordExpiryHarness(t *testing.T, policy *spi.PasswordPolicyConfig) (*httptest.Server, *sqlitestores.PasswordCredentialStore) {
	t.Helper()
	ctx := context.Background()

	users := defaultimpl.NewMemoryUserProvider()
	if err := users.CreateOrUpdate(ctx, &sso.User{ID: pwExpiryUserID}); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	creds, err := sqlitestores.NewPasswordCredentialStore(memDSN("pwexpiry_" + t.Name()))
	if err != nil {
		t.Fatalf("NewPasswordCredentialStore: %v", err)
	}
	t.Cleanup(func() { _ = creds.Close() })
	if err := creds.SetPassword(ctx, pwExpiryUserID, pwExpiryPassword); err != nil {
		t.Fatalf("SetPassword: %v", err)
	}

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "pwexpiry-app", Secret: "s", Name: "PW Expiry App",
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt", Active: true,
	})

	// Identity resolver: this harness's login username IS the userID (the
	// "simplest deployments" case NewStoredPasswordVerifier's doc describes).
	resolve := func(_ context.Context, username string) (string, error) { return username, nil }
	pw := authenticators.NewPasswordAuthenticator(authenticators.NewStoredPasswordVerifier(creds, resolve))

	opts := []sso.Option{
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithPasswordCredentialStore(creds),
	}
	if policy != nil {
		opts = append(opts, sso.WithPasswordPolicy(spi.NewPasswordPolicyValidator(*policy)))
	}
	srv := sso.NewServer(opts...)
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return hs, creds
}

// loginPWExpiry drives POST /auth/login for the harness's seeded user and
// returns the status code plus decoded JSON body.
func loginPWExpiry(t *testing.T, baseURL string) (int, map[string]any) {
	t.Helper()
	reqBody, err := json.Marshal(map[string]any{
		"provider":   authenticators.MethodPassword,
		"client_id":  "pwexpiry-app",
		"credential": map[string]string{"username": pwExpiryUserID, "password": pwExpiryPassword},
	})
	if err != nil {
		t.Fatalf("marshal login body: %v", err)
	}
	resp, err := http.Post(baseURL+"/auth/login", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("login POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// backdatePasswordChangedAt rewrites the stored updated_at column directly
// via the store's exported DB() accessor (no mock — this is the real row a
// production deployment's own SetPassword wrote, just time-traveled).
func backdatePasswordChangedAt(t *testing.T, store *sqlitestores.PasswordCredentialStore, userID string, age time.Duration) {
	t.Helper()
	ts := time.Now().Add(-age).UnixNano()
	if _, err := store.DB().ExecContext(context.Background(),
		`UPDATE password_credentials SET updated_at = ? WHERE user_id = ?`, ts, userID); err != nil {
		t.Fatalf("backdate updated_at: %v", err)
	}
}

// TestAuthLogin_PasswordExpiry_NoPolicyWired_NoOp confirms a deployment that
// never calls WithPasswordPolicy at all sees zero behavior change — even for
// a credential backdated far past any plausible age window. This is the
// primary regression guard: the feature must be a complete no-op unless an
// operator opts in.
func TestAuthLogin_PasswordExpiry_NoPolicyWired_NoOp(t *testing.T) {
	t.Parallel()
	hs, creds := newPasswordExpiryHarness(t, nil)
	backdatePasswordChangedAt(t, creds, pwExpiryUserID, 365*24*time.Hour)

	status, body := loginPWExpiry(t, hs.URL)
	if status != http.StatusOK {
		t.Fatalf("expected 200 with no password policy wired, got %d: %v", status, body)
	}
}

// TestAuthLogin_PasswordExpiry_MaxAgeDaysZero_NoOp confirms MaxAgeDays==0 is
// a no-op even when a PasswordPolicyValidator IS wired for OTHER dimensions
// (e.g. MinLength) — the zero value must mean "not enforced" for this
// dimension specifically, not "wire the whole feature off".
func TestAuthLogin_PasswordExpiry_MaxAgeDaysZero_NoOp(t *testing.T) {
	t.Parallel()
	hs, creds := newPasswordExpiryHarness(t, &spi.PasswordPolicyConfig{MinLength: 4, MaxAgeDays: 0})
	backdatePasswordChangedAt(t, creds, pwExpiryUserID, 365*24*time.Hour)

	status, body := loginPWExpiry(t, hs.URL)
	if status != http.StatusOK {
		t.Fatalf("expected 200 with MaxAgeDays=0, got %d: %v", status, body)
	}
}

// TestAuthLogin_PasswordExpiry_WithinMaxAge_Succeeds confirms a freshly-set
// password (well within a 90-day window) logs in normally.
func TestAuthLogin_PasswordExpiry_WithinMaxAge_Succeeds(t *testing.T) {
	t.Parallel()
	hs, _ := newPasswordExpiryHarness(t, &spi.PasswordPolicyConfig{MaxAgeDays: 90})

	status, body := loginPWExpiry(t, hs.URL)
	if status != http.StatusOK {
		t.Fatalf("expected 200 for a fresh password, got %d: %v", status, body)
	}
	if body["access_token"] == "" || body["access_token"] == nil {
		t.Fatalf("expected an access_token in the response: %v", body)
	}
}

// TestAuthLogin_PasswordExpiry_PastMaxAge_RejectedDistinctCode confirms a
// password older than the configured MaxAgeDays is rejected with the
// distinct password_expired code (403) — NOT collapsed into
// invalid_credentials/invalid_grant. Per AGENTS.md §3 Anti-Enumeration this is
// deliberate: the password already verified correctly (this check runs after
// authentication succeeds), so "expired" here is a policy-state signal, not a
// credential-validity oracle.
func TestAuthLogin_PasswordExpiry_PastMaxAge_RejectedDistinctCode(t *testing.T) {
	t.Parallel()
	hs, creds := newPasswordExpiryHarness(t, &spi.PasswordPolicyConfig{MaxAgeDays: 90})
	backdatePasswordChangedAt(t, creds, pwExpiryUserID, 91*24*time.Hour)

	status, body := loginPWExpiry(t, hs.URL)
	if status != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %v", status, body)
	}
	code, _ := body["error"].(string)
	if code != "password_expired" {
		t.Fatalf("expected error=password_expired, got %v (full body: %v)", code, body)
	}
	if body["access_token"] != nil {
		t.Fatalf("an expired-password rejection must not carry a token: %v", body)
	}
}

// TestAuthLogin_PasswordExpiry_ExactlyAtBoundary_Succeeds confirms the
// boundary is exclusive ("aged past" the window, not "at" it) — a credential
// exactly MaxAgeDays old (to the second) still logs in. This pins the
// time.Since(changedAt) < maxAge comparison so a future refactor can't
// accidentally flip it to <= and start rejecting on the boundary day.
func TestAuthLogin_PasswordExpiry_ExactlyAtBoundary_Succeeds(t *testing.T) {
	t.Parallel()
	hs, creds := newPasswordExpiryHarness(t, &spi.PasswordPolicyConfig{MaxAgeDays: 90})
	// Comfortably inside the window (a few seconds shy of 90 days) — a
	// same-second race at the exact nanosecond boundary would be flaky and
	// isn't the property under test.
	backdatePasswordChangedAt(t, creds, pwExpiryUserID, 90*24*time.Hour-10*time.Second)

	status, body := loginPWExpiry(t, hs.URL)
	if status != http.StatusOK {
		t.Fatalf("expected 200 just inside the MaxAgeDays window, got %d: %v", status, body)
	}
}
