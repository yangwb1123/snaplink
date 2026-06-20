package sqlite_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/core"
)

func newClientStore(t *testing.T) *sqlite.ClientStore {
	t.Helper()
	st, err := sqlite.NewClientStore(freshSharedDSN(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestSQLiteClients_AddGetRoundTrip(t *testing.T) {
	st := newClientStore(t)
	in := &sso.Client{
		ID:                    "web",
		Secret:                "shh",
		Name:                  "Web App",
		RedirectURIs:          []string{"https://app/cb", "https://app/cb2"},
		AllowedScopes:         []string{"read", "write"},
		AllowedAuthenticators: []string{"password", "phone"},
		TokenStrategy:         "jwt",
		Active:                true,
		TenantID:              "acme",
		RequirePKCE:           true,
	}
	if err := st.Add(context.Background(), in); err != nil {
		t.Fatalf("Add: %v", err)
	}
	out, err := st.Get(context.Background(), "web")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// Secret is now stored as a bcrypt hash — verify via ValidateSecret, not
	// direct string comparison.
	if out.Name != "Web App" || out.TenantID != "acme" {
		t.Errorf("scalar mismatch: %+v", out)
	}
	if !strings.HasPrefix(out.Secret, "$2") {
		t.Errorf("Secret not hashed after Add: %q", out.Secret)
	}
	if err := st.ValidateSecret(context.Background(), "web", "shh"); err != nil {
		t.Errorf("ValidateSecret with original plaintext: %v", err)
	}
	if len(out.RedirectURIs) != 2 || len(out.AllowedScopes) != 2 || len(out.AllowedAuthenticators) != 2 {
		t.Errorf("slice round-trip failed: %+v", out)
	}
	if !out.RequirePKCE || !out.Active {
		t.Errorf("bool round-trip failed: %+v", out)
	}
}

// TestSQLiteClients_SecurityFieldsSurviveRestart proves the v2 migration's
// security-load-bearing columns round-trip through a fresh store over the
// SAME DSN — the exact scenario (process restart on identity.backend=sqlite)
// where these fields previously reverted to zero, silently downgrading
// private_key_jwt/JAR verification, the RFC 7592 management credential, and
// the RFC 8707/9101 SSRF allowlists.
func TestSQLiteClients_SecurityFieldsSurviveRestart(t *testing.T) {
	dsn := freshSharedDSN(t)
	st, err := sqlite.NewClientStore(dsn)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	in := &sso.Client{
		ID:                      "secure",
		Secret:                  "shh",
		Name:                    "Secure App",
		Active:                  true,
		RegistrationAccessToken: "rat-secret-7592",
		JWKS: []core.JWK{{
			Kty: "OKP", Use: "sig", Alg: "EdDSA", Kid: "k1",
			Crv: "Ed25519", X: "abc123",
		}},
		AllowedResources:             []string{"https://api.one", "https://api.two"},
		AllowedRequestURIs:           []string{"https://rp/req1", "https://rp/req2"},
		PostLogoutRedirectURIs:       []string{"https://rp/logged-out"},
		IDTokenEncryptedResponseAlg:  "RSA-OAEP-256",
		IDTokenEncryptedResponseEnc:  "A256GCM",
		UserinfoEncryptedResponseAlg: "ECDH-ES",
		UserinfoEncryptedResponseEnc: "A128GCM",
		Federation:                   true,
	}
	if err := st.Add(context.Background(), in); err != nil {
		t.Fatalf("Add: %v", err)
	}

	// Re-open over the same DSN: a NEW store with its own connection pool,
	// mirroring a server restart. The cache=shared in-memory DB persists for
	// the test's lifetime as long as one connection stays open, so keep the
	// original store alive until the assertions run.
	st2, err := sqlite.NewClientStore(dsn)
	if err != nil {
		t.Fatalf("re-open New: %v", err)
	}
	t.Cleanup(func() { _ = st2.Close(); _ = st.Close() })

	out, err := st2.Get(context.Background(), "secure")
	if err != nil {
		t.Fatalf("Get after restart: %v", err)
	}
	// RegistrationAccessToken is stored as a bcrypt hash — verify via validation
	if !strings.HasPrefix(out.RegistrationAccessToken, "$2") {
		t.Errorf("RegistrationAccessToken not hashed after Add: %q", out.RegistrationAccessToken)
	}
	if len(out.JWKS) != 1 || out.JWKS[0].Kid != "k1" || out.JWKS[0].Kty != "OKP" ||
		out.JWKS[0].Crv != "Ed25519" || out.JWKS[0].X != "abc123" {
		t.Errorf("JWKS round-trip failed: %+v", out.JWKS)
	}
	if len(out.AllowedResources) != 2 || out.AllowedResources[0] != "https://api.one" {
		t.Errorf("AllowedResources round-trip failed: %+v", out.AllowedResources)
	}
	if len(out.AllowedRequestURIs) != 2 || out.AllowedRequestURIs[1] != "https://rp/req2" {
		t.Errorf("AllowedRequestURIs round-trip failed: %+v", out.AllowedRequestURIs)
	}
	if len(out.PostLogoutRedirectURIs) != 1 || out.PostLogoutRedirectURIs[0] != "https://rp/logged-out" {
		t.Errorf("PostLogoutRedirectURIs round-trip failed: %+v", out.PostLogoutRedirectURIs)
	}
	if out.IDTokenEncryptedResponseAlg != "RSA-OAEP-256" || out.IDTokenEncryptedResponseEnc != "A256GCM" ||
		out.UserinfoEncryptedResponseAlg != "ECDH-ES" || out.UserinfoEncryptedResponseEnc != "A128GCM" {
		t.Errorf("JWE alg/enc round-trip failed: %+v", out)
	}
	if !out.Federation {
		t.Errorf("Federation round-trip failed: got false want true")
	}
}

// TestSQLiteClients_SecurityFieldsUpdateRoundTrip proves the Update path
// (not just Add) persists the v2 columns — Update has its own SET list that
// must stay in lockstep with INSERT and scan.
func TestSQLiteClients_SecurityFieldsUpdateRoundTrip(t *testing.T) {
	st := newClientStore(t)
	if err := st.Add(context.Background(), &sso.Client{ID: "u2", Secret: "s", Active: true}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	updated := &sso.Client{
		ID: "u2", Secret: "s", Active: true,
		RegistrationAccessToken:     "updated-rat",
		JWKS:                        []core.JWK{{Kty: "EC", Crv: "P-256", Kid: "ec1", X: "xx", Y: "yy"}},
		AllowedResources:            []string{"https://api.updated"},
		AllowedRequestURIs:          []string{"https://rp/updated"},
		PostLogoutRedirectURIs:      []string{"https://rp/out"},
		IDTokenEncryptedResponseAlg: "RSA-OAEP-256",
		Federation:                  true,
	}
	if err := st.Update(context.Background(), updated); err != nil {
		t.Fatalf("Update: %v", err)
	}
	out, err := st.Get(context.Background(), "u2")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// RegistrationAccessToken is now stored as a bcrypt hash.
	if !strings.HasPrefix(out.RegistrationAccessToken, "$2") || !out.Federation ||
		out.IDTokenEncryptedResponseAlg != "RSA-OAEP-256" {
		t.Errorf("Update scalar v2 fields not applied: %+v", out)
	}
	if len(out.JWKS) != 1 || out.JWKS[0].Kid != "ec1" ||
		len(out.AllowedResources) != 1 || len(out.AllowedRequestURIs) != 1 ||
		len(out.PostLogoutRedirectURIs) != 1 {
		t.Errorf("Update slice/JWKS v2 fields not applied: %+v", out)
	}
}

// TestSQLiteClients_EmptySecurityFieldsRoundTripCleanly locks the backward-
// compatibility invariant: a client with none of the v2 fields set comes
// back with the same zero values (nil slices, empty strings, false), so the
// new columns are byte-identical to the v1 schema for legacy/minimal clients.
func TestSQLiteClients_EmptySecurityFieldsRoundTripCleanly(t *testing.T) {
	st := newClientStore(t)
	if err := st.Add(context.Background(), &sso.Client{ID: "min", Secret: "s", Active: true}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	out, err := st.Get(context.Background(), "min")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if out.RegistrationAccessToken != "" || out.Federation ||
		out.IDTokenEncryptedResponseAlg != "" || out.UserinfoEncryptedResponseEnc != "" {
		t.Errorf("empty scalar v2 fields not zero: %+v", out)
	}
	if out.JWKS != nil || out.AllowedResources != nil ||
		out.AllowedRequestURIs != nil || out.PostLogoutRedirectURIs != nil {
		t.Errorf("empty slice v2 fields not nil: %+v", out)
	}
}

func TestSQLiteClients_AddDuplicateReturnsExists(t *testing.T) {
	st := newClientStore(t)
	c := &sso.Client{ID: "dup", Secret: "s", Active: true}
	if err := st.Add(context.Background(), c); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	err := st.Add(context.Background(), c)
	if !errors.Is(err, sso.ErrClientExists) {
		t.Errorf("duplicate Add err = %v want ErrClientExists", err)
	}
}

func TestSQLiteClients_GetMissingReturnsNoSuchClient(t *testing.T) {
	st := newClientStore(t)
	_, err := st.Get(context.Background(), "ghost")
	if !errors.Is(err, sso.ErrNoSuchClient) {
		t.Errorf("err = %v want ErrNoSuchClient", err)
	}
}

func TestSQLiteClients_ValidateSecret(t *testing.T) {
	st := newClientStore(t)
	_ = st.Add(context.Background(), &sso.Client{ID: "x", Secret: "right", Active: true})
	if err := st.ValidateSecret(context.Background(), "x", "right"); err != nil {
		t.Errorf("matching secret err = %v", err)
	}
	if err := st.ValidateSecret(context.Background(), "x", "wrong"); err == nil {
		t.Error("wrong secret accepted")
	}
	if err := st.ValidateSecret(context.Background(), "ghost", "anything"); !errors.Is(err, sso.ErrNoSuchClient) {
		t.Errorf("unknown client err = %v want ErrNoSuchClient", err)
	}
}

func TestSQLiteClients_UpdateChangesFields(t *testing.T) {
	ctx := context.Background()
	st := newClientStore(t)
	_ = st.Add(ctx, &sso.Client{ID: "u", Secret: "s1", Active: true})
	updated := &sso.Client{
		ID: "u", Secret: "s2", Name: "Updated",
		RedirectURIs: []string{"https://new/cb"}, Active: false, RequirePKCE: true,
	}
	if err := st.Update(ctx, updated); err != nil {
		t.Fatalf("Update: %v", err)
	}
	out, _ := st.Get(ctx, "u")
	// Secret is stored as a bcrypt hash — verify the new value via
	// ValidateSecret rather than direct comparison.
	if out.Name != "Updated" || out.Active {
		t.Errorf("update not applied: %+v", out)
	}
	if !strings.HasPrefix(out.Secret, "$2") {
		t.Errorf("Secret not hashed after Update: %q", out.Secret)
	}
	// The update flipped Active to false; ValidateSecret rejects inactive
	// clients (parity with memory), so re-activate to exercise the secret
	// rotation independently of the active gate.
	reactivated := *updated
	reactivated.Active = true
	if err := st.Update(ctx, &reactivated); err != nil {
		t.Fatalf("re-activate Update: %v", err)
	}
	if err := st.ValidateSecret(ctx, "u", "s2"); err != nil {
		t.Errorf("ValidateSecret with updated plaintext: %v", err)
	}
	if err := st.ValidateSecret(ctx, "u", "s1"); err == nil {
		t.Error("old secret still accepted after Update")
	}
	if !out.RequirePKCE || out.RedirectURIs[0] != "https://new/cb" {
		t.Errorf("update slices/bools not applied: %+v", out)
	}
}

func TestSQLiteClients_UpdateUnknownReturnsNoSuchClient(t *testing.T) {
	st := newClientStore(t)
	err := st.Update(context.Background(), &sso.Client{ID: "ghost"})
	if !errors.Is(err, sso.ErrNoSuchClient) {
		t.Errorf("err = %v want ErrNoSuchClient", err)
	}
}

func TestSQLiteClients_DeleteIsIdempotent(t *testing.T) {
	st := newClientStore(t)
	_ = st.Add(context.Background(), &sso.Client{ID: "d", Secret: "s", Active: true})
	if err := st.Delete(context.Background(), "d"); err != nil {
		t.Errorf("first Delete: %v", err)
	}
	if err := st.Delete(context.Background(), "d"); err != nil {
		t.Errorf("second Delete err = %v want nil (idempotent)", err)
	}
	if err := st.Delete(context.Background(), "never-existed"); err != nil {
		t.Errorf("Delete on missing err = %v", err)
	}
}

func TestSQLiteClients_RotateSecretReturnsNewSecret(t *testing.T) {
	st := newClientStore(t)
	_ = st.Add(context.Background(), &sso.Client{ID: "r", Secret: "old", Active: true})
	newSecret, err := st.RotateSecret(context.Background(), "r")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if newSecret == "" || newSecret == "old" {
		t.Errorf("rotation produced no change: %q", newSecret)
	}
	if err := st.ValidateSecret(context.Background(), "r", newSecret); err != nil {
		t.Errorf("ValidateSecret(new) err = %v", err)
	}
}

func TestSQLiteClients_RotateSecretUnknownReturnsNoSuchClient(t *testing.T) {
	st := newClientStore(t)
	_, err := st.RotateSecret(context.Background(), "ghost")
	if !errors.Is(err, sso.ErrNoSuchClient) {
		t.Errorf("err = %v want ErrNoSuchClient", err)
	}
}

func TestSQLiteClients_ListOrderedById(t *testing.T) {
	st := newClientStore(t)
	for _, id := range []string{"c-3", "c-1", "c-2"} {
		_ = st.Add(context.Background(), &sso.Client{ID: id, Secret: "s", Active: true})
	}
	out, err := st.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("expected 3 clients, got %d", len(out))
	}
	if out[0].ID != "c-1" || out[1].ID != "c-2" || out[2].ID != "c-3" {
		t.Errorf("order wrong: %+v", []string{out[0].ID, out[1].ID, out[2].ID})
	}
}

func TestSQLiteClients_ListByTenant(t *testing.T) {
	st := newClientStore(t)
	_ = st.Add(context.Background(), &sso.Client{ID: "a1", Secret: "s", TenantID: "acme", Active: true})
	_ = st.Add(context.Background(), &sso.Client{ID: "a2", Secret: "s", TenantID: "acme", Active: true})
	_ = st.Add(context.Background(), &sso.Client{ID: "b1", Secret: "s", TenantID: "beta", Active: true})
	_ = st.Add(context.Background(), &sso.Client{ID: "p1", Secret: "s", Active: true}) // no tenant

	acme, err := st.ListByTenant(context.Background(), "acme")
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if len(acme) != 2 {
		t.Errorf("acme clients = %d want 2", len(acme))
	}
	for _, c := range acme {
		if c.TenantID != "acme" {
			t.Errorf("got client with tenant_id=%q in acme query", c.TenantID)
		}
	}
}

func TestSQLiteStats_OrderIndependentHash(t *testing.T) {
	ctx := context.Background()
	// Same logical set inserted in different orders across two fresh
	// DBs must fingerprint identically — row order must not leak.
	a := newClientStore(t)
	_ = a.Add(ctx, &sso.Client{ID: "c-1", Secret: "s", AllowedScopes: []string{"read", "write"}, Active: true})
	_ = a.Add(ctx, &sso.Client{ID: "c-2", Secret: "s", AllowedScopes: []string{"profile"}, Active: true})

	b := newClientStore(t)
	_ = b.Add(ctx, &sso.Client{ID: "c-2", Secret: "different-secret", AllowedScopes: []string{"profile"}, Active: false})
	// Reversed scope order + differing secret/active must NOT change the
	// digest (only discovery-relevant set membership feeds it).
	_ = b.Add(ctx, &sso.Client{ID: "c-1", Secret: "s", AllowedScopes: []string{"write", "read"}, Active: true})

	ca, ha, err := a.Stats(ctx)
	if err != nil {
		t.Fatalf("a.Stats: %v", err)
	}
	cb, hb, err := b.Stats(ctx)
	if err != nil {
		t.Fatalf("b.Stats: %v", err)
	}
	if ca != 2 || cb != 2 {
		t.Errorf("count: a=%d b=%d want 2", ca, cb)
	}
	if ha != hb {
		t.Errorf("hash differs across row order: a=%s b=%s", ha, hb)
	}
}

func TestSQLiteStats_ScopeChangeFlipsHash(t *testing.T) {
	ctx := context.Background()
	st := newClientStore(t)
	_ = st.Add(ctx, &sso.Client{ID: "c-1", Secret: "s", AllowedScopes: []string{"read"}, Active: true})
	_, before, _ := st.Stats(ctx)

	if err := st.Update(ctx, &sso.Client{ID: "c-1", Secret: "s", AllowedScopes: []string{"read", "admin"}, Active: true}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	_, after, _ := st.Stats(ctx)
	if before == after {
		t.Errorf("scope change did not flip hash: %s", after)
	}

	// Secret rotation is not a discovery-relevant field -> stable hash.
	stable := after
	if _, err := st.RotateSecret(ctx, "c-1"); err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}
	_, afterRotate, _ := st.Stats(ctx)
	if afterRotate != stable {
		t.Errorf("secret rotation flipped discovery hash: %s -> %s", stable, afterRotate)
	}
}

func TestSQLiteStats_AddDeleteRestoresHash(t *testing.T) {
	ctx := context.Background()
	st := newClientStore(t)
	_ = st.Add(ctx, &sso.Client{ID: "c-1", Secret: "s", AllowedScopes: []string{"read"}, Active: true})
	c1, h1, _ := st.Stats(ctx)

	_ = st.Add(ctx, &sso.Client{ID: "c-2", Secret: "s", AllowedScopes: []string{"read"}, Active: true})
	c2, h2, _ := st.Stats(ctx)
	if c1 != 1 || c2 != 2 {
		t.Errorf("count: c1=%d c2=%d want 1,2", c1, c2)
	}
	if h1 == h2 {
		t.Errorf("adding a client did not flip hash: %s", h2)
	}

	_ = st.Delete(ctx, "c-2")
	c3, h3, _ := st.Stats(ctx)
	if c3 != 1 || h3 != h1 {
		t.Errorf("delete did not restore fingerprint: count=%d hash=%s want 1,%s", c3, h3, h1)
	}
}

// TestSQLiteClients_SecretHashAtRest proves that Add stores a bcrypt hash,
// not the plaintext, and that ValidateSecret accepts the original plaintext.
func TestSQLiteClients_SecretHashAtRest(t *testing.T) {
	ctx := context.Background()
	st := newClientStore(t)
	plaintext := "plaintext-secret"
	if err := st.Add(ctx, &sso.Client{ID: "hash-test", Secret: plaintext, Active: true}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	out, err := st.Get(ctx, "hash-test")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// Stored value must be a bcrypt hash, not the plaintext.
	if out.Secret == plaintext {
		t.Error("Secret stored as plaintext — hash-at-rest not applied")
	}
	if !strings.HasPrefix(out.Secret, "$2") {
		t.Errorf("stored value is not a bcrypt hash: %q", out.Secret)
	}
	// Correct plaintext must validate.
	if err := st.ValidateSecret(ctx, "hash-test", plaintext); err != nil {
		t.Errorf("ValidateSecret correct: %v", err)
	}
	// Wrong plaintext must fail.
	if err := st.ValidateSecret(ctx, "hash-test", "wrong"); err == nil {
		t.Error("wrong secret accepted")
	}
}

// TestSQLiteClients_SecretPlaintextFallback proves the backward-compatibility
// path: a client whose Secret was inserted directly as plaintext (pre-migration)
// is still accepted by ValidateSecret without rehashing.
func TestSQLiteClients_SecretPlaintextFallback(t *testing.T) {
	ctx := context.Background()
	st := newClientStore(t)
	// Bypass the hashing by inserting the raw plaintext directly via SQL —
	// the same situation an existing DB row is in before this feature was
	// deployed.
	_, err := st.DB().ExecContext(ctx, `INSERT INTO clients
		(id, secret, name, redirect_uris, allowed_scopes, allowed_authenticators,
		 token_strategy, active, tenant_id, require_pkce, registration_access_token,
		 jwks, allowed_resources, allowed_request_uris, post_logout_redirect_uris,
		 idtoken_encrypted_response_alg, idtoken_encrypted_response_enc,
		 userinfo_encrypted_response_alg, userinfo_encrypted_response_enc, federation)
		VALUES ('legacy', 'raw-plaintext', '', '[]', '[]', '[]', '', 1, '', 0, '',
		 '[]', '[]', '[]', '[]', '', '', '', '', 0)`)
	if err != nil {
		t.Fatalf("direct insert: %v", err)
	}
	// ValidateSecret must accept the plaintext via the fallback path.
	if err := st.ValidateSecret(ctx, "legacy", "raw-plaintext"); err != nil {
		t.Errorf("plaintext fallback rejected: %v", err)
	}
	if err := st.ValidateSecret(ctx, "legacy", "wrong"); err == nil {
		t.Error("wrong plaintext accepted on fallback path")
	}
}

// TestSQLiteClients_RotateSecretHashAtRest proves that RotateSecret stores a
// bcrypt hash and returns the plaintext to the caller.
func TestSQLiteClients_RotateSecretHashAtRest(t *testing.T) {
	ctx := context.Background()
	st := newClientStore(t)
	_ = st.Add(ctx, &sso.Client{ID: "rot", Secret: "initial", Active: true})
	plaintext, err := st.RotateSecret(ctx, "rot")
	if err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}
	if plaintext == "" || strings.HasPrefix(plaintext, "$2") {
		t.Errorf("RotateSecret returned hash instead of plaintext: %q", plaintext)
	}
	out, _ := st.Get(ctx, "rot")
	if !strings.HasPrefix(out.Secret, "$2") {
		t.Errorf("stored secret after rotate is not a bcrypt hash: %q", out.Secret)
	}
	if err := st.ValidateSecret(ctx, "rot", plaintext); err != nil {
		t.Errorf("ValidateSecret(rotated plaintext): %v", err)
	}
	// The old plaintext must no longer work.
	if err := st.ValidateSecret(ctx, "rot", "initial"); err == nil {
		t.Error("old plaintext still accepted after rotate")
	}
}

// TestSQLiteClients_ValidateSecretRejectsInactive proves the SQLite
// backend mirrors MemoryClientStore: a deactivated confidential client
// MUST NOT pass ValidateSecret even with the correct secret. The /token
// grant path relies solely on this gate, so without it a deactivated
// client kept exchanging client_credentials/refresh for fresh tokens.
func TestSQLiteClients_ValidateSecretRejectsInactive(t *testing.T) {
	ctx := context.Background()
	st := newClientStore(t)

	if err := st.Add(ctx, &sso.Client{ID: "deact", Secret: "shh", Active: true}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// While active, the correct secret validates.
	if err := st.ValidateSecret(ctx, "deact", "shh"); err != nil {
		t.Fatalf("ValidateSecret(active): %v", err)
	}

	// Deactivate.
	cur, err := st.Get(ctx, "deact")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	cur.Active = false
	if err := st.Update(ctx, cur); err != nil {
		t.Fatalf("Update: %v", err)
	}

	// Correct secret, inactive client → rejected for parity with memory.
	if err := st.ValidateSecret(ctx, "deact", "shh"); err == nil {
		t.Fatal("inactive client validated secret; deactivated client can still mint tokens")
	} else if got := err.Error(); got != "client is inactive" {
		t.Errorf("error = %q, want %q (parity with MemoryClientStore)", got, "client is inactive")
	}

	// A wrong secret on an inactive client still fails (secret-check first,
	// matching the memory ordering).
	if err := st.ValidateSecret(ctx, "deact", "nope"); err == nil {
		t.Error("wrong secret on inactive client unexpectedly validated")
	}
}
