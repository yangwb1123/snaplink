package kerberosauth_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/oidc"

	kerberosauth "github.com/snaplink/sso/kerberos"
)

// ---- fake SPNEGOValidator (no real KDC / keytab) --------------------------
//
// fakeValidator stands in for the keytab-backed gokrb5 validator so the handler
// tests are KDC-free, mirroring kms/awskms's fakeKMS + ldap's fakeDirectory
// (the §2 "real impl, no mocks" discipline applied at the validation seam).
// When err is set, Validate FAILS CLOSED — the handler must then never mint.
type fakeValidator struct {
	principal string
	realm     string
	groups    []string
	err       error

	// gotToken captures the decoded token bytes the handler passed, so a test
	// can assert the handler base64-DECODED the header before validating (it
	// must hand the validator raw GSS bytes, not the base64 text).
	gotToken []byte
}

func (f *fakeValidator) Validate(_ context.Context, negotiateToken []byte) (string, string, []string, error) {
	f.gotToken = append([]byte(nil), negotiateToken...)
	if f.err != nil {
		return "", "", nil, f.err
	}
	return f.principal, f.realm, f.groups, nil
}

// ---- helpers --------------------------------------------------------------

const (
	testClientID = "kiosk-app"
	testRealm    = "EXAMPLE.COM"
	testSPN      = "HTTP/sso.example.com"
)

type harness struct {
	handler  http.HandlerFunc
	clients  *defaultimpl.MemoryClientStore
	users    *defaultimpl.MemoryUserProvider
	sessions *defaultimpl.MemorySessionManager
	issuer   *defaultimpl.Ed25519JWTIssuer
	// auditSink captures every recorded event so failure/success-audit tests
	// can assert the side channel (real MemorySink, no mock — §2).
	auditSink *audit.MemorySink
}

// newHarness wires real in-memory stores + an Ed25519 issuer (which implements
// BOTH sso.TokenIssuer and oidc.IDTokenIssuer) behind Build, with the supplied
// fake validator. The minting client is registered active with openid scope so
// the id_token path is exercised. An audit Recorder over a MemorySink is wired
// so tests can assert the login_success / login_failure side channel.
func newHarness(t *testing.T, v kerberosauth.SPNEGOValidator, cfgMut func(*kerberosauth.Config)) *harness {
	t.Helper()
	clients := defaultimpl.NewMemoryClientStore()
	users := defaultimpl.NewMemoryUserProvider()
	sessions := defaultimpl.NewMemorySessionManager()
	issuer := defaultimpl.NewEd25519JWTIssuer()
	auditSink := audit.NewMemorySink(64)
	recorder := audit.New(auditSink)

	if err := clients.Add(context.Background(), &sso.Client{
		ID:            testClientID,
		Active:        true,
		AllowedScopes: []string{sso.ScopeOpenID, "profile"},
	}); err != nil {
		t.Fatalf("add client: %v", err)
	}

	cfg := kerberosauth.Config{
		Name:             "kerberos",
		KeytabBytes:      []byte("not-a-real-keytab-the-fake-validator-bypasses-it"),
		ServicePrincipal: testSPN,
		Realm:            testRealm,
		ClientID:         testClientID,
	}
	if cfgMut != nil {
		cfgMut(&cfg)
	}

	res, err := kerberosauth.Build(kerberosauth.Deps{
		ClientStore:            clients,
		SessionManager:         sessions,
		UserProvider:           users,
		IssuerForClient:        func(c *sso.Client) (string, sso.TokenIssuer, error) { return "jwt", issuer, nil },
		IDTokenIssuerForClient: func(c *sso.Client) (oidc.IDTokenIssuer, bool, error) { return issuer, true, nil },
		AuditRecorder:          recorder,
	}, cfg, v)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(res.Handlers) == 0 {
		t.Fatal("Build returned no handlers")
	}
	// All mounted handlers share the same serve func; GET is the canonical leg.
	var h http.HandlerFunc
	for _, hs := range res.Handlers {
		if hs.Method == http.MethodGet {
			h = hs.Handler
		}
	}
	if h == nil {
		t.Fatal("no GET handler mounted")
	}
	return &harness{handler: h, clients: clients, users: users, sessions: sessions, issuer: issuer, auditSink: auditSink}
}

// newHarnessNoAudit builds a handler with NO AuditRecorder wired — the pre-FIX-#6
// configuration — so a test can capture the wire response as it was BEFORE the
// failure-audit side channel was added and prove the audited build is
// byte-identical on the wire.
func newHarnessNoAudit(t *testing.T, v kerberosauth.SPNEGOValidator) http.HandlerFunc {
	t.Helper()
	clients := defaultimpl.NewMemoryClientStore()
	if err := clients.Add(context.Background(), &sso.Client{
		ID: testClientID, Active: true, AllowedScopes: []string{sso.ScopeOpenID, "profile"},
	}); err != nil {
		t.Fatalf("add client: %v", err)
	}
	res, err := kerberosauth.Build(kerberosauth.Deps{
		ClientStore:    clients,
		SessionManager: defaultimpl.NewMemorySessionManager(),
		UserProvider:   defaultimpl.NewMemoryUserProvider(),
		IssuerForClient: func(c *sso.Client) (string, sso.TokenIssuer, error) {
			return "jwt", defaultimpl.NewEd25519JWTIssuer(), nil
		},
		// AuditRecorder deliberately nil.
	}, kerberosauth.Config{
		Name: "kerberos", KeytabBytes: []byte("kt"), ServicePrincipal: testSPN,
		Realm: testRealm, ClientID: testClientID,
	}, v)
	if err != nil {
		t.Fatalf("Build (no audit): %v", err)
	}
	for _, hs := range res.Handlers {
		if hs.Method == http.MethodGet {
			return hs.Handler
		}
	}
	t.Fatal("no GET handler mounted")
	return nil
}

func negotiateHeader(tokenBytes []byte) string {
	return "Negotiate " + base64.StdEncoding.EncodeToString(tokenBytes)
}

func doGET(h http.HandlerFunc, authHeader string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/auth/kerberos", nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	rr := httptest.NewRecorder()
	h(rr, req)
	return rr
}

func assertNoStore(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := rr.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q, want no-cache", got)
	}
}

func assertNegotiateChallenge(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
	if got := rr.Header().Get("WWW-Authenticate"); got != "Negotiate" {
		t.Errorf("WWW-Authenticate = %q, want Negotiate", got)
	}
}

// ---- tests ----------------------------------------------------------------

// TestNoNegotiateHeader_Challenges proves the initial SPNEGO handshake: a
// request with no Authorization header gets a 401 + WWW-Authenticate: Negotiate
// (the browser-trigger), no-store, and NO error body (this is the handshake,
// not a credential failure).
func TestNoNegotiateHeader_Challenges(t *testing.T) {
	v := &fakeValidator{principal: "alice", realm: testRealm}
	h := newHarness(t, v, nil)

	rr := doGET(h.handler, "")

	assertNegotiateChallenge(t, rr)
	assertNoStore(t, rr)
	if body := strings.TrimSpace(rr.Body.String()); body != "" {
		t.Errorf("initial challenge body = %q, want empty (no error= on the handshake leg)", body)
	}
	// The validator must NOT have been consulted — no token was offered.
	if v.gotToken != nil {
		t.Error("validator was called on the no-credential challenge leg")
	}
	// No user / session created.
	assertNoMint(t, h)
}

// TestNonNegotiateScheme_Challenges proves a non-Negotiate Authorization scheme
// (e.g. a Bearer header) is treated as the handshake leg, not a parse error.
func TestNonNegotiateScheme_Challenges(t *testing.T) {
	v := &fakeValidator{principal: "alice", realm: testRealm}
	h := newHarness(t, v, nil)

	rr := doGET(h.handler, "Bearer some.jwt.token")

	assertNegotiateChallenge(t, rr)
	assertNoStore(t, rr)
	if v.gotToken != nil {
		t.Error("validator called on a non-Negotiate scheme")
	}
}

// TestValidToken_MintsTokens proves the happy path: a token the fake validator
// accepts yields a 200 with an access token + id_token, a created session, the
// upserted user carrying the mapped realm/groups attributes, AMR krb5 on the
// minted access token, and no-store throughout.
func TestValidToken_MintsTokens(t *testing.T) {
	v := &fakeValidator{
		principal: "alice",
		realm:     testRealm,
		groups:    []string{"S-1-5-21-aaa", "S-1-5-21-bbb"},
	}
	h := newHarness(t, v, nil)

	rawToken := []byte("\x60\x82fake-gss-token-bytes")
	rr := doGET(h.handler, negotiateHeader(rawToken))

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	assertNoStore(t, rr)

	// Handler must have base64-DECODED the header before validating.
	if !bytesEqual(v.gotToken, rawToken) {
		t.Errorf("validator got %q, want the decoded token %q", v.gotToken, rawToken)
	}

	var resp struct {
		Principal   string `json:"principal"`
		SessionID   string `json:"session_id"`
		Status      string `json:"status"`
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		IDToken     string `json:"id_token"`
		Scope       string `json:"scope"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	wantPrincipal := "alice@" + testRealm
	if resp.Principal != wantPrincipal {
		t.Errorf("principal = %q, want %q", resp.Principal, wantPrincipal)
	}
	if resp.Status != sso.StatusAuthenticated {
		t.Errorf("status = %q, want authenticated", resp.Status)
	}
	if resp.AccessToken == "" {
		t.Error("no access_token minted")
	}
	if resp.IDToken == "" {
		t.Error("no id_token minted (openid scope + id issuer wired)")
	}
	if resp.SessionID == "" {
		t.Error("no session_id returned")
	}

	// Session actually created in the manager.
	if sess, err := h.sessions.Get(context.Background(), resp.SessionID); err != nil || sess == nil {
		t.Errorf("session %q not found in manager: %v", resp.SessionID, err)
	}

	// User upserted with the mapped attributes (default keys).
	u, err := h.users.GetByID(context.Background(), wantPrincipal)
	if err != nil || u == nil {
		t.Fatalf("user %q not upserted: %v", wantPrincipal, err)
	}
	if u.Provider != "kerberos" {
		t.Errorf("user provider = %q, want kerberos", u.Provider)
	}
	if u.Attributes["krb5_realm"] != testRealm {
		t.Errorf("krb5_realm attr = %q, want %q", u.Attributes["krb5_realm"], testRealm)
	}
	if u.Attributes["krb5_groups"] != "S-1-5-21-aaa,S-1-5-21-bbb" {
		t.Errorf("krb5_groups attr = %q, want the comma-joined SIDs", u.Attributes["krb5_groups"])
	}

	// The minted access token validates and carries AMR ["krb5"] + the
	// qualified subject + the session id (sid) — the proof the principal was
	// mapped onto a real RFC 9068 token, not just echoed.
	claims, err := h.issuer.Validate(context.Background(), resp.AccessToken)
	if err != nil {
		t.Fatalf("validate minted access token: %v", err)
	}
	if claims.Subject != wantPrincipal {
		t.Errorf("token sub = %q, want %q", claims.Subject, wantPrincipal)
	}
	if !containsStr(claims.AMR, "krb5") {
		t.Errorf("token AMR = %v, want it to contain krb5", claims.AMR)
	}
	if claims.ClientID != testClientID {
		t.Errorf("token client_id = %q, want %q", claims.ClientID, testClientID)
	}
}

// TestForgedToken_Rejected is the SECURITY contract: a token the validator
// rejects (the analogue of a forged / expired / wrong-realm / replayed ticket)
// yields a generic 401 invalid_token + a Negotiate retry challenge, mints
// NOTHING, and is byte-identical regardless of WHICH validation failed
// (oracle-safe).
func TestForgedToken_Rejected(t *testing.T) {
	// Two DISTINCT internal failure causes must produce the SAME wire response.
	causes := []error{
		errors.New("bad signature against keytab"),
		errors.New("ticket expired"),
	}
	var bodies []string
	for _, cause := range causes {
		v := &fakeValidator{err: cause}
		h := newHarness(t, v, nil)

		rr := doGET(h.handler, negotiateHeader([]byte("forged-token")))

		assertNegotiateChallenge(t, rr) // 401 + Negotiate (retry allowed)
		assertNoStore(t, rr)

		var resp map[string]string
		_ = json.Unmarshal(rr.Body.Bytes(), &resp)
		if resp["error"] != "invalid_token" {
			t.Errorf("error = %q, want invalid_token (oracle-safe)", resp["error"])
		}
		// NOTHING minted on a rejected token.
		assertNoMint(t, h)
		bodies = append(bodies, rr.Body.String())
	}
	// The two distinct causes are indistinguishable on the wire.
	if bodies[0] != bodies[1] {
		t.Errorf("oracle leak: distinct failure causes produced different bodies:\n %q\n %q", bodies[0], bodies[1])
	}
}

// TestMalformedBase64_Rejected proves a Negotiate header whose value isn't
// valid base64 collapses to the SAME generic 401 invalid_token as a bad ticket
// (no decode-vs-validate oracle), and never reaches the validator with junk.
func TestMalformedBase64_Rejected(t *testing.T) {
	v := &fakeValidator{principal: "alice", realm: testRealm}
	h := newHarness(t, v, nil)

	// '!' is not in the base64 alphabet.
	rr := doGET(h.handler, "Negotiate not!!base64!!")

	assertNegotiateChallenge(t, rr)
	assertNoStore(t, rr)
	var resp map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "invalid_token" {
		t.Errorf("error = %q, want invalid_token", resp["error"])
	}
	if v.gotToken != nil {
		t.Error("validator was handed an undecodable token")
	}
	assertNoMint(t, h)
}

// TestWrongRealm_Rejected proves the defense-in-depth realm gate: even when the
// validator SUCCEEDS (the keytab validated the ticket), a principal from a
// realm other than the configured one is rejected with the SAME generic 401 and
// mints nothing.
func TestWrongRealm_Rejected(t *testing.T) {
	v := &fakeValidator{principal: "mallory", realm: "EVIL.CORP"} // != EXAMPLE.COM
	h := newHarness(t, v, nil)

	rr := doGET(h.handler, negotiateHeader([]byte("valid-but-foreign-realm")))

	assertNegotiateChallenge(t, rr)
	assertNoStore(t, rr)
	var resp map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "invalid_token" {
		t.Errorf("error = %q, want invalid_token", resp["error"])
	}
	assertNoMint(t, h)
}

// TestForgedToken_EmitsFailureAudit (FIX #6) proves a validation failure emits a
// SECRET-FREE login_failure audit event (Outcome=failure, provider, reason=
// krb5_validate, NO identity/secret) — the side channel that surfaces brute-
// force/replay attempts to the audit pipeline + anomaly detectors — WHILE the
// wire response stays the byte-identical generic 401 (oracle-safe). No principal
// is attached: validation failed, so there is no proven identity.
func TestForgedToken_EmitsFailureAudit(t *testing.T) {
	const secretCause = "bad signature against keytab S-1-5-21-secret"
	v := &fakeValidator{err: errors.New(secretCause)}
	h := newHarness(t, v, nil)

	// Capture the wire response WITHOUT auditing first, to prove byte-identity.
	noAudit := newHarnessNoAudit(t, &fakeValidator{err: errors.New("a different cause entirely")})
	wantBody := doGET(noAudit, negotiateHeader([]byte("forged"))).Body.String()

	rr := doGET(h.handler, negotiateHeader([]byte("forged-token")))

	// Wire stays the generic 401 + Negotiate, and byte-identical to the
	// no-audit build (the audit is purely server-side).
	assertNegotiateChallenge(t, rr)
	assertNoStore(t, rr)
	if rr.Body.String() != wantBody {
		t.Errorf("audit changed the wire body:\n got %q\n want %q", rr.Body.String(), wantBody)
	}
	var resp map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["error"] != "invalid_token" {
		t.Errorf("error = %q, want invalid_token", resp["error"])
	}
	assertNoMint(t, h)

	// The failure audit is recorded, secret-free, with no attached identity.
	// The validator's internal error string (secretCause) must NEVER appear.
	assertSecretFreeFailureAudit(t, h, "krb5_validate", "", secretCause, "forged-token", "S-1-5-21-secret")
}

// TestWrongRealm_EmitsFailureAudit (FIX #6) proves the realm-gate rejection
// emits a login_failure audit (reason=krb5_realm_mismatch). Here the principal
// IS keytab-validated (the KDC asserted it), so the qualified principal MAY be
// attached for the operator's triage — but still no secret (ticket/keytab). The
// wire stays the byte-identical generic 401.
func TestWrongRealm_EmitsFailureAudit(t *testing.T) {
	v := &fakeValidator{principal: "mallory", realm: "EVIL.CORP"} // != EXAMPLE.COM
	h := newHarness(t, v, nil)

	rr := doGET(h.handler, negotiateHeader([]byte("valid-but-foreign-realm")))

	assertNegotiateChallenge(t, rr)
	assertNoStore(t, rr)
	assertNoMint(t, h)

	// reason=krb5_realm_mismatch; the keytab-validated principal@realm IS
	// attached (legitimate — it is KDC-asserted, not attacker-controlled). No
	// secret material rides the event.
	assertSecretFreeFailureAudit(t, h, "krb5_realm_mismatch", "mallory@EVIL.CORP", "valid-but-foreign-realm")
	// And the validated foreign realm rides Metadata for triage.
	e := auditEventsOfType(t, h, audit.EventLoginFailure)[0]
	if e.Metadata["krb5_realm"] != "EVIL.CORP" {
		t.Errorf("realm-mismatch Metadata[krb5_realm] = %q, want EVIL.CORP", e.Metadata["krb5_realm"])
	}
}

// TestMalformedBase64_EmitsFailureAudit (FIX #6) proves the malformed-base64
// path (which never reaches the validator) ALSO emits the krb5_validate failure
// audit, with no identity — consistent with its oracle-safe collapse to the
// same 401 as a bad ticket.
func TestMalformedBase64_EmitsFailureAudit(t *testing.T) {
	v := &fakeValidator{principal: "alice", realm: testRealm}
	h := newHarness(t, v, nil)

	rr := doGET(h.handler, "Negotiate not!!base64!!")

	assertNegotiateChallenge(t, rr)
	if v.gotToken != nil {
		t.Error("validator was handed an undecodable token")
	}
	assertNoMint(t, h)
	assertSecretFreeFailureAudit(t, h, "krb5_validate", "")
}

// TestNoCredentialChallenge_NoFailureAudit (FIX #6) proves the INITIAL handshake
// leg (no Authorization header) does NOT emit a failure audit — it is the normal
// SPNEGO challenge, not a credential failure, so it must not pollute the audit
// pipeline / trip brute-force detectors.
func TestNoCredentialChallenge_NoFailureAudit(t *testing.T) {
	v := &fakeValidator{principal: "alice", realm: testRealm}
	h := newHarness(t, v, nil)

	doGET(h.handler, "")           // no credential
	doGET(h.handler, "Bearer abc") // non-Negotiate scheme = also the handshake leg

	if fails := auditEventsOfType(t, h, audit.EventLoginFailure); len(fails) != 0 {
		t.Errorf("login_failure events on the handshake leg = %d, want 0", len(fails))
	}
}

// TestValidToken_EmitsLoginSuccessAudit (FIX #6 parity) proves the SUCCESS path
// still records a login_success (unchanged) and NO login_failure.
func TestValidToken_EmitsLoginSuccessAudit(t *testing.T) {
	v := &fakeValidator{principal: "alice", realm: testRealm}
	h := newHarness(t, v, nil)

	rr := doGET(h.handler, negotiateHeader([]byte("\x60\x82ok")))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}

	succ := auditEventsOfType(t, h, audit.EventLogin)
	if len(succ) != 1 {
		t.Fatalf("login_success events = %d, want 1", len(succ))
	}
	if succ[0].Outcome != audit.OutcomeSuccess {
		t.Errorf("success Outcome = %q, want success", succ[0].Outcome)
	}
	if succ[0].ActorID != "alice@"+testRealm {
		t.Errorf("success ActorID = %q, want the qualified principal", succ[0].ActorID)
	}
	if fails := auditEventsOfType(t, h, audit.EventLoginFailure); len(fails) != 0 {
		t.Errorf("login_failure events on the success path = %d, want 0", len(fails))
	}
}

// TestGroupRealmMapping_CustomKeys proves AttributeMapping renames the derived
// realm + groups attributes onto the AuthResult/user under the operator's keys.
func TestGroupRealmMapping_CustomKeys(t *testing.T) {
	v := &fakeValidator{
		principal: "bob",
		realm:     testRealm,
		groups:    []string{"admins"},
	}
	h := newHarness(t, v, func(c *kerberosauth.Config) {
		c.AttributeMapping = map[string]string{
			"realm":  "domain",
			"groups": "roles",
		}
	})

	rr := doGET(h.handler, negotiateHeader([]byte("ok")))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}

	u, err := h.users.GetByID(context.Background(), "bob@"+testRealm)
	if err != nil || u == nil {
		t.Fatalf("user not upserted: %v", err)
	}
	if u.Attributes["domain"] != testRealm {
		t.Errorf("mapped realm attr 'domain' = %q, want %q", u.Attributes["domain"], testRealm)
	}
	if u.Attributes["roles"] != "admins" {
		t.Errorf("mapped groups attr 'roles' = %q, want admins", u.Attributes["roles"])
	}
	// The default keys must NOT also be present (mapping replaced them).
	if _, ok := u.Attributes["krb5_realm"]; ok {
		t.Error("default krb5_realm key present despite remap")
	}
}

// TestNoPACGroups_OmitsAttr proves a principal with no PAC groups simply omits
// the groups attribute (the access token + realm still mint).
func TestNoPACGroups_OmitsAttr(t *testing.T) {
	v := &fakeValidator{principal: "svc", realm: testRealm, groups: nil}
	h := newHarness(t, v, nil)

	rr := doGET(h.handler, negotiateHeader([]byte("ok")))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	u, err := h.users.GetByID(context.Background(), "svc@"+testRealm)
	if err != nil || u == nil {
		t.Fatalf("user not upserted: %v", err)
	}
	if _, ok := u.Attributes["krb5_groups"]; ok {
		t.Errorf("krb5_groups present for a principal with no groups: %v", u.Attributes)
	}
	if u.Attributes["krb5_realm"] != testRealm {
		t.Errorf("krb5_realm = %q, want %q", u.Attributes["krb5_realm"], testRealm)
	}
}

// TestInactiveClient_NoMint proves an inactive minting client refuses to mint
// (same disposition as /auth/login) — a 403, no tokens, even on a validated
// ticket.
func TestInactiveClient_NoMint(t *testing.T) {
	v := &fakeValidator{principal: "alice", realm: testRealm}
	h := newHarness(t, v, nil)
	// Flip the client inactive.
	c, _ := h.clients.Get(context.Background(), testClientID)
	c.Active = false
	if err := h.clients.Update(context.Background(), c); err != nil {
		t.Fatalf("update client: %v", err)
	}

	rr := doGET(h.handler, negotiateHeader([]byte("ok")))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	assertNoStore(t, rr)
	// No tokens in the (empty) body's access_token.
	var resp map[string]string
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["access_token"] != "" {
		t.Error("access_token minted for an inactive client")
	}
}

// TestBuild_Validation covers Build's required-dep + nil-validator guards.
func TestBuild_Validation(t *testing.T) {
	goodCfg := kerberosauth.Config{
		Name: "kerberos", KeytabBytes: []byte("kt"), ServicePrincipal: testSPN,
		Realm: testRealm, ClientID: testClientID,
	}
	goodDeps := kerberosauth.Deps{
		ClientStore:     defaultimpl.NewMemoryClientStore(),
		SessionManager:  defaultimpl.NewMemorySessionManager(),
		UserProvider:    defaultimpl.NewMemoryUserProvider(),
		IssuerForClient: func(c *sso.Client) (string, sso.TokenIssuer, error) { return "jwt", nil, nil },
	}
	v := &fakeValidator{}

	if _, err := kerberosauth.Build(goodDeps, goodCfg, nil); err == nil {
		t.Error("Build with nil validator should error")
	}

	d := goodDeps
	d.ClientStore = nil
	if _, err := kerberosauth.Build(d, goodCfg, v); err == nil {
		t.Error("Build with nil ClientStore should error")
	}

	d = goodDeps
	d.SessionManager = nil
	if _, err := kerberosauth.Build(d, goodCfg, v); err == nil {
		t.Error("Build with nil SessionManager should error")
	}

	d = goodDeps
	d.UserProvider = nil
	if _, err := kerberosauth.Build(d, goodCfg, v); err == nil {
		t.Error("Build with nil UserProvider should error")
	}

	d = goodDeps
	d.IssuerForClient = nil
	if _, err := kerberosauth.Build(d, goodCfg, v); err == nil {
		t.Error("Build with nil IssuerForClient should error")
	}
}

// ---- audit-side-channel helpers -------------------------------------------

// auditEventsOfType returns every recorded event of the given type. It queries
// the MemorySink (the same Query path the rest of the server uses).
func auditEventsOfType(t *testing.T, h *harness, typ audit.EventType) []*audit.Event {
	t.Helper()
	evs, err := h.auditSink.Query(context.Background(), audit.Query{Type: typ})
	if err != nil {
		t.Fatalf("query audit events: %v", err)
	}
	return evs
}

// assertSecretFreeFailureAudit asserts EXACTLY one login_failure event was
// recorded with Outcome=failure, the provider label, the expected secret-free
// reason, and NO secret material anywhere in it (no ticket, keytab, base64
// token, or gokrb5 internal). wantPrincipalRealm is the qualified principal the
// realm-mismatch path may attach (keytab-validated); "" asserts NO actor/
// identity is attached (the validation-failure path, where there is no proven
// identity). It also asserts NO login_success leaked.
func assertSecretFreeFailureAudit(t *testing.T, h *harness, wantReason, wantPrincipalRealm string, secretsAbsent ...string) {
	t.Helper()
	fails := auditEventsOfType(t, h, audit.EventLoginFailure)
	if len(fails) != 1 {
		t.Fatalf("login_failure events = %d, want exactly 1", len(fails))
	}
	e := fails[0]
	if e.Outcome != audit.OutcomeFailure {
		t.Errorf("failure event Outcome = %q, want failure", e.Outcome)
	}
	if e.Provider != "kerberos" {
		t.Errorf("failure event Provider = %q, want kerberos", e.Provider)
	}
	if e.Reason != wantReason {
		t.Errorf("failure event Reason = %q, want %q", e.Reason, wantReason)
	}
	if e.Metadata["reason"] != wantReason {
		t.Errorf("failure event Metadata[reason] = %q, want %q", e.Metadata["reason"], wantReason)
	}
	if e.Metadata["provider"] != "kerberos" {
		t.Errorf("failure event Metadata[provider] = %q, want kerberos", e.Metadata["provider"])
	}
	if e.ActorID != wantPrincipalRealm {
		t.Errorf("failure event ActorID = %q, want %q", e.ActorID, wantPrincipalRealm)
	}
	// No success event must have leaked on a failure path.
	if succ := auditEventsOfType(t, h, audit.EventLogin); len(succ) != 0 {
		t.Errorf("login_success events = %d on a failure path, want 0", len(succ))
	}
	// The entire serialized event must contain no secret material. The fake
	// validator never sees real secrets, but this guards against a future change
	// that attaches the token/keytab/principal-from-an-unvalidated-token.
	blob := fmt.Sprintf("%+v %+v", *e, e.Metadata)
	for _, secret := range secretsAbsent {
		if secret != "" && strings.Contains(blob, secret) {
			t.Errorf("failure audit event leaked secret-ish value %q: %s", secret, blob)
		}
	}
}

// ---- assertion helpers ----------------------------------------------------

// assertNoMint asserts no user and no session were created (the failure-path
// contract: a rejected/challenged request mints NOTHING).
func assertNoMint(t *testing.T, h *harness) {
	t.Helper()
	users, err := h.users.List(context.Background())
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if len(users) != 0 {
		t.Errorf("expected no users minted, got %d", len(users))
	}
	sessions, err := h.sessions.ListAll(context.Background())
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(sessions) != 0 {
		t.Errorf("expected no sessions created, got %d", len(sessions))
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
