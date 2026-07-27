package saml_test

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	crewjam "github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	samlmod "github.com/yangwb1123/snaplink/saml"
	"github.com/yangwb1123/snaplink/saml/idp"
	"github.com/yangwb1123/snaplink/saml/sp"
)

const (
	idpSLOURL = "https://idp.example.com/saml/slo"
	spSLOURL  = "https://sp.example.com/auth/saml/slo"
)

// buildSLOServer wires saml.Build with one cert-pinned SP that ALSO carries an
// SP signing key + the SP/IdP SLO URLs, returning the mounted SP-SLO handler +
// the session manager + the IdP keypair (whose cert is pinned, so it signs the
// IdP-initiated LogoutRequest).
func buildSLOServer(t *testing.T) (http.HandlerFunc, sso.SessionManager, *idpKey) {
	t.Helper()
	idp := newIDPKey(t)
	spKeyPEM, spCertPEM := newSPSLOKey(t)
	sessions := defaultimpl.NewMemorySessionManager()

	res, err := samlmod.Build(samlmod.Deps{
		SessionManager: sessions,
		UserProvider:   defaultimpl.NewMemoryUserProvider(),
		ClientStore:    defaultimpl.NewMemoryClientStore(),
	}, samlmod.Config{
		SPs: []sp.SPConfig{{
			Name:         "test-idp",
			EntityID:     spEntity,
			ACSURL:       acsURL,
			IDPCert:      idp.certPEM(),
			IDPEntityID:  idpEntity,
			SPPrivateKey: spKeyPEM,
			SPCert:       spCertPEM,
			SPSLOURL:     spSLOURL,
			IDPSLOURL:    idpSLOURL,
		}},
	})
	if err != nil {
		t.Fatalf("saml.Build: %v", err)
	}

	// The SP SLO handler is identical for GET+POST (the serve method switches on
	// method internally); grab the GET one — the tests exercise the HTTP-Redirect
	// binding the IdP uses for SLO (DEFLATEd SAMLRequest).
	var slo *samlmod.HandlerSpec
	for i := range res.Handlers {
		h := &res.Handlers[i]
		if h.Path == sso.PathSAMLSPSLO && h.Method == http.MethodGet {
			slo = h
		}
	}
	if slo == nil {
		t.Fatalf("Build mounted no GET %s handler", sso.PathSAMLSPSLO)
	}
	return slo.Handler, sessions, idp
}

// TestSPSLO_EndToEnd_SignedRequest_TerminatesLocalSession proves the wired SP
// SLO handler terminates the LOCAL session for the IdP-initiated LogoutRequest's
// subject (asserted gone via the real Memory SessionManager) and returns a 302
// signed LogoutResponse redirect to the IdP.
func TestSPSLO_EndToEnd_SignedRequest_TerminatesLocalSession(t *testing.T) {
	t.Parallel()
	handler, sessions, idp := buildSLOServer(t)

	const nameID = "alice@example.com"
	sess, err := sessions.Create(context.Background(), nameID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	q := mintLogoutRedirectQuery(t, idp, idpEntity, nameID, "", spSLOURL, "rs")
	rec := postSPSLO(handler, q)

	// no-store on every SLO path.
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}

	// The LOCAL session is GONE.
	if s, err := sessions.Get(context.Background(), sess.ID); err == nil && s != nil {
		t.Fatalf("local session %q should be terminated by IdP-initiated SLO", sess.ID)
	}

	// The 302 Location is a signed LogoutResponse redirect to the IdP SLO.
	loc := rec.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if u.Scheme+"://"+u.Host+u.Path != idpSLOURL {
		t.Errorf("Location = %q, want a redirect to %q", loc, idpSLOURL)
	}
	if u.Query().Get("SAMLResponse") == "" {
		t.Errorf("Location missing SAMLResponse: %q", loc)
	}
}

// TestSPSLO_EndToEnd_UnsignedRequest_NoTermination is the wired-path crux: an
// UNSIGNED IdP LogoutRequest is rejected and the local session SURVIVES.
func TestSPSLO_EndToEnd_UnsignedRequest_NoTermination(t *testing.T) {
	t.Parallel()
	handler, sessions, _ := buildSLOServer(t)

	const nameID = "bob@example.com"
	sess, err := sessions.Create(context.Background(), nameID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	q := mintLogoutRedirectQuery(t, nil, idpEntity, nameID, "", spSLOURL, "") // unsigned
	rec := postSPSLO(handler, q)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for unsigned logout; body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body[sso.KeyError] != sso.ErrSAMLRequestInvalid {
		t.Errorf("error = %q, want %q", body[sso.KeyError], sso.ErrSAMLRequestInvalid)
	}
	// The session MUST survive an unsigned logout.
	if _, err := sessions.Get(context.Background(), sess.ID); err != nil {
		t.Fatalf("local session %q terminated by an UNSIGNED logout (security violation): %v", sess.ID, err)
	}
}

// TestSPSLO_EndToEnd_OnlySubjectTerminated proves the wired handler scopes
// termination to the request's subject — a second subject's session is
// untouched.
func TestSPSLO_EndToEnd_OnlySubjectTerminated(t *testing.T) {
	t.Parallel()
	handler, sessions, idp := buildSLOServer(t)

	target, err := sessions.Create(context.Background(), "carol@example.com")
	if err != nil {
		t.Fatalf("create target session: %v", err)
	}
	other, err := sessions.Create(context.Background(), "dave@example.com")
	if err != nil {
		t.Fatalf("create other session: %v", err)
	}

	q := mintLogoutRedirectQuery(t, idp, idpEntity, "carol@example.com", "", spSLOURL, "")
	if rec := postSPSLO(handler, q); rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}

	if _, err := sessions.Get(context.Background(), target.ID); err == nil {
		t.Fatalf("target session %q should be terminated", target.ID)
	}
	if _, err := sessions.Get(context.Background(), other.ID); err != nil {
		t.Fatalf("unrelated session %q terminated (global-wipe bug): %v", other.ID, err)
	}
}

// TestBuild_MountsFrontChannelContinueRoute proves saml.Build mounts the IdP
// front-channel chain RESUME endpoint (GET /saml/slo/continue) when the IdP is
// enabled — the route the browser-redirect chain resumes on.
func TestBuild_MountsFrontChannelContinueRoute(t *testing.T) {
	t.Parallel()
	res, err := samlmod.Build(samlmod.Deps{
		SessionManager:  defaultimpl.NewMemorySessionManager(),
		UserProvider:    defaultimpl.NewMemoryUserProvider(),
		ClientStore:     defaultimpl.NewMemoryClientStore(),
		IssuerForClient: func(*sso.Client) (string, sso.TokenIssuer, error) { return "t", nil, nil },
		Issuer:          asIssuer,
	}, samlmod.Config{
		IdP: samlmod.IdPConfig{Enabled: true},
	})
	if err != nil {
		t.Fatalf("saml.Build: %v", err)
	}
	found := false
	for i := range res.Handlers {
		h := &res.Handlers[i]
		if h.Path == sso.PathSAMLSLOContinue && h.Method == http.MethodGet {
			found = true
			if h.Handler == nil {
				t.Fatalf("GET %s mounted with a nil handler", sso.PathSAMLSLOContinue)
			}
		}
	}
	if !found {
		t.Fatalf("Build did not mount GET %s (front-channel chain resume)", sso.PathSAMLSLOContinue)
	}
}

// TestSPSLO_FrontChannel_RedirectsResponseToContinue is the wired SP-side
// front-channel proof: an SP configured with IDPSLOResponseURL = the IdP's
// /saml/slo/continue endpoint, on receiving a front-channel (redirect) IdP
// LogoutRequest, terminates the LOCAL session and 302s its signed LogoutResponse
// to the CONTINUE endpoint (not the request endpoint), echoing the chain-state
// RelayState so the IdP can resume.
func TestSPSLO_FrontChannel_RedirectsResponseToContinue(t *testing.T) {
	t.Parallel()
	idpKp := newIDPKey(t)
	spKeyPEM, spCertPEM := newSPSLOKey(t)
	sessions := defaultimpl.NewMemorySessionManager()
	const idpContinueURL = "https://idp.example.com/saml/slo/continue"

	res, err := samlmod.Build(samlmod.Deps{
		SessionManager: sessions,
		UserProvider:   defaultimpl.NewMemoryUserProvider(),
		ClientStore:    defaultimpl.NewMemoryClientStore(),
	}, samlmod.Config{
		SPs: []sp.SPConfig{{
			Name:              "test-idp",
			EntityID:          spEntity,
			ACSURL:            acsURL,
			IDPCert:           idpKp.certPEM(),
			IDPEntityID:       idpEntity,
			SPPrivateKey:      spKeyPEM,
			SPCert:            spCertPEM,
			SPSLOURL:          spSLOURL,
			IDPSLOURL:         idpSLOURL,
			IDPSLOResponseURL: idpContinueURL,
		}},
	})
	if err != nil {
		t.Fatalf("saml.Build: %v", err)
	}
	var slo *samlmod.HandlerSpec
	for i := range res.Handlers {
		h := &res.Handlers[i]
		if h.Path == sso.PathSAMLSPSLO && h.Method == http.MethodGet {
			slo = h
		}
	}
	if slo == nil {
		t.Fatalf("Build mounted no GET %s handler", sso.PathSAMLSPSLO)
	}

	const nameID = "fc@example.com"
	const chainState = "chain-state-abc"
	sess, err := sessions.Create(context.Background(), nameID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// The IdP redirected the browser here with a signed front-channel LogoutRequest
	// carrying the chain-state id as RelayState.
	q := mintLogoutRedirectQuery(t, idpKp, idpEntity, nameID, "", spSLOURL, chainState)
	rec := postSPSLO(slo.Handler, q)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}
	// The local session is GONE.
	if s, err := sessions.Get(context.Background(), sess.ID); err == nil && s != nil {
		t.Fatalf("local session %q should be terminated by the front-channel logout", sess.ID)
	}
	// The 302 LogoutResponse goes to the IdP's CONTINUE endpoint with the ECHOED
	// chain-state RelayState (so the IdP resumes the chain).
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if got := u.Scheme + "://" + u.Host + u.Path; got != idpContinueURL {
		t.Fatalf("front-channel response target = %q, want the continue endpoint %q", got, idpContinueURL)
	}
	if rs := u.Query().Get("RelayState"); rs != chainState {
		t.Errorf("response RelayState = %q, want the echoed chain id %q", rs, chainState)
	}
	if u.Query().Get("SAMLResponse") == "" || u.Query().Get("Signature") == "" {
		t.Errorf("front-channel LogoutResponse missing SAMLResponse/Signature: %q", u.RawQuery)
	}
}

// twoIdPEntityIDs are two DISTINCT upstream-IdP entity ids for the
// multi-SPConfig SP-side SLO dispatch tests (each SPConfig pins a different IdP).
const (
	idpAEntity = "https://idp-a.example.com"
	idpBEntity = "https://idp-b.example.com"
)

// buildMultiSPSLOServer wires saml.Build with TWO cert-pinned SPConfigs — one per
// upstream IdP (idp-A, idp-B), each with its OWN distinct pinned cert + entity id
// + front-channel continue endpoint. It returns the mounted SP-SLO GET handler,
// the shared session manager, and both IdP keypairs. This is the fixture for the
// Issuer-based dispatch tests: with two SPConfigs the RelayState (a chain-state id)
// carries no provider hint, so dispatch must select by the LogoutRequest Issuer.
func buildMultiSPSLOServer(t *testing.T) (http.HandlerFunc, sso.SessionManager, *idpKey, *idpKey) {
	t.Helper()
	idpA := newIDPKey(t)
	idpB := newIDPKey(t)
	spKeyPEM, spCertPEM := newSPSLOKey(t)
	sessions := defaultimpl.NewMemorySessionManager()

	res, err := samlmod.Build(samlmod.Deps{
		SessionManager: sessions,
		UserProvider:   defaultimpl.NewMemoryUserProvider(),
		ClientStore:    defaultimpl.NewMemoryClientStore(),
	}, samlmod.Config{
		SPs: []sp.SPConfig{
			{
				Name:              "idp-a",
				EntityID:          spEntity,
				ACSURL:            acsURL,
				IDPCert:           idpA.certPEM(),
				IDPEntityID:       idpAEntity,
				SPPrivateKey:      spKeyPEM,
				SPCert:            spCertPEM,
				SPSLOURL:          spSLOURL,
				IDPSLOURL:         "https://idp-a.example.com/saml/slo",
				IDPSLOResponseURL: "https://idp-a.example.com/saml/slo/continue",
			},
			{
				Name:              "idp-b",
				EntityID:          spEntity,
				ACSURL:            acsURL,
				IDPCert:           idpB.certPEM(),
				IDPEntityID:       idpBEntity,
				SPPrivateKey:      spKeyPEM,
				SPCert:            spCertPEM,
				SPSLOURL:          spSLOURL,
				IDPSLOURL:         "https://idp-b.example.com/saml/slo",
				IDPSLOResponseURL: "https://idp-b.example.com/saml/slo/continue",
			},
		},
	})
	if err != nil {
		t.Fatalf("saml.Build (multi-SP): %v", err)
	}
	return findHandler(t, res, http.MethodGet, sso.PathSAMLSPSLO), sessions, idpA, idpB
}

// TestSPSLO_MultiSP_FrontChannel_DispatchesByIssuer is the FIX-1 proof: an SP with
// TWO SPConfigs receives a FRONT-channel LogoutRequest whose RelayState is the
// IdP's unguessable chain-state id (NO provider hint). It is dispatched to the
// idp-A authenticator BY ITS ISSUER, the idp-A signature validates, the LOCAL
// session is terminated, and the LogoutResponse 302s back to idp-A's CONTINUE
// endpoint with the chain-state RelayState ECHOED verbatim (so the IdP chain
// resumes). Under the old RelayState-name dispatch this would 400 and silently
// leave the session alive.
func TestSPSLO_MultiSP_FrontChannel_DispatchesByIssuer(t *testing.T) {
	t.Parallel()
	handler, sessions, idpA, _ := buildMultiSPSLOServer(t)

	const nameID = "multi-a@example.com"
	const chainState = "unguessable-chain-state-id-A"
	sess, err := sessions.Create(context.Background(), nameID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Front-channel LogoutRequest issued by idp-A (Issuer = idpAEntity), signed by
	// idp-A's key, carrying the chain-state id as RelayState (no provider hint).
	q := mintLogoutRedirectQuery(t, idpA, idpAEntity, nameID, "", spSLOURL, chainState)
	rec := postSPSLO(handler, q)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 (Issuer-dispatched + terminated); body=%s", rec.Code, rec.Body.String())
	}
	// The LOCAL session is GONE — the logout actually terminated it.
	if s, err := sessions.Get(context.Background(), sess.ID); err == nil && s != nil {
		t.Fatalf("local session %q should be terminated by the front-channel logout dispatched by Issuer", sess.ID)
	}
	// The 302 LogoutResponse goes to idp-A's CONTINUE endpoint (proving the idp-A
	// authenticator handled it) with the chain-state RelayState echoed verbatim.
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if got := u.Scheme + "://" + u.Host + u.Path; got != "https://idp-a.example.com/saml/slo/continue" {
		t.Fatalf("response target = %q, want idp-A's continue endpoint (Issuer-dispatched)", got)
	}
	if rs := u.Query().Get("RelayState"); rs != chainState {
		t.Errorf("response RelayState = %q, want the echoed chain id %q", rs, chainState)
	}
}

// TestSPSLO_MultiSP_IssuerSaysBSignedByA_Rejected proves the Issuer is a LOOKUP
// KEY ONLY, not a trust bypass: a LogoutRequest whose Issuer names idp-B (so the
// dispatcher selects the idp-B authenticator) but is SIGNED by idp-A's key is
// REJECTED — idp-B's pinned cert can't validate idp-A's signature. The session
// SURVIVES. This is the security crux of dispatching by an unverified Issuer.
func TestSPSLO_MultiSP_IssuerSaysBSignedByA_Rejected(t *testing.T) {
	t.Parallel()
	handler, sessions, idpA, _ := buildMultiSPSLOServer(t)

	const nameID = "multi-mismatch@example.com"
	sess, err := sessions.Create(context.Background(), nameID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Issuer = idp-B (selects the idp-B authenticator) but SIGNED with idp-A's key.
	q := mintLogoutRedirectQuery(t, idpA, idpBEntity, nameID, "", spSLOURL, "chain-state-mismatch")
	rec := postSPSLO(handler, q)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (Issuer-selected idp-B cert must not validate idp-A's signature); body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body[sso.KeyError] != sso.ErrSAMLRequestInvalid {
		t.Errorf("error = %q, want %q", body[sso.KeyError], sso.ErrSAMLRequestInvalid)
	}
	// The session MUST survive: the Issuer chose a trust anchor whose cert rejects
	// the signature, so no trust was bypassed.
	if _, err := sessions.Get(context.Background(), sess.ID); err != nil {
		t.Fatalf("session %q terminated despite an Issuer/key mismatch (trust-bypass via forged Issuer): %v", sess.ID, err)
	}
}

// TestSPSLO_MultiSP_UnknownIssuer_Rejected: a LogoutRequest whose Issuer matches
// NO configured upstream IdP yields 400 saml_request_invalid (oracle-safe, same
// as a single-SP unknown request).
func TestSPSLO_MultiSP_UnknownIssuer_Rejected(t *testing.T) {
	t.Parallel()
	handler, sessions, idpA, _ := buildMultiSPSLOServer(t)

	const nameID = "multi-unknown@example.com"
	sess, err := sessions.Create(context.Background(), nameID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Issuer names an entity the SP pins for NEITHER SPConfig (signed by idp-A so
	// the only failure under test is the unknown-Issuer dispatch miss).
	q := mintLogoutRedirectQuery(t, idpA, "https://unknown-idp.example.com", nameID, "", spSLOURL, "rs")
	rec := postSPSLO(handler, q)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unknown Issuer; body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body[sso.KeyError] != sso.ErrSAMLRequestInvalid {
		t.Errorf("error = %q, want %q", body[sso.KeyError], sso.ErrSAMLRequestInvalid)
	}
	if _, err := sessions.Get(context.Background(), sess.ID); err != nil {
		t.Fatalf("session %q terminated by an unknown-Issuer logout: %v", sess.ID, err)
	}
}

// TestSPSLO_SingleSP_DispatchUnchanged proves the single-SPConfig fast path is
// unchanged: with exactly one authenticator the inbound LogoutRequest is handled
// directly (no Issuer lookup needed), terminating the session — byte-identical to
// the prior behavior. (buildSLOServer wires exactly one SP.)
func TestSPSLO_SingleSP_DispatchUnchanged(t *testing.T) {
	t.Parallel()
	handler, sessions, idp := buildSLOServer(t)

	const nameID = "single-sp@example.com"
	sess, err := sessions.Create(context.Background(), nameID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	// RelayState is an opaque chain-state id with no provider hint — the single-SP
	// path must still work without any Issuer lookup.
	q := mintLogoutRedirectQuery(t, idp, idpEntity, nameID, "", spSLOURL, "opaque-chain-state")
	rec := postSPSLO(handler, q)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302 (single-SP fast path); body=%s", rec.Code, rec.Body.String())
	}
	if s, err := sessions.Get(context.Background(), sess.ID); err == nil && s != nil {
		t.Fatalf("single-SP local session %q should be terminated", sess.ID)
	}
}

// TestSLO_SPtoIdPtoSP_RoundTrip is the full snaplink SP→IdP→SP interop proof on
// the NEW detached §3.4.4.1 format: the repo's OWN SP side builds a SP-initiated
// LogoutRequest redirect (detached-signed with the SP key), the repo's OWN IdP
// side (pinned to that SP's cert) validates it, terminates the session, and
// returns a detached-signed LogoutResponse redirect whose signature verifies
// against the IdP's signing cert the SP pinned. Both halves speak §3.4.4.1.
func TestSLO_SPtoIdPtoSP_RoundTrip(t *testing.T) {
	t.Parallel()
	const nameID = "roundtrip@example.com"
	idpEntityID := asIssuer + "/saml"
	idpSLOURL := asIssuer + sso.PathSAMLSLO

	issuer, _ := newRSAIssuer(t)
	clients := defaultimpl.NewMemoryClientStore()
	sessions := defaultimpl.NewMemorySessionManager()

	// The IdP's signing cert (wraps the issuer key) — what the SP pins as its IdP
	// trust anchor. The detached signature verifies against the key, so a cert
	// built independently over the same key validates the handler's signature.
	idpCert := idpSigningCert(t, issuer, idpEntityID)

	// The SP's signing material (the IdP pins its cert to authenticate the SP's
	// LogoutRequest).
	spKeyPEM, spCertPEM := newSPSLOKey(t)

	// Register the SP at the IdP WITH its signing cert + SLO URL.
	if err := clients.Add(context.Background(), &sso.Client{
		ID:     "rt-sp",
		Active: true,
		Attributes: map[string]string{
			idp.AttrSPEntityID:    spEntity,
			idp.AttrSPACSURLs:     acsURL,
			idp.AttrSPSigningCert: string(spCertPEM),
			idp.AttrSPSLOUrls:     spSLOURL,
		},
	}); err != nil {
		t.Fatalf("register SP: %v", err)
	}

	res, err := samlmod.Build(samlmod.Deps{
		ClientStore:     clients,
		SessionManager:  sessions,
		UserProvider:    defaultimpl.NewMemoryUserProvider(),
		IssuerForClient: func(*sso.Client) (string, sso.TokenIssuer, error) { return "t", issuer, nil },
		Issuer:          asIssuer,
	}, samlmod.Config{IdP: samlmod.IdPConfig{Enabled: true}})
	if err != nil {
		t.Fatalf("saml.Build: %v", err)
	}
	idpSLO := findHandler(t, res, http.MethodGet, sso.PathSAMLSLO)

	// The SP, pinned to the IdP cert + entity id, with the IdP SLO URL.
	spAuth, err := sp.NewSPAuthenticator(sp.SPConfig{
		Name:         "rt-idp",
		EntityID:     spEntity,
		ACSURL:       acsURL,
		IDPCert:      pemCert(idpCert),
		IDPEntityID:  idpEntityID,
		SPPrivateKey: spKeyPEM,
		SPCert:       spCertPEM,
		SPSLOURL:     spSLOURL,
		IDPSLOURL:    idpSLOURL,
	})
	if err != nil {
		t.Fatalf("NewSPAuthenticator: %v", err)
	}

	// A live session for the subject at the IdP.
	sess, err := sessions.Create(context.Background(), nameID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// SP builds the SP-initiated LogoutRequest redirect (detached-signed).
	logoutURL := spAuth.LogoutURL(nameID, "", "rs-roundtrip")
	if logoutURL == "" {
		t.Fatal("SP LogoutURL returned empty")
	}
	lu, err := url.Parse(logoutURL)
	if err != nil {
		t.Fatalf("parse LogoutURL: %v", err)
	}
	if lu.Scheme+"://"+lu.Host+lu.Path != idpSLOURL {
		t.Fatalf("SP LogoutURL points at %q, want IdP SLO %q", lu.Scheme+"://"+lu.Host+lu.Path, idpSLOURL)
	}

	// Drive the IdP's /saml/slo with the SP's exact raw query (detached sig).
	req := httptest.NewRequest(http.MethodGet, idpSLOURL+"?"+lu.RawQuery, nil)
	rec := httptest.NewRecorder()
	idpSLO(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("IdP SLO status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}
	// The IdP terminated the session.
	if _, err := sessions.Get(context.Background(), sess.ID); err == nil {
		t.Fatalf("session %q should be terminated by the SP-initiated SLO", sess.ID)
	}
	// The IdP's LogoutResponse redirect goes back to the SP's registered SLO URL
	// and its detached signature verifies against the IdP cert the SP pinned.
	resp, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse IdP response Location: %v", err)
	}
	if resp.Scheme+"://"+resp.Host+resp.Path != spSLOURL {
		t.Fatalf("IdP LogoutResponse redirect points at %q, want SP SLO %q", resp.Scheme+"://"+resp.Host+resp.Path, spSLOURL)
	}
	verifyDetachedAgainstCert(t, resp.RawQuery, "SAMLResponse", idpCert)
}

// --- helpers ---

// findHandler returns the mounted handler for the given method+path.
func findHandler(t *testing.T, res *samlmod.BuildResult, method, path string) http.HandlerFunc {
	t.Helper()
	for i := range res.Handlers {
		h := &res.Handlers[i]
		if h.Path == path && h.Method == method {
			return h.Handler
		}
	}
	t.Fatalf("Build mounted no %s %s handler", method, path)
	return nil
}

// idpSigningCert builds the IdP signing cert that wraps the issuer's key (the
// trust anchor a downstream SP pins). It resolves the issuer's CryptoSigner the
// same way the IdP handler does, then mints the self-signed cert via the
// exported AssertionSigner — the detached signature verifies against the key, so
// this independently-built cert validates the handler's LogoutResponse.
func idpSigningCert(t *testing.T, issuer sso.TokenIssuer, idpEntityID string) *x509.Certificate {
	t.Helper()
	cs, ok := issuer.(interface {
		CryptoSigner() (crypto.Signer, crypto.PublicKey, string)
	})
	if !ok {
		t.Fatalf("issuer does not expose CryptoSigner")
	}
	signer, pub, kid := cs.CryptoSigner()
	as, err := idp.NewAssertionSigner(signer, pub, kid, idpEntityID)
	if err != nil {
		t.Fatalf("NewAssertionSigner: %v", err)
	}
	cert, err := as.Certificate()
	if err != nil {
		t.Fatalf("AssertionSigner cert: %v", err)
	}
	return cert
}

// pemCert PEM-encodes a certificate (for SPConfig.IDPCert).
func pemCert(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// verifyDetachedAgainstCert verifies a DETACHED §3.4.4.1 signature in rawQuery
// (param = "SAMLResponse"/"SAMLRequest") against cert via x509.CheckSignature —
// the same primitive each side's verifier uses. Asserts the signature is present
// and valid (and that a missing Signature fails).
func verifyDetachedAgainstCert(t *testing.T, rawQuery, param string, cert *x509.Certificate) {
	t.Helper()
	vals, _ := url.ParseQuery(rawQuery)
	sigB64 := vals.Get("Signature")
	sigAlg := vals.Get("SigAlg")
	if sigB64 == "" || sigAlg == "" {
		t.Fatalf("detached signature missing (SigAlg=%q Signature present=%v)", sigAlg, sigB64 != "")
	}
	if sigAlg != "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" {
		t.Fatalf("unexpected SigAlg %q", sigAlg)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("decode Signature: %v", err)
	}
	// Reconstruct the signed octet string from the RAW values in §3.4.4.1 order.
	octet := param + "=" + rawRedirectVal(rawQuery, param)
	if rs, ok := rawRedirectValOK(rawQuery, "RelayState"); ok {
		octet += "&RelayState=" + rs
	}
	octet += "&SigAlg=" + rawRedirectVal(rawQuery, "SigAlg")
	if err := cert.CheckSignature(x509.SHA256WithRSA, []byte(octet), sig); err != nil {
		t.Fatalf("detached %s signature did not verify against the pinned IdP cert: %v", param, err)
	}
}

// rawRedirectVal / rawRedirectValOK extract a RAW (still-encoded) query value.
func rawRedirectVal(rawQuery, key string) string {
	v, _ := rawRedirectValOK(rawQuery, key)
	return v
}

func rawRedirectValOK(rawQuery, key string) (string, bool) {
	for _, pair := range strings.Split(rawQuery, "&") {
		if pair == "" {
			continue
		}
		name := pair
		val := ""
		if i := strings.IndexByte(pair, '='); i >= 0 {
			name, val = pair[:i], pair[i+1:]
		}
		if name == key {
			return val, true
		}
	}
	return "", false
}

// postSPSLO drives the SP SLO handler over the HTTP-Redirect binding (GET) using
// a FULL raw query string (so the detached §3.4.4.1 signature survives
// byte-for-byte — re-encoding via url.Values would break it), matching what a
// real IdP sends for SLO.
func postSPSLO(handler http.HandlerFunc, rawQuery string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, spSLOURL+"?"+rawQuery, nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

// newSPSLOKey returns a fresh RSA key + self-signed cert PEM-encoded for the SP
// signing material (SLO signing).
func newSPSLOKey(t *testing.T) (keyPEM, certPEM []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen SP key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "sp-slo-signer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create SP cert: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return keyPEM, certPEM
}

// mintLogoutRedirectQuery builds an IdP-initiated LogoutRequest for nameID and,
// when signer != nil, signs it with the SAML-standard DETACHED §3.4.4.1
// redirect-binding signature (UNSIGNED XML body + SigAlg+Signature query params
// over the URL-encoded octet string) using the IdP key (the cert the SP pins) —
// exactly what a real IdP sends. Returns the FULL raw query string. An unsigned
// request (signer == nil) carries no SigAlg/Signature.
func mintLogoutRedirectQuery(t *testing.T, signer *idpKey, issuer, nameID, sessionIndex, dest, relayState string) string {
	t.Helper()
	req := &crewjam.LogoutRequest{
		ID:           "id-lo-" + randHex(),
		Version:      "2.0",
		IssueInstant: time.Now(),
		Destination:  dest,
		Issuer:       &crewjam.Issuer{Value: issuer},
		NameID:       &crewjam.NameID{Value: nameID},
	}
	if sessionIndex != "" {
		req.SessionIndex = &crewjam.SessionIndex{Value: sessionIndex}
	}
	doc := etree.NewDocument()
	doc.SetRoot(req.Element())
	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize logout request: %v", err)
	}
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	_, _ = fw.Write(raw)
	_ = fw.Close()
	samlReq := base64.StdEncoding.EncodeToString(buf.Bytes())

	query := "SAMLRequest=" + url.QueryEscape(samlReq)
	if relayState != "" {
		query += "&RelayState=" + url.QueryEscape(relayState)
	}
	if signer == nil {
		return query
	}
	const rsaSHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	query += "&SigAlg=" + url.QueryEscape(rsaSHA256)
	ctx, err := dsig.NewSigningContext(signer.key, [][]byte{signer.cert.Raw})
	if err != nil {
		t.Fatalf("signing context: %v", err)
	}
	if err := ctx.SetSignatureMethod(rsaSHA256); err != nil {
		t.Fatalf("set sig method: %v", err)
	}
	sig, err := ctx.SignString(query)
	if err != nil {
		t.Fatalf("sign detached: %v", err)
	}
	query += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	return query
}
