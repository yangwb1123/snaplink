package idp

import (
	"crypto"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/spi"
)

// Well-known sso.Client.Attributes keys that register a downstream SP with this
// IdP. They are SERVER-SIDE config (set by the operator on the client record),
// never request input — the same pattern CAEP uses for caep_receiver_endpoint.
const (
	// AttrSPEntityID is the SP's SAML entity identifier (the AuthnRequest
	// Issuer). The SSO handler resolves the SP client by matching this. A
	// client WITHOUT it is not a SAML SP and is skipped during resolution.
	AttrSPEntityID = "saml_sp_entity_id"

	// AttrSPACSURLs is the pipe-delimited ALLOWLIST of this SP's registered
	// Assertion Consumer Service URLs. The AuthnRequest's ACS URL MUST be in
	// this list (assertion-exfiltration defense); the assertion is POSTed only
	// to the matched, registered URL — never a response-supplied one. REQUIRED
	// for a SAML SP.
	AttrSPACSURLs = "saml_sp_acs_urls"

	// AttrSPRequireSignedRequest, when "true", requires the inbound
	// AuthnRequest to carry a valid XML-DSig signature verified against
	// AttrSPSigningCert. Default (absent/"false") accepts unsigned requests
	// (TLS-protected, the common case).
	AttrSPRequireSignedRequest = "saml_sp_require_signed_request"

	// AttrSPSigningCert is the SP's PEM X.509 certificate used to verify a
	// signed AuthnRequest (only consulted when AttrSPRequireSignedRequest is
	// "true").
	AttrSPSigningCert = "saml_sp_signing_cert"

	// AttrSPNameIDFormat overrides the NameID format stamped into assertions
	// for this SP (e.g. emailAddress / persistent). Empty = the IdP default
	// (emailAddress).
	AttrSPNameIDFormat = "saml_sp_nameid_format"

	// AttrSPSLOUrls is the pipe-delimited ALLOWLIST of this SP's registered
	// Single Logout Service URLs. A LogoutResponse the IdP sends back after a
	// SP-initiated SLO goes ONLY to a URL in this list — never a
	// request-supplied one (logout-response-injection defense, the SLO analogue
	// of AttrSPACSURLs). It is ALSO the fan-out destination: an SP-initiated
	// global logout pushes a signed LogoutRequest ONLY to a URL in this list. An
	// SP that wants to RECEIVE a LogoutResponse or a fan-out LogoutRequest MUST
	// register at least one; absent ⇒ the IdP can validate + terminate but has
	// nowhere to send the response (it returns 200 with no response — the
	// session is still killed) and the SP is skipped in the fan-out.
	AttrSPSLOUrls = "saml_sp_slo_url"

	// AttrSPSLOBinding selects the SAML binding the SLO fan-out delivers this
	// SP's LogoutRequest over: "redirect" (HTTP-Redirect, a GET with a detached
	// §3.4.4.1 signature — the default, and what saml/sp validates by default) or
	// "post" (HTTP-POST, an enveloped-XML-DSig LogoutRequest form). Absent/unknown
	// ⇒ redirect. It governs ONLY the outbound fan-out WIRE binding; the inbound
	// SP-initiated /saml/slo receiver accepts BOTH bindings regardless.
	AttrSPSLOBinding = "saml_sp_slo_binding"

	// AttrSPSLOChannel selects WHICH SLO mode an SP participates in:
	//
	//   "backchannel" (default, back-compat) — the IdP POSTs/GETs the
	//                  LogoutRequest to the SP's SLO URL DIRECTLY (server-to-server,
	//                  async fan-out). Requires the SP be reachable from the IdP.
	//   "frontchannel" — the IdP redirects the USER'S BROWSER sequentially through
	//                  each such SP's SLO endpoint (the traditional SAML SLO mode
	//                  for SPs NOT reachable from the IdP). Driven by the
	//                  single-use logout-chain state machine (frontchannel_slo.go).
	//
	// WHY a SEPARATE key from AttrSPSLOBinding: AttrSPSLOBinding already selects the
	// WIRE binding (redirect|post) for the back-channel fan-out, a shipped + reviewed
	// dimension; CHANNEL (front vs back) is ORTHOGONAL to it (a back-channel SP can
	// be redirect OR post). Overloading saml_sp_slo_binding with frontchannel|
	// backchannel would collide with that reviewed semantics, so the channel gets
	// its own key. Front-channel always uses the HTTP-Redirect binding (the only one
	// a browser-redirect chain can carry), so AttrSPSLOBinding does not apply to it.
	// Absent/unknown ⇒ backchannel (byte-identical to the pre-front-channel
	// behavior: every SP fans out async, no chain).
	AttrSPSLOChannel = "saml_sp_slo_channel"
)

// SLO channel identifiers for AttrSPSLOChannel.
const (
	// ChannelBackchannel is the direct server-to-server fan-out (the default).
	ChannelBackchannel = "backchannel"
	// ChannelFrontchannel is the browser-redirect SLO chain.
	ChannelFrontchannel = "frontchannel"
)

// acsURLDelimiter separates registered ACS URLs in AttrSPACSURLs.
const acsURLDelimiter = "|"

// cryptoSignerIssuer is the structural interface a per-tenant sso.TokenIssuer
// must satisfy to lend its signing key for XML-DSig — the Phase A CryptoSigner
// seam on defaultimpl's issuers. The IdP type-asserts the TokenIssuer that
// deps.IssuerForClient returns to this; a non-conforming issuer (can't expose a
// stdlib crypto.Signer) yields a fail-closed saml_assertion_failed, never a
// fallback to another key.
type cryptoSignerIssuer interface {
	CryptoSigner() (crypto.Signer, crypto.PublicKey, string)
}

// Deps is the IdP handlers' dependency bundle. Every field is a stdlib /
// root-module / spi type (no cmd package-main type — the saml/ module can't
// import main). saml.Build constructs it from saml.Deps.
type Deps struct {
	// ClientStore is iterated to resolve the SP client by its registered
	// saml_sp_entity_id (the AuthnRequest Issuer). REQUIRED.
	ClientStore sso.ClientStore

	// SessionManager validates the live login session at /saml/sso/finish (an
	// invalid/expired/revoked session collapses to saml_request_invalid).
	// REQUIRED.
	SessionManager sso.SessionManager

	// UserProvider loads the authenticated user whose attributes populate the
	// assertion. REQUIRED.
	UserProvider sso.UserProvider

	// IssuerForClient is the server's per-tenant signing-issuer selector. The
	// IdP resolves the SP client's issuer through it and borrows the signing
	// key via CryptoSigner() — so the assertion is signed with the SAME
	// per-tenant key published in that tenant's metadata. REQUIRED (the IdP
	// cannot sign without it).
	IssuerForClient func(c *sso.Client) (string, sso.TokenIssuer, error)

	// Issuer is the AS issuer URL. The IdP entity ID is Issuer + "/saml"; it is
	// the assertion Issuer + the NameQualifier + the metadata EntityID.
	// REQUIRED.
	Issuer string

	// LoginPath is where /saml/sso redirects the user-agent to authenticate
	// (with ?client_id=<sp>&state=<saml_request_id>). Empty ⇒ "/auth/login".
	LoginPath string

	// SSOURL is the absolute public URL of the /saml/sso endpoint, published as
	// the metadata SingleSignOnService Location. Empty ⇒ Issuer + PathSAMLSSO.
	SSOURL string

	// MetadataTTL is the Cache-Control max-age on /saml/metadata. <=0 ⇒ 1h.
	MetadataTTL time.Duration

	// SignMetadata opts the /saml/metadata EntityDescriptor into an enveloped
	// XML-DSig (exclusive C14N, SHA-256) produced through the resolved per-tenant
	// AssertionSigner — the SAME key + path that signs assertions, so a consumer
	// doing automated metadata refresh (Shibboleth federations, strict SPs)
	// validates the metadata signature against the cert in this document's OWN
	// KeyDescriptor (no extra trust anchor). Default false ⇒ the metadata is
	// UNSIGNED and byte-identical to the historical output. An Ed25519 issuer
	// (goxmldsig has no EdDSA signature method) gracefully falls back to UNSIGNED
	// metadata + a log, never a 500 — mirroring that the assertion path simply
	// cannot use such a key, but the metadata endpoint stays available.
	SignMetadata bool

	// AssertionTTL is the assertion validity window. <=0 ⇒ DefaultAssertionTTL.
	AssertionTTL time.Duration

	// LogoutRequestWindow is the freshness window for an inbound SP-initiated
	// LogoutRequest: its IssueInstant must be within [now-window, now+skew], and
	// a validated request's ID is deduped (replay-rejected) for this long. <=0 ⇒
	// DefaultLogoutRequestWindow. (A captured, validly-signed LogoutRequest is
	// otherwise replayable indefinitely for targeted-logout DoS.)
	LogoutRequestWindow time.Duration

	// LogoutReplayStoreSize bounds the in-memory LogoutRequest-ID dedup cache.
	// <=0 ⇒ DefaultLogoutReplayStoreSize. Ignored when LogoutReplayStore is wired
	// (a shared backend owns its own sizing/TTL).
	LogoutReplayStoreSize int

	// LogoutReplayStore OPTIONALLY overrides the per-replica in-memory
	// LogoutRequest-ID dedup cache with a SHARED LogoutReplayStore (the sqlite peer
	// in saml/idp/sqlite) so a multi-replica IdP catches a LogoutRequest replayed
	// to a DIFFERENT replica. Nil ⇒ the bounded in-memory default (byte-identical
	// to the pre-seam behavior). The gate still runs AFTER signature + freshness
	// validation, so the shared store is a hardening layer.
	LogoutReplayStore LogoutReplayStore

	// LogoutChainTTL bounds how long a FRONT-channel browser-redirect SLO chain
	// stays resumable across its hops (frontchannel_slo.go). <=0 ⇒
	// DefaultLogoutChainTTL (5m).
	LogoutChainTTL time.Duration

	// LogoutChainStoreSize bounds the in-memory front-channel logout-chain store.
	// <=0 ⇒ DefaultLogoutChainCapacity.
	LogoutChainStoreSize int

	// Pending stores SP-initiated AuthnRequests between /saml/sso and
	// /saml/sso/finish. Nil ⇒ a default in-memory store is created.
	Pending *PendingStore

	// SessionIndex records, per subject, the SAML SPs that subject has an active
	// SSO session with (populated at /saml/sso/finish on assertion-issuance, read
	// at /saml/slo to drive the multi-SP SLO fan-out — the SAML analogue of the
	// OIDC BCL subject-client index). OPTIONAL: nil ⇒ the SLO fan-out is DISABLED
	// and byte-identical to the single-SP SLO (nothing is recorded or read; no
	// goroutine spawned). Wire the default MemorySessionIndex (or a shared
	// sqlite/redis impl for a multi-replica IdP) to enable global single logout.
	SessionIndex SAMLSessionIndex

	// AuditRecorder records the login_success (provider "saml-idp") event when
	// an assertion is issued. Nil ⇒ no audit (the rest of the flow is
	// unchanged).
	AuditRecorder *audit.Recorder

	// FanoutHTTPClient OPTIONALLY overrides the bounded HTTP client the SLO
	// fan-out dispatches LogoutRequests with. Nil ⇒ the package-default
	// fanoutHTTPClient (5s timeout, no redirect-following). It exists as a
	// test/operator seam (e.g. to inject an httptest TLS client that trusts a
	// test cert, since the fan-out destination is https-only). It does NOT relax
	// the https destination gate — that runs independently in dispatchOne.
	FanoutHTTPClient *http.Client

	// Logger is the server logger. Nil ⇒ a no-op logger.
	Logger spi.Logger

	// now is a clock seam for deterministic tests. Nil ⇒ time.Now.
	now func() time.Time
}

// Handlers bundles the three IdP HTTP handlers built from Deps.
type Handlers struct {
	deps    Deps
	pending *PendingStore

	// signerCache memoizes AssertionSigners by signing-key kid. The self-signed
	// cert each AssertionSigner builds is NOT byte-stable across fresh instances
	// (ECDSA cert signatures use a random nonce, and even an RSA cert carries a
	// random serial), so metadata and the finish handler MUST share the SAME
	// AssertionSigner per key — otherwise the cert an SP fetched from metadata
	// wouldn't byte-match the cert in the assertion's KeyInfo, and goxmldsig's
	// trusted-roots check would reject it. Caching by kid (a stable per-key
	// fingerprint) guarantees one cert per key across every request. Rotation
	// produces a new kid → a new cached signer → new metadata cert, naturally.
	signerMu    sync.RWMutex
	signerCache map[string]*AssertionSigner

	// metadataCache memoizes the rendered metadata document per (kid, signed)
	// key. Caching is REQUIRED for the signed path: an ECDSA XML-DSig
	// SignatureValue is non-deterministic (random k), so signing the same
	// EntityDescriptor twice yields different bytes — without a cache the body
	// (and its ETag) would change on every request, defeating the
	// If-None-Match → 304 conditional-request path. The cert is stable per kid
	// (the AssertionSigner caches it) and the entity id / SSO URL are
	// server-constants, so the rendered doc is stable per (kid, signed) and the
	// cache key is sound. A rotation (new kid) naturally produces a fresh entry.
	metadataMu    sync.RWMutex
	metadataCache map[string]*MetadataDoc

	// logoutReplay dedups inbound SP-initiated LogoutRequest IDs within the
	// freshness window (Fix 2). A captured, validly-signed LogoutRequest replays
	// here → rejected (targeted-logout DoS defense). Sized like the assertion
	// replay store on the SP side. A SHARED backend (Deps.LogoutReplayStore, e.g.
	// the sqlite peer) makes the dedup cross-replica.
	logoutReplay LogoutReplayStore

	// chains holds in-flight FRONT-channel logout chains (frontchannel_slo.go),
	// keyed by an unguessable single-use state id. It drives the browser-redirect
	// SLO chain through each front-channel SP's SLO endpoint and back to the
	// initiator. Always non-nil (a default bounded store); it is exercised ONLY
	// when the session index is wired AND a subject has front-channel SPs, so a
	// build with no front-channel SPs never touches it (byte-identical).
	chains *logoutChainStore
}

// NewHandlers validates deps and returns the IdP handler set. A missing
// required dep fails closed (returns an error) so the operator's boot stops
// rather than mounting a half-wired IdP.
func NewHandlers(deps Deps) (*Handlers, error) {
	if deps.ClientStore == nil {
		return nil, errors.New("saml/idp: ClientStore required")
	}
	if deps.SessionManager == nil {
		return nil, errors.New("saml/idp: SessionManager required")
	}
	if deps.UserProvider == nil {
		return nil, errors.New("saml/idp: UserProvider required")
	}
	if deps.IssuerForClient == nil {
		return nil, errors.New("saml/idp: IssuerForClient required (the IdP signs assertions with the per-tenant key)")
	}
	if deps.Issuer == "" {
		return nil, errors.New("saml/idp: Issuer required")
	}
	if deps.Logger == nil {
		deps.Logger = spi.NopLogger{}
	}
	if deps.now == nil {
		deps.now = time.Now
	}
	pending := deps.Pending
	if pending == nil {
		// Default in-memory store: 0 selects DefaultPendingTTL +
		// DefaultPendingCapacity.
		pending = NewPendingStore(0, 0)
	}
	// Logout-replay store: an opt-in SHARED backend (Deps.LogoutReplayStore — the
	// sqlite peer for a multi-replica IdP) takes precedence; nil ⇒ the bounded
	// per-replica in-memory default (byte-identical to the pre-seam behavior).
	logoutReplay := deps.LogoutReplayStore
	if logoutReplay == nil {
		logoutReplay = newLogoutReplayStore(deps.LogoutReplayStoreSize)
	}
	return &Handlers{
		deps:          deps,
		pending:       pending,
		signerCache:   make(map[string]*AssertionSigner),
		metadataCache: make(map[string]*MetadataDoc),
		logoutReplay:  logoutReplay,
		chains:        newLogoutChainStore(deps.LogoutChainTTL, deps.LogoutChainStoreSize),
	}, nil
}

// logoutWindow returns the LogoutRequest freshness window. Configurable via
// Deps.LogoutRequestWindow; <=0 ⇒ DefaultLogoutRequestWindow.
func (h *Handlers) logoutWindow() time.Duration {
	if h.deps.LogoutRequestWindow > 0 {
		return h.deps.LogoutRequestWindow
	}
	return DefaultLogoutRequestWindow
}

// checkLogoutFreshnessAndReplay enforces the LogoutRequest freshness window +
// single-use ID dedup (Fix 2). Called ONLY after the signature is verified (so
// an attacker can't flood the replay store with unsigned junk). Returns a
// non-nil error (the caller collapses it to the one oracle-safe code) when the
// IssueInstant is zero/stale/far-future, the ID is empty, or the ID has been
// seen within the window. The ID is recorded with a TTL of the freshness window
// (a later replay fails the freshness check anyway, so the entry can be pruned).
func (h *Handlers) checkLogoutFreshnessAndReplay(id string, issueInstant time.Time) error {
	now := h.deps.now()
	window := h.logoutWindow()

	if issueInstant.IsZero() {
		return errors.New("saml/idp: logout request missing IssueInstant")
	}
	if now.Sub(issueInstant) > window {
		return errors.New("saml/idp: stale logout request")
	}
	if issueInstant.Sub(now) > logoutMaxClockSkew {
		return errors.New("saml/idp: logout request IssueInstant in the future")
	}
	if id == "" {
		return errors.New("saml/idp: logout request missing ID")
	}
	if fresh := h.logoutReplay.CheckAndRemember(id, issueInstant.Add(window), now); !fresh {
		return errors.New("saml/idp: replayed logout request")
	}
	return nil
}

// entityID returns this IdP's SAML entity identifier: Issuer + "/saml".
func (h *Handlers) entityID() string { return strings.TrimRight(h.deps.Issuer, "/") + "/saml" }

// ssoURL returns the absolute SingleSignOnService location for metadata.
func (h *Handlers) ssoURL() string {
	if h.deps.SSOURL != "" {
		return h.deps.SSOURL
	}
	return strings.TrimRight(h.deps.Issuer, "/") + sso.PathSAMLSSO
}

// loginPath returns where /saml/sso redirects to authenticate.
func (h *Handlers) loginPath() string {
	if h.deps.LoginPath != "" {
		return h.deps.LoginPath
	}
	return "/auth/login"
}
