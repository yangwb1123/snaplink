package sso

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	neturl "net/url"
	"strconv"
	"strings"

	"github.com/snaplink/sso/domains/region"
	"github.com/snaplink/sso/shared/core"
)

// MeshAuthorize is the dep-free, reusable mesh authorization decision —
// Phase A of gRPC ext_authz support. It extracts the bearer, validates it
// EXACTLY like /userinfo (validateAnyToken + the DPoP/mTLS sender-constraint
// + read-side residency), and on ALLOW derives the X-Auth-* identity
// (Subject/ClientID/Scopes/ExpiresAt/Roles) — all from the validated token
// only, never from the inbound request. It performs NO HTTP writing: it is
// a pure decision + identity over a stdlib-typed request abstraction
// (method/URL/headers/cert), so the same logic backs two transports:
//
//   - handleMeshExtAuthz (this module) — the Envoy/Istio ext_authz
//     HTTP-mode endpoint, a thin wrapper that renders this result to HTTP
//     (200 + X-Auth-* on ALLOW; 401 invalid_token on DENY); its wire
//     behavior is byte-identical to the pre-refactor inline handler.
//   - the future Phase-B go-control-plane gRPC Authorization service — a
//     SEPARATE nested module that builds a MeshAuthorizeRequest from the
//     CheckRequest and reuses this EXACT validation + identity derivation.
//
// SECURITY:
//   - Sender-constraint preserved: a DPoP- or mTLS-bound token presented
//     WITHOUT a matching proof / client cert is DENIED.
//   - Oracle-safe DENY: every validation failure collapses to invalid_token;
//     the missing-credentials case carries a bare challenge (no error=).
//   - Edge-strip identity: every X-Auth-* is DERIVED from the validated token;
//     an inbound X-Auth-* is never trusted.

// MeshAuthorizeRequest is the stdlib-typed, dependency-free request
// abstraction MeshAuthorize operates on. It carries exactly enough request
// context to reproduce the /userinfo validation path off the HTTP request:
// the bearer + DPoP proof live in Header; Method + URL bind the DPoP proof
// (htm/htu); the mTLS material (TLS state and/or an explicit peer cert)
// feeds the sender-constraint. No transport type leaks in — the HTTP
// handler and a future gRPC module both build this from their own request.
type MeshAuthorizeRequest struct {
	// Method is the HTTP method of the mesh-intercepted request, used as
	// the DPoP proof's htm binding. For the HTTP endpoint this is the
	// ext_authz request's own method (GET/POST at the mesh path); a gRPC
	// ext_authz module supplies the intercepted request's method.
	Method string

	// URL is the absolute URL used as the DPoP proof's htu binding. The
	// HTTP wrapper passes requestURLForDPoP(r) (the same X-Forwarded-aware
	// public URL the rest of the server computes) so behavior is
	// byte-identical to the inline handler.
	URL string

	// Header carries the inbound request headers: Authorization (bearer),
	// DPoP (proof), the X-Forwarded-* chain (issuer/htu/region resolution),
	// and — under security.mtls.backend: header — the client-cert header.
	// Never read for X-Auth-* (those are derived from the token, not the
	// request).
	Header http.Header

	// TLS is the connection's TLS state when the AS terminates mTLS
	// directly (security.mtls.backend: tls reads TLS.PeerCertificates[0]).
	// Optional; nil under header-mode mTLS or no mTLS.
	TLS *tls.ConnectionState

	// ClientCert is an explicit peer certificate for callers that have one
	// outside r.TLS (e.g. a gRPC ext_authz module that receives the peer
	// cert from the transport, not an *http.Request). When set it is
	// installed as the synthetic request's TLS peer cert so the default
	// TLS extractor finds it. Optional; ignored when nil.
	ClientCert *x509.Certificate
}

// MeshAuthorizeResult is the outcome of MeshAuthorize: a binary ALLOW/DENY
// plus, on ALLOW, the DERIVED identity the sidecar injects upstream. On
// DENY it carries a single oracle-safe wire code (no per-cause detail).
type MeshAuthorizeResult struct {
	// Allowed is true iff the bearer validated (incl. the sender-constraint
	// and residency gates). The identity fields below are populated ONLY
	// when Allowed; on DENY they are zero.
	Allowed bool

	// Derived identity (ALLOW only) — all from the validated token, never
	// echoed from the inbound request.
	Subject   string   // X-Auth-Subject (token sub)
	ClientID  string   // X-Auth-Client-Id (token client_id; omitted when empty)
	Scopes    []string // X-Auth-Scopes (token scopes; omitted when empty)
	ExpiresAt int64    // X-Auth-Expires (token exp, Unix seconds; 0 when the token has no exp)
	Roles     []string // X-Auth-Roles (permissions provider lookup; nil when unwired / none / lookup error)

	// DenyCode is the oracle-safe wire code on DENY: ErrInvalidToken for
	// every validation/sender-constraint/residency failure, or "" for the
	// missing-credentials case (which renders a bare Bearer challenge with
	// no error= per RFC 6750 §3.1). Empty on ALLOW. NO per-cause detail is
	// exposed here — the only observable distinction is the same one
	// /userinfo already makes (missing vs invalid).
	DenyCode string

	// DPoPNonce carries the fresh server-issued DPoP nonce (RFC 9449 §8/§9)
	// on the ONE deny cause that is a protocol handshake (DPoP-bound token
	// whose proof is missing a nonce while a nonce provider is wired). The
	// HTTP path does NOT consume this field (it replays challengeHeader
	// verbatim); only the gRPC transport reads it. Every other deny cause
	// collapses to DenyCode alone — binding/validity/residency are
	// non-probeable.
	DPoPNonce string

	// challengeHeader holds the response headers the existing
	// setBearerChallenge / stampDPoPNonce helpers produced for a DENY
	// (WWW-Authenticate, and DPoP-Nonce on a use_dpop_nonce challenge).
	// Unexported: it is an HTTP-rendering detail the thin wrapper replays
	// verbatim to stay byte-identical with the pre-refactor handler — it is
	// NOT part of the reusable decision surface (a gRPC caller branches on
	// Allowed/DenyCode, not on HTTP challenge headers).
	challengeHeader http.Header
}

// meshHeaderRecorder is a minimal http.ResponseWriter that captures only
// response HEADERS. The decision-path helpers reused by MeshAuthorize
// (setBearerChallenge, stampDPoPNonce) write a DENY challenge solely via
// Header().Set; they never write a status or body on the path MeshAuthorize
// drives. WriteHeader/Write are implemented defensively (so the type is a
// complete ResponseWriter) but are not expected to fire — MeshAuthorize
// itself emits no body and lets the transport wrapper own status/body.
type meshHeaderRecorder struct {
	header http.Header
}

func newMeshHeaderRecorder() *meshHeaderRecorder {
	return &meshHeaderRecorder{header: make(http.Header)}
}

func (m *meshHeaderRecorder) Header() http.Header         { return m.header }
func (m *meshHeaderRecorder) WriteHeader(int)             {}
func (m *meshHeaderRecorder) Write(b []byte) (int, error) { return len(b), nil }

// MeshAuthorize runs the mesh authorization decision for req and returns the
// ALLOW/DENY outcome plus the derived identity (on ALLOW). It reuses the
// EXACT helpers the /userinfo and inline ext_authz paths use — bearerToken,
// validateAnyToken, verifyDPoPBearer, verifyMTLSBearer,
// residencyDeniedForAccess, and the permissions Roles lookup — by building a
// synthetic HandlerContext over a synthetic *http.Request reconstructed from
// req. The synthetic request carries the same Method, URL (Host +
// X-Forwarded-* via the cloned Header), DPoP proof, TLS state, and client
// cert the real request did, so every read those helpers perform — DPoP
// htm/htu, mTLS thumbprint, issuer/region resolution — yields an identical
// result. No HTTP is written here.
//
// ctx is the request context (deadlines/cancellation/values for the issuer +
// permissions lookups). req carries the wire-level request material.
func (s *Server) MeshAuthorize(ctx context.Context, req MeshAuthorizeRequest) MeshAuthorizeResult {
	if ctx == nil { // Background so downstream lookups see a real context
		ctx = context.Background()
	}
	hr := buildMeshSyntheticRequest(ctx, req)
	rec := newMeshHeaderRecorder()
	hctx := core.NewContext(rec, hr)
	// Stash the serving region so the read-side residency gate sees it.
	s.stashMeshServingRegion(hctx)
	res := MeshAuthorizeResult{challengeHeader: rec.header}

	// DENY ladder — same order + oracle-collapse as /userinfo: missing token →
	// bare challenge (empty DenyCode); every other deny → ErrInvalidToken.
	tokenString := bearerToken(hr)
	if tokenString == "" {
		setBearerChallenge(hctx, s.resolveIssuer(hctx), "", "") // RFC 6750 §3.1 bare challenge
		res.DenyCode = ""
		return res
	}
	claims, _, err := s.validateAnyToken(ctx, tokenString)
	if err != nil {
		return s.meshDenyInvalidToken(hctx, res, "The access token is invalid or expired")
	}
	// Sender-constraint: a bound token without a matching proof/cert collapses
	// to the same invalid_token DENY — binding is not probeable.
	if derr := s.verifyDPoPBearer(hctx, claims); derr != nil {
		return s.meshHandleDPoPDeny(hctx, res, rec, derr, claims)
	}
	if merr := s.verifyMTLSBearer(hctx, claims); merr != nil {
		s.logger.Error("mesh authorize mtls bearer verification failed", "error", merr, "subject", claims.Subject)
		return s.meshDenyInvalidToken(hctx, res, "Client certificate missing or thumbprint mismatch")
	}
	// Data-residency READ-gate — after bearer + sender-constraint; oracle-safe.
	if _, denied := s.residencyDeniedForAccess(hctx, claims); denied {
		return s.meshDenyInvalidToken(hctx, res, "Access denied")
	}
	// Session-liveness check: when a token carries an sid claim AND a
	// SessionManager is wired, verify the session is still active (oracle-safe
	// invalid_token on failure). OPTIONAL — nil s.sessionMgr is the default.
	if denied := s.meshCheckSession(hctx, ctx, claims, &res); denied {
		return res
	}
	res.Allowed = true // ALLOW — derive identity from the validated token only
	s.deriveMeshIdentity(ctx, claims, &res)
	return res
}

// meshHandleDPoPDeny handles a DPoP verification failure. It distinguishes the
// DPoP nonce handshake case (RFC 9449 §8, returns the updated res with the fresh
// nonce) from other failures (returns the oracle-safe invalid_token DENY).
func (s *Server) meshHandleDPoPDeny(hctx HandlerContext, res MeshAuthorizeResult, rec *meshHeaderRecorder, derr error, claims *TokenClaims) MeshAuthorizeResult {
	if errors.Is(derr, ErrDPoPNonceRequired) {
		s.stampDPoPNonce(hctx)
		setBearerChallenge(hctx, s.resolveIssuer(hctx), ErrUseDPoPNonce, "Fresh DPoP nonce required")
		res.DenyCode = ErrInvalidToken
		res.DPoPNonce = rec.header.Get(HeaderDPoPNonce)
		return res
	}
	s.logger.Error("mesh authorize dpop bearer verification failed", "error", derr, "subject", claims.Subject)
	return s.meshDenyInvalidToken(hctx, res, "DPoP proof missing or thumbprint mismatch")
}

// meshCheckSession checks whether the session identified by claims.SID is still
// active, collapsing every failure (storage error, not found, expired) to the
// same oracle-safe invalid_token. Returns true when the request should be denied
// (res is already populated with the DENY state); false when the session is
// active or no session check applies (continue to ALLOW).
func (s *Server) meshCheckSession(hctx HandlerContext, ctx context.Context, claims *TokenClaims, res *MeshAuthorizeResult) bool {
	if claims.SID == "" || s.sessionMgr == nil {
		return false
	}
	sess, err := s.sessionMgr.Get(ctx, claims.SID)
	if err != nil || sess == nil || sess.IsExpired() {
		if err != nil {
			s.logger.Error("mesh authorize session check failed", "error", err, "sid", claims.SID, "subject", claims.Subject)
		}
		*res = s.meshDenyInvalidToken(hctx, *res, "Session no longer active")
		return true
	}
	return false
}

// meshDenyInvalidToken emits the oracle-collapsed invalid_token DENY shared by
// every non-missing-token rung of the ladder (validation, DPoP/mTLS
// sender-constraint, residency): the SAME setBearerChallenge(ErrInvalidToken,
// desc) the inline ladder wrote, then stamps res.DenyCode = ErrInvalidToken and
// returns res. desc is the only per-rung input; the wire code is fixed so no
// cause is probeable.
func (s *Server) meshDenyInvalidToken(hctx HandlerContext, res MeshAuthorizeResult, desc string) MeshAuthorizeResult {
	setBearerChallenge(hctx, s.resolveIssuer(hctx), ErrInvalidToken, desc)
	res.DenyCode = ErrInvalidToken
	return res
}

// buildMeshSyntheticRequest reconstructs the synthetic *http.Request the reused
// /userinfo-path helpers read from. Method + Header + Host + URL.Path + TLS
// reproduce every field DPoP/mTLS/issuer/region resolution touch; the bound ctx
// carries the caller's deadline/cancellation into validateAnyToken / the
// ClientStore / permissions lookups. Behavior is byte-identical to the former
// inline assembly.
func buildMeshSyntheticRequest(ctx context.Context, req MeshAuthorizeRequest) *http.Request {
	hr := &http.Request{
		Method: req.Method,
		Header: cloneMeshHeader(req.Header),
	}
	// Parse the absolute URL so r.URL.Path (DPoP htu, base-URL path) and
	// r.Host (issuer/htu host) match the wire. A parse failure leaves an
	// empty URL/Host, which only weakens htu/issuer resolution toward the
	// deny side — never a bypass.
	if req.URL != "" {
		if u, err := neturl.Parse(req.URL); err == nil {
			hr.URL = u
			hr.Host = u.Host
		}
	}
	if hr.URL == nil {
		hr.URL = &neturl.URL{}
	}
	// mTLS material. r.TLS feeds the TLS-backend extractor
	// (r.TLS.PeerCertificates[0]); an explicit ClientCert is installed as a
	// synthetic peer cert so the same default extractor finds it without a
	// real TLS handshake (the gRPC-module path).
	hr.TLS = req.TLS
	if req.ClientCert != nil {
		if hr.TLS == nil {
			hr.TLS = &tls.ConnectionState{}
		}
		// Copy so we never mutate a caller-shared ConnectionState; the
		// extractor reads PeerCertificates[0].
		st := *hr.TLS
		st.PeerCertificates = append([]*x509.Certificate{req.ClientCert}, st.PeerCertificates...)
		hr.TLS = &st
	}
	// Bind the request context so the synthetic request carries the caller's
	// deadline/cancellation into validateAnyToken / the ClientStore /
	// permissions lookups.
	return hr.WithContext(ctx)
}

// deriveMeshIdentity populates the ALLOW-side identity on res from the validated
// token claims ONLY — never from the inbound request. Optional roles are added
// only when a permissions provider is wired AND the lookup succeeds with a
// non-empty result; a lookup failure is non-fatal (ALLOW still holds, roles
// omitted), mirroring the inline handler's behavior exactly.
func (s *Server) deriveMeshIdentity(ctx context.Context, claims *core.TokenClaims, res *MeshAuthorizeResult) {
	res.Subject = claims.Subject
	res.ClientID = claims.ClientID
	res.Scopes = claims.Scopes
	if !claims.ExpiresAt.IsZero() {
		res.ExpiresAt = claims.ExpiresAt.Unix()
	}
	if s.permissions == nil || claims.Subject == "" {
		return
	}
	// OIDC §8 pairwise: permissions are keyed by the LOCAL subject, but the
	// token's sub may be the per-sector pseudonym. Resolve before the roles
	// lookup (mirrors /userinfo) or a pairwise client gets EMPTY roles. res.Subject
	// stays the pairwise sub the client presented (privacy unchanged).
	lookupSub := claims.Subject
	if local, lerr := s.resolveLocalSubject(ctx, claims.Subject); lerr == nil && local != "" {
		lookupSub = local
	}
	roles, rerr := s.permissions.Roles(ctx, lookupSub, claims.ClientID)
	if rerr != nil || len(roles) == 0 {
		return
	}
	codes := make([]string, 0, len(roles))
	for _, r := range roles {
		codes = append(codes, r.Code)
	}
	res.Roles = codes
}

// stashMeshServingRegion resolves the serving region for the synthetic mesh
// request and stashes it on the HandlerContext exactly as region.Middleware
// does, so the read-side residency gate sees the same region without the
// middleware having run. It replicates the middleware's resolve →
// AllowedRegions backstop → stash sequence (region/middleware.go is the
// source of truth) because the closure body isn't reachable directly. A nil
// resolver stashes nothing — residency disabled stays byte-identical.
func (s *Server) stashMeshServingRegion(hctx core.HandlerContext) {
	if s.regionResolver == nil {
		return
	}
	id, err := s.regionResolver.Resolve(hctx.Request())
	if err != nil {
		if s.regionMiddlewareOpts.OnError != nil {
			s.regionMiddlewareOpts.OnError(hctx.Request(), err)
		}
		region.WithHandlerContext(hctx, region.ID(""))
		return
	}
	if len(s.regionMiddlewareOpts.AllowedRegions) > 0 && id != "" && !meshRegionAllowed(s.regionMiddlewareOpts.AllowedRegions, id) {
		id = ""
	}
	region.WithHandlerContext(hctx, id)
}

func meshRegionAllowed(set []region.ID, want region.ID) bool {
	for _, id := range set {
		if id == want {
			return true
		}
	}
	return false
}

// cloneMeshHeader returns a deep copy of h so the synthetic request never
// shares (or mutates) the caller's header map. nil → an empty, non-nil
// header (the helpers call Header.Get, which is nil-safe, but the synthetic
// request keeps a real map for consistency).
func cloneMeshHeader(h http.Header) http.Header {
	if h == nil {
		return make(http.Header)
	}
	out := make(http.Header, len(h))
	for k, vs := range h {
		cp := make([]string, len(vs))
		copy(cp, vs)
		out[k] = cp
	}
	return out
}

// writeMeshAuthzResponse renders a MeshAuthorizeResult to the HTTP
// ext_authz response on hctx, byte-identically to the pre-refactor inline
// handler. On ALLOW it stamps the DERIVED X-Auth-* identity headers + a 200
// (empty body — Envoy reads status + headers). On DENY it replays the
// challenge headers MeshAuthorize captured (WWW-Authenticate, and DPoP-Nonce
// for a use_dpop_nonce challenge) + a 401 (empty body, oracle-safe). The
// X-Auth-* roles header is comma-joined; scopes space-joined — the exact
// formats the sidecar expects.
func (s *Server) writeMeshAuthzResponse(hctx HandlerContext, res MeshAuthorizeResult) {
	if !res.Allowed {
		// Replay the captured DENY challenge headers verbatim (the existing
		// setBearerChallenge / stampDPoPNonce produced them via Header().Set,
		// so copy the exact key→values), then 401 with no body (oracle-safe
		// — no detail, no identity). tokenNoStoreHeaders never sets
		// WWW-Authenticate / DPoP-Nonce, so this is a faithful replay of what
		// the inline handler wrote directly.
		dst := hctx.ResponseWriter().Header()
		for k, vs := range res.challengeHeader {
			dst[k] = append([]string(nil), vs...)
		}
		hctx.ResponseWriter().WriteHeader(http.StatusUnauthorized)
		return
	}
	h := hctx.ResponseWriter().Header()
	h.Set(HeaderAuthSubject, res.Subject)
	if res.ClientID != "" {
		h.Set(HeaderAuthClientID, res.ClientID)
	}
	if len(res.Scopes) > 0 {
		h.Set(HeaderAuthScopes, strings.Join(res.Scopes, " "))
	}
	if res.ExpiresAt != 0 {
		h.Set(HeaderAuthExpires, strconv.FormatInt(res.ExpiresAt, 10))
	}
	if len(res.Roles) > 0 {
		h.Set(HeaderAuthRoles, strings.Join(res.Roles, ","))
	}
	// Empty body — Envoy reads the 2xx status + the response headers.
	hctx.ResponseWriter().WriteHeader(http.StatusOK)
}

// --- Resource-side DPoP (RFC 9449) — used by MeshAuthorize + /userinfo ---

// checkDPoPAth enforces RFC 9449 §4.3 + §7.1: at a protected resource the proof
// MUST carry ath = base64url(SHA-256(access_token)) and the RS MUST verify it
// equals the hash of the PRESENTED token, binding the proof to the specific
// token so a captured proof can't be replayed with a DIFFERENT token of the same
// key. accessToken=="" is the /token issuance path (no token yet) — ath is
// neither present nor checked. Always SHA-256 per spec; constant-time compare.
func checkDPoPAth(proofAth, accessToken string) error {
	if accessToken == "" {
		return nil
	}
	sum := sha256.Sum256([]byte(accessToken))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(proofAth), []byte(want)) != 1 {
		return errors.New("dpop: ath does not bind the presented access token")
	}
	return nil
}

// dpopSchemeToken extracts the raw access-token string from the Authorization
// header, accepting the RFC 9449 "DPoP" scheme (and "Bearer" defensively); the
// value is hashed into the DPoP ath binding. Empty when no recognized scheme.
func dpopSchemeToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	for _, scheme := range []string{"DPoP ", "Bearer "} {
		if len(h) > len(scheme) && strings.EqualFold(h[:len(scheme)], scheme) {
			return h[len(scheme):]
		}
	}
	return ""
}

// verifyDPoPBearer is the resource-side DPoP gate: for a cnf.jkt-bound access
// token it requires a valid DPoP proof header whose key thumbprint matches the
// token's cnf.jkt AND whose ath binds the presented token. A non-DPoP token
// passes through (legacy bearer). All failures collapse to a DPoP-shaped error.
func (s *Server) verifyDPoPBearer(ctx HandlerContext, claims *TokenClaims) error {
	if claims == nil {
		return errors.New("dpop: nil claims")
	}
	if claims.ConfirmationJKT == "" {
		return nil // not DPoP-bound — legacy bearer flow continues
	}
	proof := ctx.Request().Header.Get(HeaderDPoP)
	if proof == "" {
		return errors.New("dpop: token requires DPoP proof header")
	}
	// The RAW presented access token (DPoP scheme: "Authorization: DPoP <tok>")
	// is hashed into ath inside verifyDPoPProof. Extracting it from the same
	// header that produced `claims` guarantees the proof is bound to THIS token.
	binding, err := verifyDPoPProof(
		ctx.Request().Context(),
		proof,
		ctx.Request().Method,
		requestURLForDPoP(ctx.Request()),
		s.jtiReplayStore,
		s.jtiReplayFailClosed,
		s.dpopNonceProvider,
		s.resolvedDPoPProofMaxAge(),
		s.resolvedDPoPProofClockSkew(),
		dpopSchemeToken(ctx.Request()),
	)
	if err != nil {
		return fmt.Errorf("dpop: proof verification: %w", err)
	}
	if binding.JKT != claims.ConfirmationJKT {
		return errors.New("dpop: proof JKT does not match token cnf.jkt")
	}
	return nil
}
