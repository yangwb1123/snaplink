package extauthz

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/snaplink/sso"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
)

// MeshAuthorizer is the narrow seam this gRPC service depends on:
// *sso.Server satisfies it via its MeshAuthorize method (mesh_authz.go,
// Phase A). The interface — rather than a concrete *sso.Server — keeps the
// coupling minimal and lets the operator's fork inject the server (and lets
// tests inject a fake). It is the SINGLE source of truth for the mesh
// authorization decision: this module re-maps wire <-> seam ONLY and never
// re-implements any token validation, sender-constraint, or residency logic
// (a duplicated mesh-authz path is an auth-bypass risk).
type MeshAuthorizer interface {
	MeshAuthorize(context.Context, sso.MeshAuthorizeRequest) sso.MeshAuthorizeResult
}

// AuthorizationServer implements the Envoy gRPC external authorization
// service (envoy.service.auth.v3.Authorization). It is the gRPC-mode
// companion to the shipped, in-core HTTP-mode mesh ext_authz endpoint
// (handleMeshExtAuthz): a mesh whose ext_authz filter is configured in
// gRPC mode points at this service and gets the SAME token validation +
// identity injection, because Check maps the CheckRequest into the
// dep-free MeshAuthorize seam and back into a CheckResponse.
//
// Embedding UnimplementedAuthorizationServer is the protoc-gen-go-grpc
// forward-compatibility contract (new RPCs added to the service won't
// break the build).
//
// SECURITY (AGENTS.md §2), all enforced by the seam, faithfully surfaced
// here:
//   - The derived X-Auth-* identity comes ONLY from the validated token,
//     NEVER from the inbound CheckRequest. On ALLOW we additionally tell
//     Envoy to STRIP any client-supplied X-Auth-* before injecting our
//     own (HeadersToRemove + an authoritative OVERWRITE append action) —
//     the edge-strip invariant over gRPC.
//   - Oracle-safe DENY: every failure collapses to PERMISSION_DENIED + a
//     401 invalid_token challenge with NO body and NO per-cause detail
//     (the seam's DenyCode is already collapsed to "" | invalid_token).
//   - The DPoP/mTLS sender-constraint + read-side residency flow through
//     the seam, fed from the CheckRequest's method/URL/headers/cert — a
//     stolen sender-constrained token cannot replay as a plain bearer over
//     gRPC either.
type AuthorizationServer struct {
	authv3.UnimplementedAuthorizationServer

	authorizer MeshAuthorizer
}

// authStripHeaders is the set of identity headers Envoy must remove from
// the inbound request before injecting the DERIVED ones on ALLOW. A client
// that smuggles e.g. X-Auth-Subject must NOT have it survive to the
// upstream — the upstream trusts these headers only because this service
// set them. We both remove the inbound copies (HeadersToRemove) and set
// ours with OVERWRITE_IF_EXISTS_OR_ADD, so neither a casing trick nor an
// ordering quirk lets a spoofed value through. Keys mirror the core
// sso.HeaderAuth* constants (lower-cased per the ext_authz header
// convention is not required here — HeadersToRemove matching is
// case-insensitive in Envoy — but we use the canonical names for clarity).
var authStripHeaders = []string{
	sso.HeaderAuthSubject,
	sso.HeaderAuthClientID,
	sso.HeaderAuthScopes,
	sso.HeaderAuthExpires,
	sso.HeaderAuthRoles,
}

// NewAuthorizationServer builds the gRPC Authorization service over a
// MeshAuthorizer (in production the operator's *sso.Server). The returned
// value is registered with authv3.RegisterAuthorizationServer on the
// operator's grpc.Server (see doc.go).
func NewAuthorizationServer(authorizer MeshAuthorizer) *AuthorizationServer {
	return &AuthorizationServer{authorizer: authorizer}
}

// Check is the single RPC of the Envoy Authorization service. It runs the
// mesh authorization decision for one intercepted request and returns the
// ALLOW (OkHttpResponse, status OK) or DENY (DeniedHttpResponse, status
// PERMISSION_DENIED) verdict.
//
// Mapping (the whole job of this method — no auth logic lives here):
//
//	CheckRequest.Attributes.Request.Http  ->  sso.MeshAuthorizeRequest
//	  .Method                              ->    .Method   (DPoP htm)
//	  .Scheme + .Host + .Path (Path carries ?query) -> .URL (DPoP htu)
//	  .Headers (lower-cased map)           ->    .Header   (bearer/DPoP/XFF)
//	CheckRequest.Attributes.Source.Certificate (URL+PEM) -> .ClientCert (mTLS)
//	                          |
//	                          v
//	          authorizer.MeshAuthorize(ctx, req) -> sso.MeshAuthorizeResult
//	                          |
//	                          v
//	  Allowed -> CheckResponse{ OK, OkHttpResponse{ X-Auth-* injected,
//	                                                 inbound X-Auth-* stripped } }
//	  else    -> CheckResponse{ PERMISSION_DENIED,
//	                            DeniedHttpResponse{ 401, WWW-Authenticate, no body
//	                              [ + DPoP-Nonce + use_dpop_nonce on the nonce
//	                                handshake — the one non-invalid_token deny ] } }
//
// We ALWAYS return a nil Go error and carry the verdict in the
// CheckResponse.Status field (OK vs PERMISSION_DENIED). Returning a non-nil
// error would surface as a gRPC transport failure, which makes Envoy apply
// its failure_mode_allow setting — potentially failing OPEN. Keeping the
// transport call successful and putting the decision in CheckResponse.Status
// means a DENY is an unambiguous DENY regardless of the sidecar's
// failure-mode configuration.
func (a *AuthorizationServer) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	mreq := buildMeshRequest(req)
	res := a.authorizer.MeshAuthorize(ctx, mreq)

	if res.Allowed {
		return allowResponse(res), nil
	}
	return denyResponse(res), nil
}

// buildMeshRequest reconstructs a sso.MeshAuthorizeRequest from the Envoy
// CheckRequest. Every field the seam reads to reproduce the /userinfo
// validation path is sourced here; anything absent degrades only toward the
// DENY side (e.g. a missing/garbled cert leaves ClientCert nil, which makes
// an mTLS-bound token fail the sender-constraint — never a bypass).
func buildMeshRequest(req *authv3.CheckRequest) sso.MeshAuthorizeRequest {
	httpAttrs := req.GetAttributes().GetRequest().GetHttp()

	mreq := sso.MeshAuthorizeRequest{
		Method: httpAttrs.GetMethod(),
		URL:    reconstructURL(httpAttrs),
		Header: headersToHTTP(httpAttrs.GetHeaders()),
	}

	// Client cert for the mTLS sender-constraint. Envoy puts the peer cert
	// (when the downstream presented one and the listener is configured to
	// forward it) in Source.Certificate as URL-encoded PEM. Parse it to an
	// *x509.Certificate; the seam installs it as the synthetic request's
	// TLS peer cert so the default mTLS extractor finds it. Absent or
	// unparseable -> nil (the seam treats it as "no client cert").
	if cert := parsePeerCertificate(req.GetAttributes().GetSource().GetCertificate()); cert != nil {
		mreq.ClientCert = cert
	}
	return mreq
}

// reconstructURL rebuilds the absolute request URL (scheme://host/path[?query])
// from the Envoy HTTP attributes. This is the DPoP htu binding the seam
// checks the proof against, so it MUST match what the DPoP client signed:
// scheme + authority + path. Envoy populates Scheme/Host from the
// downstream request (the public-facing values at the mesh edge), the same
// values requestURLForDPoP derives from X-Forwarded-* on the HTTP path.
//
// Envoy's GetPath() carries the FULL request target INCLUDING the query
// (`/x?a=1`), and GetQuery() is ALWAYS empty in the ext_authz
// AttributeContext (the query is not split out). So we strings.Cut the path
// on the first '?' into Path + RawQuery and assign them to the distinct
// url.URL fields — assigning the whole `/x?a=1` to url.URL.Path would
// percent-encode the '?' into the path (`/x%3Fa=1`), a semantically wrong
// (though, with the seam's normalizeDPoPHTU stripping the query on both
// sides, today harmless) reconstruction.
//
// The query is preserved (faithful to the wire) but the seam's htu
// comparison normalizes it away (strips query+fragment) on its side, so it
// is not load-bearing for the binding; carrying it keeps the reconstructed
// URL accurate. Host already carries the authority (host[:port]); we do not
// re-add a port.
func reconstructURL(h *authv3.AttributeContext_HttpRequest) string {
	scheme := h.GetScheme()
	if scheme == "" {
		// Envoy may omit scheme for some protocols; default to https since
		// the mesh data-plane is TLS. An empty scheme would only weaken the
		// htu/issuer host resolution toward DENY, never a bypass.
		scheme = "https"
	}
	host := h.GetHost()
	// Envoy embeds the query inside GetPath(); split it off so url.URL keeps
	// Path and RawQuery distinct (no '?' percent-encoded into the path).
	path, rawQuery, _ := strings.Cut(h.GetPath(), "?")
	// Defensive fallback ONLY when GetPath() had no '?' yet a separate
	// GetQuery() is somehow populated (Envoy's documented behavior won't do
	// this, but a non-conformant data plane shouldn't silently drop a query).
	if rawQuery == "" {
		rawQuery = h.GetQuery()
	}
	if host == "" {
		// No authority -> we cannot build an absolute URL. Return the path
		// alone (or empty); the seam's neturl.Parse yields an empty Host,
		// which only degrades htu/issuer resolution toward DENY. (Drop any
		// query: without a host the value isn't a usable absolute URL anyway,
		// and the seam normalizes the query out regardless.)
		return path
	}
	u := url.URL{Scheme: scheme, Host: host, Path: path, RawQuery: rawQuery}
	// Path may already include a leading '/'; url.URL.String handles that.
	return u.String()
}

// headersToHTTP converts Envoy's lower-cased header map into a canonical
// http.Header via Set, so the stdlib-based readers in the seam find their
// values. Envoy guarantees the inbound keys are lower-cased (HTTP header
// keys are case-insensitive), and http.Header.Set canonicalizes each key
// through textproto.CanonicalMIMEHeaderKey, so "authorization" lands under
// "Authorization" where bearerToken reads it, and the X-Forwarded-* chain
// lands under its canonical keys.
//
// DPoP is correct WITHOUT special-casing: the canonical proof header is
// "DPoP", and CanonicalMIMEHeaderKey maps both "dpop" (on Set here) and
// "DPoP" (on the seam's Get) to the SAME interned key "Dpop", so the proof
// stored here is exactly what the seam's Get("DPoP") retrieves.
func headersToHTTP(in map[string]string) http.Header {
	out := make(http.Header, len(in))
	for k, v := range in {
		out.Set(k, v)
	}
	return out
}

// parsePeerCertificate decodes Envoy's URL-encoded PEM peer certificate
// (AttributeContext.Source.Certificate, documented as "encoded in URL and
// PEM format") into an *x509.Certificate. Returns nil on any failure
// (empty, non-cert PEM, parse error) — a nil cert means "no verified client
// cert", which the seam treats as the absence of mTLS material. Fail-safe:
// a malformed cert can only FAIL an mTLS sender-constraint (DENY), never
// satisfy one.
//
// We try the URL-unescaped form FIRST (the documented encoding), then the
// raw string as a fallback. The raw fallback matters because url.Query
// unescaping is LOSSY on un-escaped PEM: a '+' in the base64 body decodes
// to a space, corrupting the block. So we never trust a single transform —
// we PEM-decode each candidate and use the first that yields a CERTIFICATE.
func parsePeerCertificate(s string) *x509.Certificate {
	if s == "" {
		return nil
	}
	candidates := make([]string, 0, 2)
	if decoded, err := url.QueryUnescape(s); err == nil && decoded != s {
		// Only add the unescaped form when it actually changed something;
		// when s has no escapes, decoded == s and the raw candidate covers it.
		candidates = append(candidates, decoded)
	}
	candidates = append(candidates, s)

	for _, c := range candidates {
		if cert := certFromPEM(c); cert != nil {
			return cert
		}
	}
	return nil
}

// certFromPEM decodes a single PEM CERTIFICATE block to an *x509.Certificate,
// or nil if c is not a parseable CERTIFICATE PEM.
func certFromPEM(c string) *x509.Certificate {
	block, _ := pem.Decode([]byte(c))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return cert
}

// allowResponse builds the OK CheckResponse: status OK + an OkHttpResponse
// carrying the DERIVED X-Auth-* identity headers Envoy injects upstream,
// and HeadersToRemove stripping any inbound X-Auth-* (edge-strip). The
// header formats MATCH the HTTP handler (writeMeshAuthzResponse):
// X-Auth-Scopes space-joined, X-Auth-Roles comma-joined, X-Auth-Expires the
// decimal Unix-seconds exp. Empty/zero fields are omitted exactly as the
// HTTP path omits them.
func allowResponse(res sso.MeshAuthorizeResult) *authv3.CheckResponse {
	headers := make([]*corev3.HeaderValueOption, 0, len(authStripHeaders))

	add := func(key, value string) {
		headers = append(headers, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{Key: key, Value: value},
			// Authoritatively overwrite (or add) — never append to an
			// attacker-supplied inbound value. Combined with
			// HeadersToRemove below this is belt-and-suspenders so a
			// spoofed X-Auth-* cannot survive to the upstream.
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}

	// Subject is always present on ALLOW (the token validated; sub is set).
	add(sso.HeaderAuthSubject, res.Subject)
	if res.ClientID != "" {
		add(sso.HeaderAuthClientID, res.ClientID)
	}
	if len(res.Scopes) > 0 {
		add(sso.HeaderAuthScopes, strings.Join(res.Scopes, " "))
	}
	if res.ExpiresAt != 0 {
		add(sso.HeaderAuthExpires, strconv.FormatInt(res.ExpiresAt, 10))
	}
	if len(res.Roles) > 0 {
		add(sso.HeaderAuthRoles, strings.Join(res.Roles, ","))
	}

	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				Headers: headers,
				// Strip any client-supplied X-Auth-* on the inbound request
				// so only our DERIVED headers reach the upstream. Envoy
				// removes these BEFORE applying the Headers above.
				HeadersToRemove: authStripHeaders,
			},
		},
	}
}

// denyResponse builds the PERMISSION_DENIED CheckResponse: a 401
// DeniedHttpResponse with the oracle-safe WWW-Authenticate Bearer challenge
// and NO body. It mirrors the HTTP handler's DENY (a 401 with the
// setBearerChallenge header, empty body) without leaking any per-cause
// detail — the seam already collapsed every failure to one DenyCode
// (""|invalid_token).
//
// The WWW-Authenticate challenge is reconstructed from DenyCode here (the
// seam's captured challenge header is an unexported HTTP-rendering detail
// not exposed on the result). DenyCode == "" is the missing-credentials
// case -> a bare `Bearer realm="..."` (no error=, per RFC 6750 §3.1);
// DenyCode == invalid_token -> `Bearer realm="...", error="invalid_token"`.
//
// The ONE exception to the invalid_token collapse is the DPoP nonce
// handshake: when the seam set res.DPoPNonce (a DPoP-bound token whose proof
// lacked a fresh nonce while a nonce provider is wired), we emit the
// DPoP-Nonce response header carrying that fresh nonce AND set the
// WWW-Authenticate error to use_dpop_nonce — exactly the RFC 9449 §8/§9
// handshake the HTTP mode emits. This is NOT a per-cause oracle leak: it is
// protocol-REQUIRED for the client to reissue a nonce-bound proof, and
// without it a DPoP client behind a mesh-only deployment could never recover
// after a nonce expiry (the fresh nonce lives only in the seam's unexported
// challengeHeader, unreadable over gRPC). Every OTHER deny cause still
// collapses to invalid_token / a bare challenge with NO DPoP-Nonce, so
// binding/validity/residency stay non-probeable.
func denyResponse(res sso.MeshAuthorizeResult) *authv3.CheckResponse {
	headers := make([]*corev3.HeaderValueOption, 0, 2)

	// DPoP nonce handshake: surface the fresh nonce + the use_dpop_nonce
	// challenge so a mesh-only DPoP client can reissue (matching HTTP mode).
	// DPoPNonce != "" IS the signal for this case.
	challengeCode := res.DenyCode
	if res.DPoPNonce != "" {
		challengeCode = sso.ErrUseDPoPNonce
		headers = append(headers, &corev3.HeaderValueOption{
			Header: &corev3.HeaderValue{
				Key:   sso.HeaderDPoPNonce,
				Value: res.DPoPNonce,
			},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}
	headers = append(headers, &corev3.HeaderValueOption{
		Header: &corev3.HeaderValue{
			Key:   "WWW-Authenticate",
			Value: bearerChallenge(challengeCode),
		},
		AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
	})

	return &authv3.CheckResponse{
		// The grpc-status carries the authorization verdict; this is the
		// field Envoy reads to ALLOW vs DENY. PERMISSION_DENIED == DENY.
		Status: &rpcstatus.Status{Code: int32(codes.PermissionDenied)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status:  &typev3.HttpStatus{Code: typev3.StatusCode_Unauthorized},
				Headers: headers,
				// No body — oracle-safe. Envoy returns the 401 + challenge.
				Body: "",
			},
		},
	}
}

// bearerChallenge renders the WWW-Authenticate value for a DENY, mirroring
// the core setBearerChallenge shape (RFC 6750 §3). realm is fixed to "sso"
// to match the server default (setBearerChallenge defaults an empty realm
// to "sso"); the mesh ext_authz path never sets a custom realm. An empty
// denyCode (missing credentials) yields a bare challenge with no error=.
func bearerChallenge(denyCode string) string {
	const realm = `Bearer realm="sso"`
	if denyCode == "" {
		return realm
	}
	return realm + `, error="` + denyCode + `"`
}
