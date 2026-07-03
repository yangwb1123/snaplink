package rs

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/snaplink/sso/shared/security"
)

// claimsCtxKey is unexported so only NewContext can install claims — a
// handler can never be tricked by a value smuggled in from outside.
type claimsCtxKey struct{}

// NewContext returns ctx carrying validated claims. Exposed for tests and
// for adapters wrapping other frameworks around this package.
func NewContext(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, claimsCtxKey{}, c)
}

// ClaimsFromContext retrieves the claims HTTPMiddleware validated for this
// request. ok is false on requests that did not pass through the middleware.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(claimsCtxKey{}).(*Claims)
	return c, ok
}

// HTTPMiddleware protects next with token validation. Bearer and DPoP
// schemes are both accepted; a DPoP-schemed request (or one carrying a DPoP
// proof header) takes the RFC 9449 path, and a cnf.jkt-bound token presented
// as plain Bearer is REJECTED — the sender-constraint must be enforced, not
// silently skipped (RFC 9449 §7.1).
//
// Failures answer 401 with the standard WWW-Authenticate challenge: a
// request with no credentials gets the bare scheme (no error attribute, per
// RFC 6750 §3.1); a failed validation gets error="invalid_token" plus a
// category-only description — the detailed cause never crosses the wire, so
// the challenge cannot become a token-validation oracle. 401s are never
// cacheable.
//
// On success the claims ride the request context — read them downstream with
// ClaimsFromContext.
func HTTPMiddleware(cfg Config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, viaDPoP := extractToken(r)
		if token == "" {
			writeChallenge(w, nil, viaDPoP, cfg)
			return
		}
		claims, err := validateRequest(r, token, viaDPoP, cfg)
		if err != nil {
			writeChallenge(w, err, viaDPoP || r.Header.Get(headerDPoP) != "", cfg)
			return
		}
		next.ServeHTTP(w, r.WithContext(NewContext(r.Context(), claims)))
	})
}

// validateRequest routes a request to the DPoP or plain path.
func validateRequest(r *http.Request, token string, viaDPoP bool, cfg Config) (*Claims, error) {
	proof := r.Header.Get(headerDPoP)
	if viaDPoP || proof != "" {
		return ValidateTokenWithDPoP(r.Context(), token, proof, r.Method, requestHTU(r), cfg)
	}
	claims, err := validateByMode(r.Context(), token, cfg)
	if err != nil {
		return nil, err
	}
	if claims.CnfJKT != "" {
		return nil, fmt.Errorf("%w: cnf-bound token requires a DPoP proof", ErrDPoPInvalid)
	}
	return claims, nil
}

// extractToken pulls the access token off the Authorization header,
// accepting the DPoP scheme first (RFC 9449 §7.1) and Bearer second.
func extractToken(r *http.Request) (token string, viaDPoP bool) {
	h := r.Header.Get(headerAuthorization)
	for _, scheme := range []string{schemeDPoP, schemeBearer} {
		prefix := scheme + " "
		if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
			return strings.TrimSpace(h[len(prefix):]), scheme == schemeDPoP
		}
	}
	return "", false
}

// requestHTU rebuilds the absolute request URL for DPoP htu comparison,
// honoring first-hop X-Forwarded-Proto/Host — ONLY safe behind a trusted
// edge that strips and re-sets them (the same trust model as the AS; see
// AGENTS.md "X-Forwarded-* Trust").
func requestHTU(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if h := r.Header.Get("X-Forwarded-Proto"); h != "" {
		scheme = h
	}
	host := r.Host
	if h := r.Header.Get("X-Forwarded-Host"); h != "" {
		host = h
	}
	return scheme + "://" + host + r.URL.Path
}

// writeChallenge emits the 401. err == nil means no credentials were
// presented at all.
func writeChallenge(w http.ResponseWriter, err error, usedDPoP bool, cfg Config) {
	h := w.Header()
	// Credential-bearing exchanges are never cacheable — same hygiene as
	// the AS's token endpoints, including on errors.
	h.Set(headerCacheControl, "no-store")
	h.Set(headerPragma, "no-cache")
	scheme := schemeBearer
	if usedDPoP {
		scheme = schemeDPoP
	}
	h.Set(headerWWWAuthenticate, challengeValue(scheme, err, cfg))
	if err == nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	h.Set(headerContentType, contentTypeJSON)
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"invalid_token"}`))
}

// challengeValue renders the WWW-Authenticate value. The DPoP scheme always
// advertises the accepted algs (RFC 9449 §7.1); attribute values go through
// security.QuoteAuthParam so a hostile token can never splice attributes
// into the header.
func challengeValue(scheme string, err error, cfg Config) string {
	var params []string
	if err != nil {
		params = append(params,
			"error="+security.QuoteAuthParam("invalid_token"),
			"error_description="+security.QuoteAuthParam(challengeDescription(err)))
	}
	if scheme == schemeDPoP {
		params = append(params, "algs="+security.QuoteAuthParam(strings.Join(cfg.allowedAlgValues(), " ")))
	}
	if len(params) == 0 {
		return scheme
	}
	return scheme + " " + strings.Join(params, ", ")
}

// challengeDescription collapses the error taxonomy to coarse categories:
// enough for a well-behaved client to react (refresh vs re-authenticate),
// never enough to probe why a stolen token failed.
func challengeDescription(err error) string {
	switch {
	case errors.Is(err, ErrTokenExpired):
		return "token expired"
	case errors.Is(err, ErrDPoPInvalid), errors.Is(err, ErrDPoPReplayed):
		return "invalid dpop proof"
	default:
		return "token validation failed"
	}
}
