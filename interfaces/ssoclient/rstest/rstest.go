// Package rstest provides in-process fixtures for testing consumers of the
// rs resource-server SDK: a real Ed25519 signing issuer plus an httptest
// JWKS endpoint, so RS tests exercise genuine signature verification without
// starting the whole SSO server. (It lives beside rs/ rather than under it —
// the repo caps directory depth at 3.)
package rstest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/shared/core"
)

// accessTokenTyp is the RFC 9068 header typ the fixture stamps — the same
// value the production issuers stamp, so rs's strict typ gate passes.
const accessTokenTyp = "at+jwt"

// defaultTokenTTL keeps fixture tokens comfortably valid for a test's
// lifetime while still expiring fast enough that a leaked fixture token is
// worthless.
const defaultTokenTTL = 5 * time.Minute

// Issuer is a minimal token-minting fixture: a real defaultimpl Ed25519
// issuer with its JWKS served over an httptest server that supports
// ETag/If-None-Match revalidation (like the real AS, and required to
// exercise the rs JWKS cache's 304 path).
type Issuer struct {
	// JWT is the underlying signing issuer, exposed for tests needing
	// rotation or direct SignJWT access.
	JWT *defaultimpl.Ed25519JWTIssuer

	srv      *httptest.Server
	jwksHits int64
	notMod   int64
}

// NewIssuer builds the fixture and starts its JWKS server. Callers own the
// lifecycle: defer Close.
func NewIssuer() (*Issuer, error) {
	jwt := defaultimpl.NewEd25519JWTIssuer()
	keys, err := jwt.JWKS(context.Background())
	if err != nil {
		return nil, fmt.Errorf("rstest: jwks: %w", err)
	}
	body, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		return nil, fmt.Errorf("rstest: jwks marshal: %w", err)
	}
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:8]) + `"`

	i := &Issuer{JWT: jwt}
	mux := http.NewServeMux()
	mux.HandleFunc(core.PathJWKS, func(w http.ResponseWriter, r *http.Request) {
		i.jwksHits++
		if r.Header.Get("If-None-Match") == etag {
			i.notMod++
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", etag)
		_, _ = w.Write(body)
	})
	i.srv = httptest.NewServer(mux)
	return i, nil
}

// URL is the issuer base URL — use it as both rs.Config.Issuer and the `iss`
// claim (MintAccessToken stamps it by default).
func (i *Issuer) URL() string { return i.srv.URL }

// JWKSURL is the served JWKS document URL, for rs.NewJWKSCache.
func (i *Issuer) JWKSURL() string { return i.srv.URL + core.PathJWKS }

// JWKSHits returns (total fetches, 304 revalidations) observed by the JWKS
// endpoint — lets cache tests assert the ETag path without another server.
func (i *Issuer) JWKSHits() (total, notModified int64) { return i.jwksHits, i.notMod }

// MintAccessToken signs an at+jwt access token over the given claims,
// filling iss/iat/exp defaults when the caller did not set them. The claims
// map is the raw payload — tests craft wrong-aud, expired, or cnf-bound
// tokens by setting those members directly.
func (i *Issuer) MintAccessToken(claims map[string]any) (string, error) {
	merged := make(map[string]any, len(claims)+3)
	for k, v := range claims {
		merged[k] = v
	}
	now := time.Now()
	if _, ok := merged["iss"]; !ok {
		merged["iss"] = i.URL()
	}
	if _, ok := merged["iat"]; !ok {
		merged["iat"] = now.Unix()
	}
	if _, ok := merged["exp"]; !ok {
		merged["exp"] = now.Add(defaultTokenTTL).Unix()
	}
	return i.JWT.SignJWT(context.Background(), accessTokenTyp, merged)
}

// Close stops the JWKS server.
func (i *Issuer) Close() { i.srv.Close() }
