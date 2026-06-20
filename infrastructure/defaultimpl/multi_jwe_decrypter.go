package defaultimpl

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/security"
)

// MultiJWEDecrypter composes several [security.JWEDecrypter]s and routes
// each encrypted JAR request object to the one owning its JWE `alg`, so
// an AS can accept both RSA (RSA-OAEP-256) and EC (ECDH-ES) encrypted
// request objects. Delegates that also publish a key ([sso.JWKSProvider])
// have their enc keys aggregated into one JWKS document, so RPs see every
// key they may encrypt to. SupportedAlgs/Encs union the delegates'.
//
// Implements [security.JWEDecrypter] and [sso.JWKSProvider].
type MultiJWEDecrypter struct {
	byAlg         map[string]security.JWEDecrypter
	algs          []string
	encs          []string
	jwksProviders []sso.JWKSProvider
}

// NewMultiJWEDecrypter composes decrypters, routing by alg. Panics if two
// delegates claim the same alg (ambiguous routing) — an unrecoverable
// wiring mistake surfaced at boot.
func NewMultiJWEDecrypter(decrypters ...security.JWEDecrypter) *MultiJWEDecrypter {
	m := &MultiJWEDecrypter{byAlg: map[string]security.JWEDecrypter{}}
	encSeen := map[string]struct{}{}
	for _, d := range decrypters {
		if d == nil {
			continue
		}
		for _, a := range d.SupportedAlgs() {
			if _, dup := m.byAlg[a]; dup {
				panic(fmt.Sprintf("MultiJWEDecrypter: alg %q claimed by two decrypters", a))
			}
			m.byAlg[a] = d
			m.algs = append(m.algs, a)
		}
		for _, e := range d.SupportedEncs() {
			if _, dup := encSeen[e]; dup {
				continue
			}
			encSeen[e] = struct{}{}
			m.encs = append(m.encs, e)
		}
		if p, ok := d.(sso.JWKSProvider); ok {
			m.jwksProviders = append(m.jwksProviders, p)
		}
	}
	return m
}

var (
	_ security.JWEDecrypter = (*MultiJWEDecrypter)(nil)
	_ sso.JWKSProvider      = (*MultiJWEDecrypter)(nil)
)

// Decrypt routes to the delegate owning the JWE's `alg` (read from the
// protected header without verifying). An unroutable alg errors; the
// caller collapses it to invalid_request_object (no oracle).
func (m *MultiJWEDecrypter) Decrypt(ctx context.Context, jwe string) ([]byte, error) {
	alg, ok := jweHeaderAlg(jwe)
	if !ok {
		return nil, errors.New("multi_jwe: cannot read JWE alg header")
	}
	d, ok := m.byAlg[alg]
	if !ok {
		return nil, fmt.Errorf("multi_jwe: no decrypter for alg %q", alg)
	}
	return d.Decrypt(ctx, jwe)
}

// SupportedAlgs returns the union of the delegates' algs.
func (m *MultiJWEDecrypter) SupportedAlgs() []string { return m.algs }

// SupportedEncs returns the union of the delegates' encs.
func (m *MultiJWEDecrypter) SupportedEncs() []string { return m.encs }

// JWKS aggregates the enc keys of delegates that publish one.
func (m *MultiJWEDecrypter) JWKS(ctx context.Context) ([]sso.JWK, error) {
	var out []sso.JWK
	for _, p := range m.jwksProviders {
		ks, err := p.JWKS(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, ks...)
	}
	return out, nil
}

// jweHeaderAlg reads the `alg` from a JWE compact serialization's
// protected header (the first dot-separated segment) without decrypting
// or verifying anything — a cheap routing pre-read.
func jweHeaderAlg(compact string) (string, bool) {
	i := strings.IndexByte(compact, '.')
	if i <= 0 {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(compact[:i])
	if err != nil {
		return "", false
	}
	var h struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(raw, &h); err != nil || h.Alg == "" {
		return "", false
	}
	return h.Alg, true
}
