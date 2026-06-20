package defaultimpl

import (
	"context"
	"fmt"

	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/security"
)

// MultiJWEResponseEncrypter composes several [security.JWEEncrypter]s and
// routes each Encrypt call to the one that supports the requested `alg`,
// so a server can offer both RSA (RSA-OAEP-256) and EC (ECDH-ES) response
// encryption simultaneously — different RPs register different key types.
// SupportedAlgs / SupportedEncs union the delegates' values so discovery
// advertises every offered suite.
//
// Implements [security.JWEEncrypter].
type MultiJWEResponseEncrypter struct {
	// byAlg maps each supported alg to its owning encrypter. Built once
	// at construction; a duplicate alg across delegates panics (an
	// unresolvable routing ambiguity, caught at startup).
	byAlg map[string]security.JWEEncrypter
	algs  []string
	encs  []string
}

// NewMultiJWEResponseEncrypter composes encrypters, routing by alg.
// Panics if two delegates claim the same alg (ambiguous routing) — an
// unrecoverable wiring mistake surfaced at boot.
func NewMultiJWEResponseEncrypter(encrypters ...security.JWEEncrypter) *MultiJWEResponseEncrypter {
	m := &MultiJWEResponseEncrypter{byAlg: map[string]security.JWEEncrypter{}}
	encSeen := map[string]struct{}{}
	for _, e := range encrypters {
		if e == nil {
			continue
		}
		for _, a := range e.SupportedAlgs() {
			if _, dup := m.byAlg[a]; dup {
				panic(fmt.Sprintf("MultiJWEResponseEncrypter: alg %q claimed by two encrypters", a))
			}
			m.byAlg[a] = e
			m.algs = append(m.algs, a)
		}
		for _, enc := range e.SupportedEncs() {
			if _, dup := encSeen[enc]; dup {
				continue
			}
			encSeen[enc] = struct{}{}
			m.encs = append(m.encs, enc)
		}
	}
	return m
}

var _ security.JWEEncrypter = (*MultiJWEResponseEncrypter)(nil)

// Encrypt routes to the delegate that supports alg. An unsupported alg
// returns an error the caller collapses on the wire (oracle-leak
// hardening), never distinguishing it from a crypto failure.
func (m *MultiJWEResponseEncrypter) Encrypt(ctx context.Context, plaintext []byte, recipientJWKS []core.JWK, alg, enc string) (string, error) {
	e, ok := m.byAlg[alg]
	if !ok {
		return "", fmt.Errorf("multi_jwe_enc: no encrypter for alg %q", alg)
	}
	return e.Encrypt(ctx, plaintext, recipientJWKS, alg, enc)
}

// SupportedAlgs returns the union of the delegates' algs.
func (m *MultiJWEResponseEncrypter) SupportedAlgs() []string { return m.algs }

// SupportedEncs returns the union of the delegates' encs.
func (m *MultiJWEResponseEncrypter) SupportedEncs() []string { return m.encs }
