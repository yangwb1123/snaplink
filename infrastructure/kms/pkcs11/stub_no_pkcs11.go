//go:build no_pkcs11

// Package pkcs11 is a stub that replaces the real PKCS#11 module when
// compiled with the `no_pkcs11` build tag. Every exported function returns
// [ErrExcluded] with a clear message, so consumers get a compile-time-safe
// stub instead of a CGO linker error.
//
// Use: go build -tags no_pkcs11 ./...
package pkcs11

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"

	"github.com/snaplink/sso/shared/core"
)

// ErrExcluded is returned by every constructor when the pkcs11 package
// is compiled with the no_pkcs11 build tag.
var ErrExcluded = errors.New("pkcs11: excluded by build tag no_pkcs11 — rebuild without -tags no_pkcs11 to use PKCS#11")

// Option mirrors the real build's Option (origin.go / signer.go) for
// build-tag API parity: code written against WithKeyOrigin(...) compiles
// unchanged under -tags no_pkcs11, it just has nothing to configure.
type Option func(*Signer)

// WithKeyOrigin is a no-op placeholder mirroring the real Option's shape;
// a no_pkcs11 build has no token to attest, so there is nothing to set.
func WithKeyOrigin(_ core.KeyOrigin) Option {
	return func(*Signer) {}
}

// WithKeyID is a no-op placeholder mirroring the real Option's shape; a
// no_pkcs11 build has no token to attest, so there is nothing to compare.
func WithKeyID(_ string) Option {
	return func(*Signer) {}
}

// Mechanism is a placeholder that mirrors the real type.
type Mechanism int

const (
	MechECDSA Mechanism = iota
	MeccRSAPKCS1v15
	MeccRSAPSS
	MechEdDSA
)

func (m Mechanism) String() string {
	return fmt.Sprintf("Mechanism(%d)", int(m))
}

// Session is a stub interface that mirrors the real Session.
type Session interface {
	Sign(mech Mechanism, keyHandle uint, data []byte) ([]byte, error)
	PublicKeyDER() ([]byte, error)
}

// Signer is a stub that implements crypto.Signer but returns ErrExcluded
// from every method.
type Signer struct{}

// NewSigner returns ErrExcluded.
func NewSigner(_ Session, _ uint, _ crypto.PublicKey, _ ...Option) (*Signer, error) {
	return nil, ErrExcluded
}

// Public returns nil.
func (s *Signer) Public() crypto.PublicKey { return nil }

// PublicKey returns ErrExcluded.
func (s *Signer) PublicKey() (crypto.PublicKey, error) { return nil, ErrExcluded }

// Sign returns ErrExcluded.
func (s *Signer) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, ErrExcluded
}

// KeyOrigin returns ErrExcluded: a no_pkcs11 build has no token to attest,
// so it cannot implement core.KeyOriginProvider beyond this placeholder.
func (s *Signer) KeyOrigin(_ context.Context, _ string) (core.KeyOrigin, error) {
	return core.OriginUnknown, ErrExcluded
}

// Config holds the PKCS#11 token connection parameters. When the no_pkcs11
// build tag is set, it is a placeholder — New returns ErrExcluded regardless
// of the Config values.
type Config struct {
	ModulePath string
	TokenLabel string
	PIN        string
	KeyLabel   string
}

// New returns ErrExcluded when compiled with -tags no_pkcs11.
func New(_ Config, _ ...Option) (*Signer, error) {
	return nil, ErrExcluded
}

// Close is a no-op stub.
func (s *Signer) Close() error { return nil }

// Interface guards: Signer implements crypto.Signer for type compatibility,
// and (per the placeholder KeyOrigin above) core.KeyOriginProvider.
var (
	_ crypto.Signer          = (*Signer)(nil)
	_ core.KeyOriginProvider = (*Signer)(nil)
)
