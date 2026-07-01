//go:build no_pkcs11

// Package pkcs11 is a stub that replaces the real PKCS#11 module when
// compiled with the `no_pkcs11` build tag. Every exported function returns
// [ErrExcluded] with a clear message, so consumers get a compile-time-safe
// stub instead of a CGO linker error.
//
// Use: go build -tags no_pkcs11 ./...
package pkcs11

import (
	"crypto"
	"errors"
	"fmt"
	"io"
)

// ErrExcluded is returned by every constructor when the pkcs11 package
// is compiled with the no_pkcs11 build tag.
var ErrExcluded = errors.New("pkcs11: excluded by build tag no_pkcs11 — rebuild without -tags no_pkcs11 to use PKCS#11")

// Mechanism is a placeholder that mirrors the real type.
type Mechanism int

const (
	MechECDSA        Mechanism = iota
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
func NewSigner(_ Session, _ uint, _ crypto.PublicKey) (*Signer, error) {
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
func New(_ Config) (*Signer, error) {
	return nil, ErrExcluded
}

// Close is a no-op stub.
func (s *Signer) Close() error { return nil }

// Interface guard: Signer implements crypto.Signer for type compatibility.
var _ crypto.Signer = (*Signer)(nil)
