//go:build no_kms_awskms

// Package awskms is stubbed out when compiled with -tags no_kms_awskms.
// Every exported function returns [ErrExcluded].
package awskms

import (
	"crypto"
	"errors"
	"io"
)

// ErrExcluded is returned by every constructor.
var ErrExcluded = errors.New("awskms: excluded by build tag no_kms_awskms — rebuild without -tags no_kms_awskms to use AWS KMS")

// Signer is a stub that implements crypto.Signer but returns ErrExcluded.
type Signer struct{}

// New returns ErrExcluded.
func New(_ interface{ Sign(any, any) }, _ string) (*Signer, error) {
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

var _ crypto.Signer = (*Signer)(nil)
