//go:build no_kms_azurekeyvault

// Package azurekeyvault is stubbed out when compiled with -tags no_kms_azurekeyvault.
package azurekeyvault

import (
	"crypto"
	"errors"
	"io"
)

// ErrExcluded is returned by every constructor.
var ErrExcluded = errors.New("azurekeyvault: excluded by build tag no_kms_azurekeyvault — rebuild without -tags no_kms_azurekeyvault to use Azure Key Vault")

// Signer is a stub that implements crypto.Signer but returns ErrExcluded.
type Signer struct{}

// New returns ErrExcluded.
func New(_ string, _ any) (*Signer, error) {
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
