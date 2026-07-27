package defaultjwe

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/core/corecredential"
	"github.com/yangwb1123/snaplink/shared/security"
)

// DefaultJWEKeyBits is the RSA modulus size RotatingJWEDecrypter mints when no
// initial key is supplied. 2048 matches the RSAJWEDecrypter cipher suite
// (RSA-OAEP-256) and is the FAPI 2.0 floor.
const DefaultJWEKeyBits = 2048

// RotatingJWEDecrypter is a rotatable [security.JWEDecrypter] for the AS's JWE
// request-object decryption key, plugged into the credential-rotation framework
// as a [corecredential.CompromiseRotator]. It composes RSAJWEDecrypter: the
// CURRENT key decrypts + is published in JWKS; after a routine rotation the
// PREVIOUS key stays accepted (and published) through an overlap window so
// in-flight PAR/JAR request objects encrypted to the old key still decrypt
// while RPs re-fetch JWKS. An emergency compromise (RotateCompromised) keeps NO
// overlap — the leaked key drops out of both the decrypt set and JWKS at once.
//
// The rotator IS the live decrypter (wire it via sso.WithJARDecrypter AND
// register it with the rotation.Registry) — Rotate installs the new key into
// the same object serving decryptions, the "install into the live consumer"
// pattern the CredentialRotator contract describes. Safe for concurrent use.
type RotatingJWEDecrypter struct {
	mu        sync.RWMutex
	kidPrefix string
	keyBits   int
	overlap   time.Duration

	version   int
	createdAt time.Time
	current   *RSAJWEDecrypter

	// previous is the demoted key, accepted (decrypt-only) + published in JWKS
	// until prevNotAfter. Nil outside an overlap window.
	previous     *RSAJWEDecrypter
	prevNotAfter time.Time
}

// NewRotatingJWEDecrypter seeds the holder at version 1. A nil initial key
// generates a fresh keyBits-bit RSA key (crypto/rand failure is the only
// error); a supplied key's size overrides keyBits for future rotations.
// kidPrefix defaults to "jwe-enc"; each version's JWKS kid is "<prefix>/vN".
func NewRotatingJWEDecrypter(initial *rsa.PrivateKey, kidPrefix string, keyBits int, overlap time.Duration) (*RotatingJWEDecrypter, error) {
	if keyBits <= 0 {
		keyBits = DefaultJWEKeyBits
	}
	if kidPrefix == "" {
		kidPrefix = "jwe-enc"
	}
	if initial == nil {
		var err error
		if initial, err = rsa.GenerateKey(rand.Reader, keyBits); err != nil {
			return nil, fmt.Errorf("rotating_jwe: generate initial key: %w", err)
		}
	} else {
		keyBits = initial.N.BitLen()
	}
	r := &RotatingJWEDecrypter{
		kidPrefix: kidPrefix,
		keyBits:   keyBits,
		overlap:   overlap,
		version:   1,
		createdAt: time.Now(),
	}
	dec, err := NewRSAJWEDecrypter(initial, r.kid(1))
	if err != nil {
		return nil, err
	}
	r.current = dec
	return r, nil
}

func (r *RotatingJWEDecrypter) kid(version int) string {
	return fmt.Sprintf("%s/v%d", r.kidPrefix, version)
}

var (
	_ security.JWEDecrypter             = (*RotatingJWEDecrypter)(nil)
	_ core.JWKSProvider                 = (*RotatingJWEDecrypter)(nil)
	_ corecredential.CredentialRotator  = (*RotatingJWEDecrypter)(nil)
	_ corecredential.CompromiseRotator  = (*RotatingJWEDecrypter)(nil)
	_ corecredential.DependencyReporter = (*RotatingJWEDecrypter)(nil)
)

// Decrypt unwraps a JWE request object with the current key, falling back to
// the demoted previous key within its overlap window. On both failing it
// returns the CURRENT key's error — never the previous key's — so a rejected
// caller learns nothing about the overlap state (oracle-safe; the caller
// collapses it to invalid_request_object regardless).
func (r *RotatingJWEDecrypter) Decrypt(ctx context.Context, jwe string) ([]byte, error) {
	r.mu.RLock()
	current, previous, prevNotAfter := r.current, r.previous, r.prevNotAfter
	r.mu.RUnlock()

	if current == nil {
		return nil, corecredential.ErrNoActiveCredential
	}
	plain, err := current.Decrypt(ctx, jwe)
	if err == nil {
		return plain, nil
	}
	if previous != nil && time.Now().Before(prevNotAfter) {
		if plain2, err2 := previous.Decrypt(ctx, jwe); err2 == nil {
			return plain2, nil
		}
	}
	return nil, err
}

// SupportedAlgs / SupportedEncs are fixed by the composed RSAJWEDecrypter's
// cipher suite — the previous key shares it, so rotation never changes them.
func (r *RotatingJWEDecrypter) SupportedAlgs() []string { return []string{"RSA-OAEP-256"} }
func (r *RotatingJWEDecrypter) SupportedEncs() []string { return []string{"A256GCM"} }

// JWKS publishes the current public encryption key plus, during an overlap
// window, the demoted previous one — so an RP that has not yet re-fetched can
// still encrypt to the key the AS is about to retire, until the window closes.
func (r *RotatingJWEDecrypter) JWKS(ctx context.Context) ([]core.JWK, error) {
	r.mu.RLock()
	current, previous := r.current, r.previous
	prevActive := previous != nil && time.Now().Before(r.prevNotAfter)
	r.mu.RUnlock()

	out, err := current.JWKS(ctx)
	if err != nil {
		return nil, err
	}
	if !prevActive {
		return out, nil
	}
	prev, err := previous.JWKS(ctx)
	if err != nil {
		return nil, err
	}
	return append(out, prev...), nil
}

// CurrentMeta reports the currently-installed version (rotation.CurrentMetaProvider,
// duck-typed to avoid an infrastructure->platform import) so the inventory shows
// it before the scheduler's first rotation fires.
func (r *RotatingJWEDecrypter) CurrentMeta() corecredential.CredentialMeta {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.metaFor(r.version, r.createdAt)
}

func (r *RotatingJWEDecrypter) metaFor(version int, createdAt time.Time) corecredential.CredentialMeta {
	return corecredential.CredentialMeta{
		ID:        r.kid(version),
		Type:      corecredential.CredentialTypeJWEDecryption,
		Version:   version,
		Status:    corecredential.CredentialStatusActive,
		CreatedAt: createdAt,
		Algorithm: "RSA-OAEP-256",
	}
}

// Type / OverlapWindow / Rotate / RotateCompromised / Dependents satisfy the
// rotation SPIs. Rotate keeps the overlap window; RotateCompromised drops it.
func (r *RotatingJWEDecrypter) Type() corecredential.CredentialType {
	return corecredential.CredentialTypeJWEDecryption
}
func (r *RotatingJWEDecrypter) OverlapWindow() time.Duration { return r.overlap }

func (r *RotatingJWEDecrypter) Rotate(context.Context) (corecredential.CredentialMeta, error) {
	return r.rotate(time.Now(), r.overlap)
}

func (r *RotatingJWEDecrypter) RotateCompromised(context.Context) (corecredential.CredentialMeta, error) {
	return r.rotate(time.Now(), 0)
}

// Dependents reports that rotating this key changes the published JWKS — RPs
// must re-fetch it before they can encrypt to the new key.
func (r *RotatingJWEDecrypter) Dependents() []corecredential.Dependency {
	return []corecredential.Dependency{corecredential.DependencyJWKS}
}

// rotate mints a fresh key and installs it, demoting the current key into the
// overlap window (overlap <= 0 drops it immediately). On generation/parse
// failure the state is untouched — the old key keeps serving, per the
// CredentialRotator contract.
func (r *RotatingJWEDecrypter) rotate(now time.Time, overlap time.Duration) (corecredential.CredentialMeta, error) {
	priv, err := rsa.GenerateKey(rand.Reader, r.keyBits)
	if err != nil {
		return corecredential.CredentialMeta{}, fmt.Errorf("rotating_jwe: generate key: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	nextVersion := r.version + 1
	dec, err := NewRSAJWEDecrypter(priv, r.kid(nextVersion))
	if err != nil {
		return corecredential.CredentialMeta{}, err
	}
	if overlap > 0 {
		r.previous = r.current
		r.prevNotAfter = now.Add(overlap)
	} else {
		r.previous = nil
		r.prevNotAfter = time.Time{}
	}
	r.current = dec
	r.version = nextVersion
	r.createdAt = now
	return r.metaFor(r.version, now), nil
}
