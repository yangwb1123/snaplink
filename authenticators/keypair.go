package authenticators

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/snaplink/sso"
)

// PublicKeyResolver looks up the registered Ed25519 public key for a key ID.
type PublicKeyResolver interface {
	Resolve(ctx context.Context, keyID string) (ed25519.PublicKey, *sso.Subject, error)
}

// MemoryPublicKeyStore is a process-local PublicKeyResolver.
type MemoryPublicKeyStore struct {
	mu      sync.RWMutex
	entries map[string]publicKeyEntry
}

type publicKeyEntry struct {
	key     ed25519.PublicKey
	subject *sso.Subject
}

func NewMemoryPublicKeyStore() *MemoryPublicKeyStore {
	return &MemoryPublicKeyStore{entries: make(map[string]publicKeyEntry)}
}

func (s *MemoryPublicKeyStore) Register(keyID string, key ed25519.PublicKey, subject *sso.Subject) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[keyID] = publicKeyEntry{key: key, subject: subject}
}

func (s *MemoryPublicKeyStore) Resolve(_ context.Context, keyID string) (ed25519.PublicKey, *sso.Subject, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[keyID]
	if !ok {
		return nil, nil, errors.New("keypair: unknown key_id")
	}
	return e.key, e.subject, nil
}

// KeyPairAuthenticator authenticates a client by verifying an Ed25519
// signature over a fresh nonce. Flow:
//
//	credentials = {
//	  key_id:    "<id of registered public key>",
//	  nonce:     "<random string supplied by client>",
//	  timestamp: "<unix seconds>",
//	  signature: "<base64(Sign(privKey, key_id|nonce|timestamp))>",
//	}
//
// The server replays the canonical message and verifies it against the stored
// public key. Replay protection is the caller's responsibility (compare nonce
// against a recent-nonce cache, reject stale timestamps).
type KeyPairAuthenticator struct {
	resolver  PublicKeyResolver
	maxClockSkew time.Duration
}

func NewKeyPairAuthenticator(resolver PublicKeyResolver, maxClockSkew time.Duration) *KeyPairAuthenticator {
	if maxClockSkew <= 0 {
		maxClockSkew = DefaultKeyPairClockSkew
	}
	return &KeyPairAuthenticator{resolver: resolver, maxClockSkew: maxClockSkew}
}

func (k *KeyPairAuthenticator) Name() string { return MethodKeyPair }

func (k *KeyPairAuthenticator) Authenticate(ctx context.Context, req *sso.AuthRequest) (*sso.AuthResult, error) {
	keyID := req.Credential["key_id"]
	nonce := req.Credential["nonce"]
	tsStr := req.Credential["timestamp"]
	sigB64 := req.Credential["signature"]
	if keyID == "" || nonce == "" || tsStr == "" || sigB64 == "" {
		return nil, errors.New("keypair: key_id, nonce, timestamp, signature required")
	}

	tsUnix, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("keypair: invalid timestamp: %w", err)
	}
	ts := time.Unix(tsUnix, 0)
	if delta := time.Since(ts); delta > k.maxClockSkew || -delta > k.maxClockSkew {
		return nil, errors.New("keypair: timestamp outside allowed clock skew")
	}

	signature, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		// Tolerate standard base64 too.
		signature, err = base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			return nil, fmt.Errorf("keypair: signature not base64: %w", err)
		}
	}

	pub, subject, err := k.resolver.Resolve(ctx, keyID)
	if err != nil {
		return nil, err
	}

	message := canonicalKeyPairMessage(keyID, nonce, tsStr)
	if !ed25519.Verify(pub, message, signature) {
		return nil, errors.New("keypair: signature verification failed")
	}

	if subject == nil {
		subject = &sso.Subject{ID: subjectPrefixKeyPair + keyID}
	}
	return &sso.AuthResult{
		UserID:      subject.ID,
		ExternalID:  keyID,
		Provider:    k.Name(),
		Attributes:  subject.Claims,
		AuthMethods: []string{AuthMethodSig},
	}, nil
}

func (k *KeyPairAuthenticator) Callback(_ context.Context, _ *sso.CallbackState) (*sso.AuthResult, error) {
	return nil, errors.New("keypair: callback not supported")
}

func (k *KeyPairAuthenticator) LoginURL(_ string) string { return "" }

// CanonicalKeyPairMessage returns the byte string a client must sign for a
// given (key_id, nonce, timestamp). Exposed so client SDKs can reproduce it.
func CanonicalKeyPairMessage(keyID, nonce, timestamp string) []byte {
	return canonicalKeyPairMessage(keyID, nonce, timestamp)
}

func canonicalKeyPairMessage(keyID, nonce, timestamp string) []byte {
	return []byte(keyID + keyPairMessageSeparator + nonce + keyPairMessageSeparator + timestamp)
}

// ParseEd25519PublicKeyPEM parses a PEM-encoded Ed25519 public key (PKIX format).
func ParseEd25519PublicKeyPEM(pemBytes []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("keypair: no PEM block found")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("keypair: parse PKIX: %w", err)
	}
	ed, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("keypair: not an Ed25519 public key")
	}
	return ed, nil
}
