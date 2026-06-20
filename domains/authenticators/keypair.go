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

	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/security"
	"github.com/snaplink/sso/shared/spi"
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
// public key. The bounded timestamp/clock-skew window alone does NOT stop
// replay: the SAME (key_id, nonce, timestamp) tuple can be resubmitted within
// that window. Wire [WithKeyPairNonceStore] to close that hole — it records
// each accepted nonce in a [security.JTIReplayStore] and rejects a second
// sighting. Without it, the prior bounded-window-only behavior is unchanged.
type KeyPairAuthenticator struct {
	resolver     PublicKeyResolver
	maxClockSkew time.Duration
	// nonceStore is optional. When wired, a verified nonce that has been
	// seen before within its window is rejected as a replay; nil keeps the
	// historical bounded-window-only behavior (byte-identical).
	nonceStore security.JTIReplayStore
	logger     spi.Logger // optional; surfaces fail-open nonce-store errors only
}

// KeyPairOption configures a KeyPairAuthenticator at construction. Most
// deployments need none — the bounded clock-skew window covers honest clients.
type KeyPairOption func(*KeyPairAuthenticator)

// WithKeyPairNonceStore wires an optional replay-defense store. After the
// Ed25519 signature AND the timestamp window both verify, the accepted nonce
// is recorded against the store; a nonce already seen within its window is
// rejected (the SAME signed request can no longer be replayed inside the
// clock-skew window). The store reuses the existing [security.JTIReplayStore]
// SPI — a nonce is just another "have I seen this key before" check — so any
// memory/sqlite/redis JTI backend works unchanged.
//
// FAIL-OPEN on store error: a degraded replay-defense backend must not turn a
// cryptographically valid login into a failure (it is logged via
// [WithKeyPairLogger] for ops visibility, matching the JTI-replay default
// across this repo). A nil store — or simply not passing this option — keeps
// the historical bounded-window-only behavior.
func WithKeyPairNonceStore(store security.JTIReplayStore) KeyPairOption {
	return func(k *KeyPairAuthenticator) { k.nonceStore = store }
}

// WithKeyPairLogger attaches an optional logger used only to surface a
// malfunctioning nonce store (the replay check stays fail-open: the logger
// never changes the auth outcome). A nil logger keeps the prior silent
// behavior.
func WithKeyPairLogger(l spi.Logger) KeyPairOption {
	return func(k *KeyPairAuthenticator) { k.logger = l }
}

func NewKeyPairAuthenticator(resolver PublicKeyResolver, maxClockSkew time.Duration, opts ...KeyPairOption) *KeyPairAuthenticator {
	if maxClockSkew <= 0 {
		maxClockSkew = DefaultKeyPairClockSkew
	}
	k := &KeyPairAuthenticator{resolver: resolver, maxClockSkew: maxClockSkew}
	for _, opt := range opts {
		opt(k)
	}
	return k
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

	// Replay defense runs ONLY on an otherwise-valid request (signature +
	// timestamp window both passed). Key the nonce by key_id so two clients
	// can't collide on a shared nonce string, and anchor the entry's expiry
	// to the clock-skew window — past it the timestamp gate rejects anyway,
	// so there is no value in remembering the nonce longer. FAIL-OPEN: a
	// store error is logged but never blocks a cryptographically valid login.
	if k.nonceStore != nil {
		nonceKey := keyID + keyPairMessageSeparator + nonce
		firstSighting, err := k.nonceStore.MarkSeen(ctx, nonceKey, ts.Add(k.maxClockSkew))
		switch {
		case err != nil:
			if k.logger != nil {
				k.logger.Error("keypair nonce store failed (allowing)", "key_id", keyID, "error", err)
			}
		case !firstSighting:
			return nil, errors.New("keypair: nonce replay detected")
		}
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
