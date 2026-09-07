package authenticators

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/security"
	"github.com/yangwb1123/snaplink/shared/spi"
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
	s.entries[keyID] = publicKeyEntry{key: slices.Clone(key), subject: cloneSubject(subject)}
}

func (s *MemoryPublicKeyStore) Resolve(_ context.Context, keyID string) (ed25519.PublicKey, *sso.Subject, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[keyID]
	if !ok {
		return nil, nil, errors.New("keypair: unknown key_id")
	}
	return slices.Clone(e.key), cloneSubject(e.subject), nil
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
	creds, err := k.parseKeyPairCredentials(req)
	if err != nil {
		return nil, err
	}

	pub, subject, err := k.resolver.Resolve(ctx, creds.keyID)
	if err != nil {
		return nil, err
	}

	message := canonicalKeyPairMessage(creds.keyID, creds.nonce, creds.tsStr)
	if !ed25519.Verify(pub, message, creds.signature) {
		return nil, errors.New("keypair: signature verification failed")
	}

	if err := k.checkNonceReplay(ctx, creds); err != nil {
		return nil, err
	}

	if subject == nil {
		subject = &sso.Subject{ID: subjectPrefixKeyPair + creds.keyID}
	}
	return &sso.AuthResult{
		UserID:      subject.ID,
		ExternalID:  creds.keyID,
		Provider:    k.Name(),
		Attributes:  subject.Claims,
		AuthMethods: []string{AuthMethodSig},
	}, nil
}

// keyPairCredentials holds the parsed, window-validated request fields. ts is
// the parsed timestamp; signature is the decoded (raw-URL or std base64) blob.
type keyPairCredentials struct {
	keyID     string
	nonce     string
	tsStr     string
	ts        time.Time
	signature []byte
}

// parseKeyPairCredentials extracts the credential fields and enforces the
// timestamp clock-skew window BEFORE decoding the signature, then decodes it.
// Order is load-bearing: a stale timestamp is rejected ahead of any signature
// processing.
func (k *KeyPairAuthenticator) parseKeyPairCredentials(req *sso.AuthRequest) (keyPairCredentials, error) {
	keyID := req.Credential["key_id"]
	nonce := req.Credential["nonce"]
	tsStr := req.Credential["timestamp"]
	sigB64 := req.Credential["signature"]
	if keyID == "" || nonce == "" || tsStr == "" || sigB64 == "" {
		return keyPairCredentials{}, errors.New("keypair: key_id, nonce, timestamp, signature required")
	}

	tsUnix, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return keyPairCredentials{}, fmt.Errorf("keypair: invalid timestamp: %w", err)
	}
	ts := time.Unix(tsUnix, 0)
	if delta := time.Since(ts); delta > k.maxClockSkew || -delta > k.maxClockSkew {
		return keyPairCredentials{}, errors.New("keypair: timestamp outside allowed clock skew")
	}

	signature, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		// Tolerate standard base64 too.
		signature, err = base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			return keyPairCredentials{}, fmt.Errorf("keypair: signature not base64: %w", err)
		}
	}

	return keyPairCredentials{keyID: keyID, nonce: nonce, tsStr: tsStr, ts: ts, signature: signature}, nil
}

// checkNonceReplay runs ONLY on an otherwise-valid request (signature +
// timestamp window both passed). Key the nonce by key_id so two clients can't
// collide on a shared nonce string, and anchor the entry's expiry to the
// clock-skew window — past it the timestamp gate rejects anyway, so there is no
// value in remembering the nonce longer. FAIL-OPEN: a store error is logged but
// never blocks a cryptographically valid login. A nil store keeps the
// historical bounded-window-only behavior.
func (k *KeyPairAuthenticator) checkNonceReplay(ctx context.Context, creds keyPairCredentials) error {
	if k.nonceStore == nil {
		return nil
	}
	nonceKey := creds.keyID + keyPairMessageSeparator + creds.nonce
	firstSighting, err := k.nonceStore.MarkSeen(ctx, nonceKey, creds.ts.Add(k.maxClockSkew))
	switch {
	case err != nil:
		if k.logger != nil {
			k.logger.Error("keypair nonce store failed (allowing)", "key_id", creds.keyID, "error", err)
		}
	case !firstSighting:
		return errors.New("keypair: nonce replay detected")
	}
	return nil
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
