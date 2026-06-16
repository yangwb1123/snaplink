package authenticators

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/security"
	"github.com/snaplink/sso/spi"
)

// TOTP implements RFC 6238 "Time-based One-Time Password Algorithm".
//
// The same primitive every Authenticator app (Google Authenticator,
// 1Password, Authy, etc.) speaks. A shared secret is provisioned once
// (typically via QR code containing an `otpauth://` URI); the client
// derives a 6-digit code from `HMAC-SHA1(secret, floor(now / 30s))`
// every step. The server validates by computing the same code and
// comparing.
//
// This implementation:
//   - 6-digit codes (the universal default).
//   - 30-second time step.
//   - ±1 step skew tolerated (common practice — covers caller-server
//     clock drift up to ~30s in either direction).
//   - HMAC-SHA1 (RFC 6238 §1.2 mandates support; SHA-256 / SHA-512
//     variants are listed but most authenticator apps don't speak them).
//   - Constant-time code comparison (subtle.ConstantTimeCompare) so
//     timing oracles can't sniff which digit position diverged first.
//
// What this implementation does only when wired:
//   - Per-user code-reuse defense. By default a code is valid for one
//     full step window and replays inside that window succeed. Operators
//     that need strict one-time semantics wire [WithTOTPConsumedStore]:
//     it records each accepted (user, step) pair in a
//     [security.JTIReplayStore] and rejects a second use of the same code.
//
// What this implementation deliberately doesn't do:
//   - HOTP (counter-based). TOTP is the universal choice for human MFA.

// TOTPStore retrieves a user's TOTP shared secret. Implementations
// MUST return the secret as raw bytes (NOT the base32-encoded form
// shown in QR codes); decode at the storage layer. Empty secret ==
// the user hasn't enrolled in TOTP, which the authenticator treats
// as authentication failure.
type TOTPStore interface {
	GetSecret(ctx context.Context, userID string) ([]byte, error)
}

// TOTPStoreFunc adapts a function to the TOTPStore interface.
type TOTPStoreFunc func(ctx context.Context, userID string) ([]byte, error)

func (f TOTPStoreFunc) GetSecret(ctx context.Context, userID string) ([]byte, error) {
	return f(ctx, userID)
}

// MemoryTOTPStore is an in-process [TOTPStore] for tests and demos.
// Production deployments need a backend that survives a restart and
// is encrypted-at-rest — TOTP secrets are MUST-encrypt material.
type MemoryTOTPStore struct {
	mu      sync.Mutex
	secrets map[string][]byte
}

func NewMemoryTOTPStore() *MemoryTOTPStore {
	return &MemoryTOTPStore{secrets: make(map[string][]byte)}
}

// Set assigns a shared secret to userID. Caller-supplied bytes are
// copied so post-Set mutation doesn't leak into stored state.
func (m *MemoryTOTPStore) Set(userID string, secret []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(secret))
	copy(cp, secret)
	m.secrets[userID] = cp
}

func (m *MemoryTOTPStore) GetSecret(_ context.Context, userID string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.secrets[userID]
	if !ok {
		return nil, ErrTOTPNoSecret
	}
	cp := make([]byte, len(s))
	copy(cp, s)
	return cp, nil
}

// ErrTOTPNoSecret is returned by TOTPStore when the supplied userID
// has no enrollment record. Authenticator collapses every failure
// case to a generic "invalid code" on the wire so a probe can't
// distinguish "user not enrolled" from "wrong code".
var ErrTOTPNoSecret = errors.New("totp: no secret for user")

// TOTPAuthenticator implements [sso.Authenticator] backed by a
// TOTPStore. Credential map MUST contain "username" + "code".
type TOTPAuthenticator struct {
	store TOTPStore
	// step is the time window per code. RFC 6238 §4 mandates 30s
	// as the default and ALL deployed authenticator apps assume it;
	// changing this breaks interop with end-user devices.
	step time.Duration
	// skewSteps tolerates ±N steps of clock drift between the
	// caller and the server. 1 = ±30s tolerance.
	skewSteps int
	// digits is the code length. RFC 6238 supports 6-8; we hardcode
	// 6 because that's universal and changing it breaks QR-code
	// auto-provisioning expectations.
	digits int
	// consumedStore is optional. When wired, the matched (user, step) is
	// recorded after a code verifies; a second use of that same code is
	// rejected. nil keeps the default behavior (a code stays valid for its
	// full window — replays inside it succeed).
	consumedStore security.JTIReplayStore
	logger        spi.Logger // optional; surfaces fail-open consumed-store errors only
}

// TOTPOption tunes the constructor. Most deployments need none.
type TOTPOption func(*TOTPAuthenticator)

// WithTOTPSkew overrides the ±step tolerance. Default 1. Set to 0
// for strict no-drift environments; >2 increases attacker brute-
// force window proportionally.
func WithTOTPSkew(steps int) TOTPOption {
	return func(t *TOTPAuthenticator) { t.skewSteps = steps }
}

// WithTOTPConsumedStore wires an optional one-time-use store. After a code
// verifies, the matched (userID, step) is recorded; a prior consume of that
// same (userID, step) makes the code unusable for the rest of its window —
// the strict one-time semantics RFC 6238 §5.2 RECOMMENDS. It reuses the
// existing [security.JTIReplayStore] SPI (a consumed (user, step) is just
// another "have I seen this key before" check), so any memory/sqlite/redis
// JTI backend works unchanged.
//
// Fail behavior is deliberately asymmetric: a CONFIRMED prior consume is
// fail-CLOSED (reject — the entire point of the option is to deny reuse),
// while a store ERROR is fail-OPEN (log via [WithTOTPLogger] + allow — a
// degraded backend must not lock out users holding a valid code), matching
// the JTI-replay default across this repo. A nil store — or simply not
// passing this option — keeps the default window-reuse behavior.
func WithTOTPConsumedStore(store security.JTIReplayStore) TOTPOption {
	return func(t *TOTPAuthenticator) { t.consumedStore = store }
}

// WithTOTPLogger attaches an optional logger used only to surface a
// malfunctioning consumed store (the fail-open path; a confirmed prior
// consume rejects regardless). A nil logger keeps the prior silent behavior.
func WithTOTPLogger(l spi.Logger) TOTPOption {
	return func(t *TOTPAuthenticator) { t.logger = l }
}

// NewTOTPAuthenticator constructs a TOTP authenticator backed by the
// supplied store.
func NewTOTPAuthenticator(store TOTPStore, opts ...TOTPOption) *TOTPAuthenticator {
	t := &TOTPAuthenticator{
		store:     store,
		step:      30 * time.Second,
		skewSteps: 1,
		digits:    6,
	}
	for _, opt := range opts {
		opt(t)
	}
	return t
}

func (t *TOTPAuthenticator) Name() string             { return MethodTOTP }
func (t *TOTPAuthenticator) LoginURL(_ string) string { return "" }

func (t *TOTPAuthenticator) Authenticate(ctx context.Context, req *sso.AuthRequest) (*sso.AuthResult, error) {
	username := req.Credential["username"]
	code := strings.TrimSpace(req.Credential["code"])
	if username == "" || code == "" {
		return nil, errors.New("totp: username and code required")
	}
	secret, err := t.store.GetSecret(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("totp: %w", err)
	}
	if len(secret) == 0 {
		return nil, errors.New("totp: empty secret")
	}
	now := time.Now()
	matchedStep, ok := t.verifyCodeStep(secret, code, now)
	if !ok {
		return nil, errors.New("totp: invalid code")
	}

	// One-time-use enforcement runs ONLY on an already-valid code. Key by
	// (userID, matched step) so the SAME code can't be replayed inside its
	// window, yet the NEXT step's distinct code still authenticates. The
	// entry expires one full step past the matched window (covers the +skew
	// edge), after which the code is naturally stale. A confirmed prior
	// consume is fail-CLOSED (reject); a store error is fail-OPEN (allow).
	if t.consumedStore != nil {
		consumedKey := subjectPrefixTOTPConsumed + username + keyPairMessageSeparator + strconv.FormatInt(matchedStep, 10)
		expiresAt := time.Unix((matchedStep+int64(t.skewSteps)+1)*int64(t.step.Seconds()), 0)
		firstSighting, mErr := t.consumedStore.MarkSeen(ctx, consumedKey, expiresAt)
		switch {
		case mErr != nil:
			if t.logger != nil {
				t.logger.Error("totp consumed store failed (allowing)", "username", username, "error", mErr)
			}
		case !firstSighting:
			return nil, errors.New("totp: code already used")
		}
	}

	return &sso.AuthResult{
		UserID:      username,
		Provider:    t.Name(),
		AuthMethods: []string{AuthMethodOTP},
	}, nil
}

func (t *TOTPAuthenticator) Callback(_ context.Context, _ *sso.CallbackState) (*sso.AuthResult, error) {
	return nil, errors.New("totp: callback not supported")
}

// VerifyCode reports whether code is a valid TOTP for secret at the current
// time, honoring the authenticator's configured skew window. It does NOT touch
// the store — it exists for the self-service enrollment confirm step, which
// must prove possession of a freshly generated (not-yet-persisted) secret
// before it is committed. Login-time verification stays on Authenticate.
func (t *TOTPAuthenticator) VerifyCode(secret []byte, code string) bool {
	return t.verifyCodeWithSkew(secret, strings.TrimSpace(code), time.Now())
}

// verifyCodeWithSkew checks the supplied 6-digit code against the
// expected TOTP for `now`, including ±skewSteps of clock drift.
// Constant-time comparison on every candidate so a code that
// matches step `now-1` doesn't take measurably longer to validate
// than one that matches step `now`.
func (t *TOTPAuthenticator) verifyCodeWithSkew(secret []byte, code string, now time.Time) bool {
	_, ok := t.verifyCodeStep(secret, code, now)
	return ok
}

// verifyCodeStep is verifyCodeWithSkew that additionally returns the step
// counter the code matched, so one-time-use enforcement can key the consumed
// store by the exact window the code belongs to. Like verifyCodeWithSkew it
// never breaks early — the full ±skew loop runs so timing reveals nothing
// about WHICH step matched. matchedStep is meaningful only when ok is true.
func (t *TOTPAuthenticator) verifyCodeStep(secret []byte, code string, now time.Time) (matchedStep int64, ok bool) {
	if len(code) != t.digits {
		return 0, false
	}
	stepCounter := now.Unix() / int64(t.step.Seconds())
	want := []byte(code)
	for offset := -t.skewSteps; offset <= t.skewSteps; offset++ {
		candidate := stepCounter + int64(offset)
		expected := hotp(secret, candidate, t.digits)
		if subtle.ConstantTimeCompare([]byte(expected), want) == 1 {
			matchedStep = candidate
			ok = true
			// Don't break — finish the loop so timing reveals no
			// information about WHICH step matched.
		}
	}
	return matchedStep, ok
}

// hotp computes the RFC 4226 HMAC-Based One-Time Password — the
// primitive RFC 6238 §4.2 wraps with a time-step counter. Pure
// stdlib (sha1 + hmac); no third-party crypto.
func hotp(secret []byte, counter int64, digits int) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))
	m := hmac.New(sha1.New, secret)
	m.Write(buf[:])
	hash := m.Sum(nil)
	// Dynamic truncation per RFC 4226 §5.3.
	offset := hash[len(hash)-1] & 0x0f
	binCode := (uint32(hash[offset])&0x7f)<<24 |
		(uint32(hash[offset+1])&0xff)<<16 |
		(uint32(hash[offset+2])&0xff)<<8 |
		(uint32(hash[offset+3]) & 0xff)
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	code := binCode % mod
	return fmt.Sprintf("%0*d", digits, code)
}

// GenerateTOTPSecret mints a fresh shared secret suitable for QR-
// code distribution. RFC 6238 §5.1 recommends ≥160 bits; we emit
// 160 bits (20 bytes) which matches the SHA-1 block size + matches
// Google Authenticator's default. Returns the raw bytes — callers
// that need to render a QR code call EncodeTOTPSecret for the
// base32 form.
func GenerateTOTPSecret() ([]byte, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("totp: gen secret: %w", err)
	}
	return buf, nil
}

// EncodeTOTPSecret produces the base32-no-pad form that
// `otpauth://` URIs use for the `secret=` field. Matches the
// universal authenticator-app convention.
func EncodeTOTPSecret(secret []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
}

// OTPAuthURL renders the `otpauth://totp/<issuer>:<account>?secret=...&...`
// URI that QR-code generators consume to provision an authenticator
// app. The `issuer` and `account` are displayed in the user's app
// (e.g. "Acme Corp" + "alice@example.com").
func OTPAuthURL(issuer, account string, secret []byte) string {
	v := url.Values{}
	v.Set("secret", EncodeTOTPSecret(secret))
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", "6")
	v.Set("period", "30")
	label := url.PathEscape(issuer + ":" + account)
	return "otpauth://totp/" + label + "?" + v.Encode()
}
