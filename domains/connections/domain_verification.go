package connections

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// DomainStatus is the DNS-ownership state of one connection's claim on an email
// domain: a claim starts DomainPending and becomes DomainVerified once the
// challenge TXT record is observed (or, for boot-seeded connections, when the
// operator asserts it directly via Store.VerifyDomain).
type DomainStatus string

const (
	DomainPending  DomainStatus = "pending"
	DomainVerified DomainStatus = "verified"
)

// DomainVerification is one (connection, domain) ownership claim.
//
// Token is deliberately NOT a secret: the proof model is "you control the
// domain's DNS zone" (like ACME dns-01 / Let's Encrypt), and the operator must
// publish Token as a public TXT record at Record. It is therefore stored in the
// clear and surfaced to the admin in the per-connection listing — unlike the
// email-verification tokens in protocols/selfservice, which ARE bearer secrets
// and are hashed at rest. Never log it regardless (it is admin-scoped state).
type DomainVerification struct {
	ConnectionID string
	Domain       string
	Status       DomainStatus
	Token        string
	Record       string // DNS TXT record name to publish (derived: prefix + "." + domain)
	CreatedAt    time.Time
	VerifiedAt   time.Time // zero until Status == DomainVerified
}

// ErrNoDomainClaim is returned when a connection has never claimed the given
// domain (Upsert creates the claim the first time the domain appears in
// Connection.Domains). Distinct from ErrNoConnection so the admin verify
// endpoint can map it to a 404 without confusing it with a missing connection.
var ErrNoDomainClaim = errors.New("connections: no domain claim for connection")

// TokenBoundDomainVerifier is an optional Store capability for DNS-proof
// promotion. Implementations must compare token with the currently stored
// claim and promote that same claim atomically. A mismatch returns (false,
// nil); a missing claim returns ErrNoDomainClaim and storage failures are
// returned. It is optional so existing Store implementations remain source
// compatible, but VerifyDomainOwnership refuses unsafe token-free promotion.
type TokenBoundDomainVerifier interface {
	VerifyDomainWithToken(ctx context.Context, connID, domain, token string) (bool, error)
}

var errTokenBoundDomainVerificationUnsupported = errors.New("connections: token-bound domain verification unsupported")

// DefaultRecordPrefix is the DNS label prepended to a claimed domain to form the
// challenge TXT record name when StoreConfig.RecordPrefix is empty.
const DefaultRecordPrefix = "_snaplink-domain-verify"

// DefaultDomainVerificationTimeout bounds a single DNS TXT lookup so a slow or
// hung resolver cannot stall the admin request that triggered the check
// (mirrors federation's fetch-timeout role; a DNS lookup has no SSRF surface —
// no attacker-chosen host, no redirect — so bounding is the only hardening).
const DefaultDomainVerificationTimeout = 5 * time.Second

// StoreConfig is the optional behavior shared by every Store implementation
// (MemoryStore, sqlite.Store). Exported so a second package can apply the same
// StoreOptions without importing an unexported type.
type StoreConfig struct {
	// DomainVerificationRequired, when true, makes Upsert record a NEW or
	// reassigned domain claim as DomainPending WITHOUT taking over routing —
	// a competing already-verified owner keeps serving home-realm discovery
	// until the new claimant proves DNS control via VerifyDomain. The zero
	// value (false) preserves the historical last-write-wins Upsert behavior
	// byte-identically (claims are still recorded, auto-verified).
	DomainVerificationRequired bool
	// RecordPrefix overrides DefaultRecordPrefix for the challenge TXT record
	// name. Empty uses DefaultRecordPrefix.
	RecordPrefix string
}

// StoreOption configures a StoreConfig; passed to NewMemoryStore / sqlite.New.
type StoreOption func(*StoreConfig)

// WithDomainVerificationRequired flips a store into the anti-hijack hardened
// mode (see StoreConfig.DomainVerificationRequired).
func WithDomainVerificationRequired(required bool) StoreOption {
	return func(c *StoreConfig) { c.DomainVerificationRequired = required }
}

// WithDomainVerificationRecordPrefix overrides the challenge TXT record label.
func WithDomainVerificationRecordPrefix(prefix string) StoreOption {
	return func(c *StoreConfig) { c.RecordPrefix = prefix }
}

// ApplyStoreOptions folds opts onto a zero StoreConfig. Shared by the store
// constructors so both backends interpret the same options identically.
func ApplyStoreOptions(opts ...StoreOption) StoreConfig {
	var cfg StoreConfig
	for _, o := range opts {
		if o != nil {
			o(&cfg)
		}
	}
	return cfg
}

// GenerateDomainToken returns a fresh random challenge token (hex-encoded, 20
// random bytes). Not a secret (see DomainVerification) — crypto/rand is used
// only for unguessability, not confidentiality.
func GenerateDomainToken() (string, error) {
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// DomainVerificationRecordName returns the DNS TXT record name to publish/query
// for domain, using prefix (or DefaultRecordPrefix when empty).
func DomainVerificationRecordName(prefix, domain string) string {
	if prefix == "" {
		prefix = DefaultRecordPrefix
	}
	return prefix + "." + strings.ToLower(strings.TrimSpace(domain))
}

// VerifyDomainOwnership performs the DNS-TXT challenge check for connID's claim
// on domain: it loads the claim (ErrNoDomainClaim if connID never claimed
// domain — propagated for a 404), short-circuits an already-verified claim
// WITHOUT a network call, then looks up the claim's Record and uses the
// token-bound promotion capability when any TXT value equals the claim Token.
//
// Fail-closed: a store error loading the claim is returned (never swallowed) so
// a read failure can NEVER silently authorize a domain takeover. A pending claim
// without the token-bound capability is also rejected rather than falling back
// to Store.VerifyDomain, which cannot close the claim-read/DNS/promotion TOCTOU.
// A DNS lookup error (the common NXDOMAIN-before-publish case, or a transient
// failure) is NOT an error — it is the expected "not yet verified" state, so it
// returns (false, nil) and the admin retries after publishing the record.
func VerifyDomainOwnership(ctx context.Context, store Store, resolver DNSResolver, connID, domain string, timeout time.Duration) (bool, error) {
	claim, err := store.DomainClaim(ctx, connID, domain)
	if err != nil {
		return false, err
	}
	if claim.Status == DomainVerified {
		return true, nil
	}
	verifier, ok := store.(TokenBoundDomainVerifier)
	if !ok {
		return false, errTokenBoundDomainVerificationUnsupported
	}
	if timeout <= 0 {
		timeout = DefaultDomainVerificationTimeout
	}
	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	txts, err := resolver.LookupTXT(lookupCtx, claim.Record)
	if err != nil {
		return false, nil
	}
	for _, t := range txts {
		if t != claim.Token {
			continue
		}
		verified, err := verifier.VerifyDomainWithToken(ctx, connID, domain, claim.Token)
		if err != nil {
			return false, err
		}
		return verified, nil
	}
	return false, nil
}
