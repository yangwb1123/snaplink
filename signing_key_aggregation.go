package sso

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/metrics"
	"github.com/snaplink/sso/signingkeys"
)

// Signing-key aggregation resubscribe backoff bounds. On a Subscribe-channel
// close while ctx is live the loop retries with an exponentially growing,
// jittered, capped delay so a flapping registry doesn't hot-loop. Deterministic
// jitter (a per-attempt step, NOT crypto/math rand) keeps the loop allocation-
// and dependency-free while still de-synchronizing a fleet of replicas that all
// lost the registry at the same instant.
const (
	signingKeyAggBackoffInitial = 1 * time.Second
	signingKeyAggBackoffMax     = 30 * time.Second

	// signingKeyAggDegradedReason is the SetMeta reason on the one-per-
	// transition degraded audit event.
	signingKeyAggDegradedReason = "subscribe_channel_closed"
)

// DefaultSigningKeyLeaseTTL is the lease a replica requests when publishing
// its signing keys to a shared registry. A backend with real lease expiry
// (etcd) drops a replica's announcement this long after its last renewing
// Publish — long enough to survive a brief outage, short enough that a
// crashed replica's keys eventually disappear from peers' JWKS. The
// in-process memory peer ignores lease expiry (single process).
const DefaultSigningKeyLeaseTTL = 5 * time.Minute

// WithSharedSigningKeyRegistry opts this Server into leaderless
// multi-replica signing-key aggregation. Each replica holds its own
// in-process signing key (distinct kid); without aggregation a token minted
// here fails verification on a peer (or on an RP that fetched JWKS from a
// peer) because the peer's verify-set lacks this replica's kid. With a
// registry wired, every replica PUBLISHES its signing PUBLIC keys and
// ADOPTS its peers' public keys VERIFY-ONLY into the matching-alg issuer —
// so JWKS() and Validate() serve/accept the union, while each replica still
// SIGNS only with its own private key. No shared private key, no leader
// election, no rotation coordination.
//
// Call [Server.StartSigningKeyAggregation] with the run context to begin
// publishing + consuming.
//
// No-op when unset (nil): single-node deployments need no aggregation and
// behavior is byte-identical to a build without the feature. A nil registry
// is treated as unset.
func WithSharedSigningKeyRegistry(reg signingkeys.Registry) Option {
	return func(s *Server) { s.signingKeyRegistry = reg }
}

// WithSigningKeyReplicaID sets the stable identifier this replica announces
// to the shared signing-key registry. It MUST be unique per replica (reusing
// one across replicas makes them clobber each other's announcement). cmd
// derives it from the same hostname-based id it uses for the service
// registry. REQUIRED whenever a registry is wired: an empty id makes
// StartSigningKeyAggregation return an error rather than start one-directional
// aggregation (this replica would adopt peers but its own rejected
// announcement would leave peers unable to verify its tokens). Ignored when no
// registry is wired.
func WithSigningKeyReplicaID(id string) Option {
	return func(s *Server) { s.replicaID = id }
}

// WithSigningKeyLeaseTTL overrides the lease a replica requests when
// publishing (see DefaultSigningKeyLeaseTTL). Values <= 0 clamp to the
// default. Ignored unless a registry is wired.
func WithSigningKeyLeaseTTL(ttl time.Duration) Option {
	return func(s *Server) {
		if ttl <= 0 {
			ttl = DefaultSigningKeyLeaseTTL
		}
		s.signingKeyLeaseTTL = ttl
	}
}

// StartSigningKeyAggregation publishes this replica's signing public keys,
// seeds the local verify-set from every peer already in the registry, then
// consumes registry events. Unlike a single drain of the subscription, the
// consumer SELF-HEALS: if the registry's Subscribe channel closes while the
// run context is still live (etcd watch died / network blip), the replica
// would otherwise STOP adopting peers' keys silently — local Publish keeps
// succeeding, but peers' newly-rotated tokens later fail with "unknown kid"
// while /readyz stays green. So instead the loop marks itself DEGRADED
// (SigningKeyAggregationReady → not-ready, sso_signing_key_aggregation_up → 0,
// one audit event), backs off, and RESUBSCRIBES — re-running the initial
// Publish + List seed each time so a recovered loop catches up. The returned
// channel closes ONLY when ctx is cancelled (the loop exits cleanly),
// mirroring [Server.StartInvalidationBus] so cmd coordinates shutdown
// identically.
//
// No-op when no registry is wired: returns an already-closed channel and a
// nil error, so callers may invoke it unconditionally.
func (s *Server) StartSigningKeyAggregation(ctx context.Context) (<-chan struct{}, error) {
	done := make(chan struct{})
	if s.signingKeyRegistry == nil {
		close(done)
		return done, nil
	}

	// Fail loud on SDK misuse: a wired registry with no replicaID would let
	// the registry reject this replica's PublishSigningKeys (the memory peer
	// requires a non-empty ReplicaID), so this replica would ADOPT its peers'
	// keys but its OWN announcement would never land — peers (and RPs that
	// fetched JWKS from a peer) could not verify tokens this replica signs.
	// That silent one-directional aggregation is worse than not starting, so
	// refuse rather than limp along. cmd always sets replicaID, so only direct
	// SDK callers can hit this.
	if s.replicaID == "" {
		close(done)
		return done, fmt.Errorf("signingkeys: WithSigningKeyReplicaID is required when a registry is wired")
	}

	// Synchronous first subscribe so a Subscribe error surfaces to the caller
	// (matching the prior contract + the bus's startup semantics) rather than
	// being swallowed into the background retry loop. A LATER channel close is
	// the self-heal path; an INITIAL Subscribe failure is a wiring/transport
	// fault the operator should see at boot.
	events, err := s.subscribeAndSeed(ctx)
	if err != nil {
		close(done)
		return done, err
	}
	// Healthy from the first successful subscribe.
	s.setSigningKeyAggHealthy()

	go s.runSigningKeyAggregation(ctx, done, events)
	return done, nil
}

// subscribeAndSeed publishes this replica's keys, opens a subscription, and
// seeds the local verify-set from every peer already present. Returns the live
// event channel on success. Re-run verbatim on every (re)subscribe so a
// recovered loop catches up on peers it missed while degraded.
func (s *Server) subscribeAndSeed(ctx context.Context) (<-chan signingkeys.Event, error) {
	// Publish our own keys first so peers can adopt them.
	if err := s.PublishSigningKeys(ctx); err != nil {
		s.logger.Error("signingkeys: publish failed", "error", err)
		// Non-fatal: a transport hiccup here only delays peers seeing our
		// keys until the next rotation re-publish. Continue to subscribe so
		// we still adopt THEIR keys.
	}

	events, err := s.signingKeyRegistry.Subscribe(ctx)
	if err != nil {
		return nil, err
	}

	// Seed from peers already present before our subscription started, so a
	// late-joining (or just-recovered) replica adopts incumbents immediately
	// rather than waiting for their next renewing Publish.
	if anns, listErr := s.signingKeyRegistry.List(ctx); listErr != nil {
		s.logger.Error("signingkeys: peer list failed", "error", listErr)
	} else {
		for _, ann := range anns {
			s.applySigningKeyEvent(signingkeys.Event{Type: signingkeys.EventKeysUpserted, Announcement: ann})
		}
	}
	return events, nil
}

// runSigningKeyAggregation is the self-healing consumer. It drains the current
// subscription, and on a channel close distinguishes a clean ctx-cancel (exit
// normally, NOT degraded) from a live-context registry drop (mark degraded,
// back off, resubscribe). Closes done exactly once, only when ctx is cancelled.
func (s *Server) runSigningKeyAggregation(ctx context.Context, done chan struct{}, events <-chan signingkeys.Event) {
	defer close(done)
	attempt := 0
	for {
		for evt := range events {
			s.applySigningKeyEvent(evt)
		}
		// The channel closed. If ctx is done this is a clean shutdown — the
		// subscriber stream closed BECAUSE ctx was cancelled (memory + etcd
		// peers both close on ctx.Done). Exit without marking degraded so a
		// graceful drain never trips /readyz or pages anyone.
		if ctx.Err() != nil {
			return
		}

		// A close with a live context is the silent-failure mode this whole
		// loop exists to defend against: mark degraded ONCE per transition
		// (audit + gauge + flag), then back off and resubscribe.
		s.setSigningKeyAggDegraded()

		attempt++
		if !sleepCtx(ctx, s.signingKeyAggBackoff(attempt)) {
			return // ctx cancelled during backoff — clean exit, stay-degraded flag is moot.
		}

		next, err := s.subscribeAndSeed(ctx)
		if err != nil {
			// Resubscribe failed (registry still down). Stay degraded and try
			// again after a longer backoff. ErrClosed (registry permanently
			// closed at shutdown) is benign here — the next ctx check or
			// backoff will observe the cancel and exit.
			if ctx.Err() != nil {
				return
			}
			s.logger.Error("signingkeys: resubscribe failed, will retry", "attempt", attempt, "error", err)
			continue
		}
		// Recovered: clear degraded (gauge → 1, flag → false, recovered audit)
		// and resume draining the fresh stream with a reset backoff.
		s.setSigningKeyAggHealthy()
		events = next
		attempt = 0
	}
}

// setSigningKeyAggDegraded flips the replica into the degraded state ONCE per
// transition: it no-ops if already degraded (so a flapping registry emits one
// audit event + one gauge write per outage, not per retry). Called only from
// the single subscriber goroutine, so the read-then-set is race-free w.r.t.
// itself; the flag is atomic only for the concurrent /readyz reader.
func (s *Server) setSigningKeyAggDegraded() {
	if s.signingKeyAggDegraded.Swap(true) {
		return // already degraded — don't re-emit.
	}
	s.logger.Error("signingkeys: aggregation subscription closed while running; peer-key adoption stalled, resubscribing", "replica_id", s.replicaID)
	if s.metrics != nil {
		s.metrics.SigningKeyAggregationUp.Set(0)
	}
	audit.RecordSigningKeyAggregationDegraded(s.auditor, context.Background(), signingKeyAggDegradedReason)
}

// setSigningKeyAggHealthy clears the degraded state. On the initial subscribe
// it just stamps the gauge to 1 (Swap returns false). On RECOVERY from a
// degraded state it additionally emits the recovered audit event. Symmetric
// with setSigningKeyAggDegraded; one transition, one event.
func (s *Server) setSigningKeyAggHealthy() {
	wasDegraded := s.signingKeyAggDegraded.Swap(false)
	if s.metrics != nil {
		s.metrics.SigningKeyAggregationUp.Set(1)
	}
	if wasDegraded {
		s.logger.Info("signingkeys: aggregation subscription recovered; resumed adopting peer keys", "replica_id", s.replicaID)
		audit.RecordSigningKeyAggregationRecovered(s.auditor, context.Background())
	}
}

// SigningKeyAggregationReady reports whether this replica's leaderless
// signing-key aggregation subscription is healthy. It returns an error while
// the subscription is degraded (the registry stream closed and the loop is
// between resubscribe attempts) — at which point the replica is no longer
// adopting peers' newly-published keys, so it may reject valid peer tokens
// ("unknown kid") or serve a stale JWKS. cmd wraps this into a /readyz
// ReadyCheck ONLY when a registry is wired; with no registry the aggregation
// loop never runs, the flag is always false, and no check is registered.
func (s *Server) SigningKeyAggregationReady() error {
	if s.signingKeyAggDegraded.Load() {
		return errors.New("signingkeys: aggregation subscription degraded (not adopting peer keys)")
	}
	return nil
}

// signingKeyAggBackoff returns the resubscribe delay for the given 1-based
// attempt: exponential from the initial up to the cap, plus a deterministic
// per-attempt jitter (no rand) so a fleet that all lost the registry at once
// de-synchronizes its retries. The jitter is bounded to a quarter of the
// computed base, keeping the delay within [base, base+base/4] and never above
// the cap + jitter ceiling. The base is the production const unless a test set
// signingKeyAggBackoffBase (so the resubscribe path is exercisable without
// real-second waits).
func (s *Server) signingKeyAggBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	base := signingKeyAggBackoffInitial
	if s.signingKeyAggBackoffBase > 0 {
		base = s.signingKeyAggBackoffBase
	}
	max := signingKeyAggBackoffMax
	if base > max {
		max = base
	}
	d := base
	for i := 1; i < attempt && d < max; i++ {
		d *= 2
	}
	if d > max {
		d = max
	}
	// Deterministic jitter: a small spread keyed off the attempt number so two
	// replicas on different attempt counts (they lost the watch at slightly
	// different times) don't retry in lockstep. attempt%5 spans 0..4/5 of a
	// quarter-window — enough spread without a randomness dependency.
	jitter := (d / 4) * time.Duration(attempt%5) / 5
	return d + jitter
}

// sleepCtx waits for d or ctx cancellation, returning true if the full delay
// elapsed and false if ctx was cancelled first. Lets the backoff abort
// promptly on shutdown.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// PublishSigningKeys gathers every JWKS-publishing issuer's public keys into
// a single announcement and publishes it under this replica's id. Call it at
// startup (done by StartSigningKeyAggregation) AND after each signing-key
// rotation — the announcement replaces the replica's prior one wholesale, so
// a rotated kid propagates and the retired kid drops from peers' verify-sets.
// No-op (returns nil) when no registry is wired.
func (s *Server) PublishSigningKeys(ctx context.Context) error {
	if s.signingKeyRegistry == nil {
		return nil
	}
	var keys []core.JWK
	for _, ti := range s.tokenIssuers {
		jp, ok := ti.(core.JWKSProvider)
		if !ok {
			continue
		}
		jwks, err := jp.JWKS(ctx)
		if err != nil {
			s.logger.Error("signingkeys: collect JWKS for publish failed", "error", err)
			continue
		}
		keys = append(keys, jwks...)
	}
	lease := s.signingKeyLeaseTTL
	if lease <= 0 {
		lease = DefaultSigningKeyLeaseTTL
	}
	return s.signingKeyRegistry.Publish(ctx, signingkeys.Announcement{
		ReplicaID:    s.replicaID,
		Keys:         keys,
		LeaseSeconds: int64(lease.Seconds()),
	})
}

// ensureIssuerAlgs builds (once) a map of issuer-name -> signing alg from
// each issuer's JWKS, so applySigningKeyEvent can route an announced key to
// the matching-alg issuer without re-querying JWKS per event. An issuer's
// alg is its JWKS()[0].Alg (the primary signing key).
func (s *Server) ensureIssuerAlgs() {
	s.issuerAlgsOnce.Do(func() {
		algs := make(map[string]string, len(s.tokenIssuers))
		for name, ti := range s.tokenIssuers {
			jp, ok := ti.(core.JWKSProvider)
			if !ok {
				continue
			}
			jwks, err := jp.JWKS(context.Background())
			if err != nil || len(jwks) == 0 {
				continue
			}
			algs[name] = jwks[0].Alg
		}
		s.issuerAlgs = algs
	})
}

// applySigningKeyEvent reconciles a registry event into the local issuers'
// peer verify-sets. KeysUpserted adopts each announced key into the issuer
// whose signing alg matches the key's Alg (alg-match is ENFORCED before
// adoption so an issuer never adopts a key of a different alg — preserving
// the per-issuer kid->alg invariant and the alg-confusion defense).
// KeysRemoved drops every kid previously adopted from that replica.
//
// Skips this replica's own announcements (a replica must not adopt its own
// signing key as a peer key — that would collide with its local key). Bad or
// undecodable peer keys are logged and skipped (fail-open), never fatal.
func (s *Server) applySigningKeyEvent(evt signingkeys.Event) {
	replicaID := evt.Announcement.ReplicaID
	if replicaID == "" || replicaID == s.replicaID {
		return
	}

	switch evt.Type {
	case signingkeys.EventKeysRemoved:
		s.dropAllAdopted(replicaID)

	case signingkeys.EventKeysUpserted:
		s.ensureIssuerAlgs()
		// Reconcile: drop everything previously adopted from this replica,
		// then re-adopt the current announcement. This makes a SHRINKING
		// announcement (peer rotated, old kid gone) drop the stale kid, not
		// just add the new one — without tracking per-key diffs. Refcounting
		// (see registerAdoptedKids/dropAllAdopted) ensures the drop here never
		// evicts a kid another live replica still announces.
		s.dropAllAdopted(replicaID)

		var adopted []string
		for _, jwk := range evt.Announcement.Keys {
			kid, ok := s.adoptPeerKey(replicaID, jwk)
			if ok {
				adopted = append(adopted, kid)
			}
		}
		s.registerAdoptedKids(replicaID, adopted)

	default:
		// Unknown event type from a newer peer — ignore rather than error,
		// so a mixed-version cluster degrades gracefully during a rollout.
	}
}

// registerAdoptedKids records that replicaID currently announces exactly the
// given kids and bumps each kid's cross-replica refcount. Must run AFTER the
// matching dropAllAdopted in a reconcile so the per-replica set reflects the
// latest announcement. A kid adopted by two replicas reaches refcount 2, so
// dropping one leaves the issuer key in place for the other (FIX C).
func (s *Server) registerAdoptedKids(replicaID string, kids []string) {
	if len(kids) == 0 {
		return
	}
	s.adoptedPeerMu.Lock()
	defer s.adoptedPeerMu.Unlock()
	if s.adoptedPeerKids == nil {
		s.adoptedPeerKids = make(map[string][]string)
	}
	if s.adoptedKidRefs == nil {
		s.adoptedKidRefs = make(map[string]int)
	}
	s.adoptedPeerKids[replicaID] = kids
	for _, kid := range kids {
		s.adoptedKidRefs[kid]++
	}
}

// adoptPeerKey routes one announced JWK to a matching-alg issuer and adopts
// it verify-only. Returns the adopted kid and true on the first issuer that
// accepts it; tries EVERY matching-alg issuer before giving up, so one
// issuer's AdoptVerifyKey error (e.g. a local kid collision in that issuer)
// does not abandon a key another issuer would happily verify.
//
// Alg-match is enforced HERE, before adoption: the key is only handed to an
// issuer whose own signing alg equals the key's Alg. A key whose alg matches
// no wired issuer (e.g. an ES256 peer key on an EdDSA-only deployment) is
// logged + skipped — not an error. Decoding + adoption dispatch by the
// issuer's adopt-capability (EdDSA -> ed25519.PublicKey, ES256 ->
// *ecdsa.PublicKey, RS256/PS256 -> *rsa.PublicKey). Because each issuer signs
// exactly one alg and the alg-match gate already passed, an RS256 key never
// reaches a PS256 issuer (and vice versa) — the RS256/PS256 boundary stays
// strict.
func (s *Server) adoptPeerKey(replicaID string, jwk core.JWK) (string, bool) {
	if jwk.Kid == "" || jwk.Alg == "" {
		s.logger.Debug("signingkeys: skipping peer key with empty kid/alg", "replica_id", replicaID)
		return "", false
	}
	for name, ti := range s.tokenIssuers {
		// Alg-match gate: an issuer must NEVER adopt a key of a different
		// alg, or per-issuer kid->alg (and the alg-confusion defense) breaks.
		if s.issuerAlgs[name] != jwk.Alg {
			continue
		}
		// Dispatch by the issuer's adopt-capability. Each issuer exposes
		// exactly ONE AdoptVerifyKey shape (matching its key type), so only
		// one branch fires per issuer. The decode is keyed off the same key
		// type the issuer accepts, so an EC issuer never receives RSA material
		// and vice versa.
		adopted, decodeFailed, supported := s.tryAdoptIntoIssuer(replicaID, name, ti, jwk)
		if decodeFailed {
			// A decode failure is a property of the JWK itself, not of any one
			// issuer — no matching-alg issuer could adopt it. Fail-open:
			// abandon THIS key (the caller's per-JWK loop continues to the
			// remaining keys in the announcement). Surface it as a metric so a
			// peer publishing bad keys is visible beyond the log line.
			s.recordAdoptionError(metrics.AdoptionReasonDecode)
			return "", false
		}
		if !supported {
			// Matching alg but this issuer does not expose the matching
			// AdoptVerifyKey shape — skip cleanly and try the next issuer.
			continue
		}
		if !adopted {
			// One matching-alg issuer rejected the key (e.g. a local kid
			// collision in that issuer). Don't abandon the key wholesale —
			// another matching-alg issuer may accept it. Already logged inside
			// tryAdoptIntoIssuer; try the next.
			continue
		}
		s.logger.Info("signingkeys: adopted peer verify key",
			"replica_id", replicaID, "kid", jwk.Kid, "alg", jwk.Alg, "issuer", name)
		return jwk.Kid, true
	}
	s.logger.Debug("signingkeys: no matching-alg issuer for peer key, skipping",
		"replica_id", replicaID, "kid", jwk.Kid, "alg", jwk.Alg)
	return "", false
}

// tryAdoptIntoIssuer decodes the JWK to the key type the issuer adopts and
// calls its AdoptVerifyKey. Returns (adopted, decodeFailed, supported):
//   - supported=false: the issuer doesn't expose the matching AdoptVerifyKey
//     shape (caller skips to the next matching-alg issuer).
//   - decodeFailed=true: the JWK itself is malformed/off-curve/undersized for
//     its key type (caller abandons the key — no issuer could adopt it).
//   - adopted=true: the issuer accepted the key.
//
// A nil/zero return triple (false,false,false) is the "supported=false" case.
// Logging of decode + adopt failures happens here so adoptPeerKey stays a thin
// router. Fail-open throughout: a bad peer key is logged and skipped, never
// fatal to the subscriber goroutine.
func (s *Server) tryAdoptIntoIssuer(replicaID, name string, ti core.TokenIssuer, jwk core.JWK) (adopted, decodeFailed, supported bool) {
	switch {
	case isEdDSAJWK(jwk):
		ad, ok := ti.(interface {
			AdoptVerifyKey(string, ed25519.PublicKey) error
		})
		if !ok {
			return false, false, false
		}
		pub, err := decodeEd25519JWK(jwk)
		if err != nil {
			s.logger.Error("signingkeys: undecodable peer key, skipping",
				"replica_id", replicaID, "kid", jwk.Kid, "error", err)
			return false, true, true
		}
		return s.adoptOne(replicaID, name, jwk.Kid, func() error { return ad.AdoptVerifyKey(jwk.Kid, pub) }), false, true

	case isECJWK(jwk):
		ad, ok := ti.(interface {
			AdoptVerifyKey(string, *ecdsa.PublicKey) error
		})
		if !ok {
			return false, false, false
		}
		pub, err := decodeECDSAJWK(jwk)
		if err != nil {
			s.logger.Error("signingkeys: undecodable peer key, skipping",
				"replica_id", replicaID, "kid", jwk.Kid, "error", err)
			return false, true, true
		}
		return s.adoptOne(replicaID, name, jwk.Kid, func() error { return ad.AdoptVerifyKey(jwk.Kid, pub) }), false, true

	case isRSAJWK(jwk):
		ad, ok := ti.(interface {
			AdoptVerifyKey(string, *rsa.PublicKey) error
		})
		if !ok {
			return false, false, false
		}
		pub, err := decodeRSAJWK(jwk)
		if err != nil {
			s.logger.Error("signingkeys: undecodable peer key, skipping",
				"replica_id", replicaID, "kid", jwk.Kid, "error", err)
			return false, true, true
		}
		return s.adoptOne(replicaID, name, jwk.Kid, func() error { return ad.AdoptVerifyKey(jwk.Kid, pub) }), false, true

	default:
		// Unknown kty — no decoder. Treat as unsupported so the caller keeps
		// scanning issuers (none will match), then logs "no matching-alg
		// issuer". Not a decode error (we never attempted a decode).
		return false, false, false
	}
}

// adoptOne runs an issuer's AdoptVerifyKey and logs a rejection, returning
// whether it succeeded. Centralizes the "try next matching-alg issuer on
// error" logging so the three type-branches in tryAdoptIntoIssuer stay terse.
func (s *Server) adoptOne(replicaID, name, kid string, adopt func() error) bool {
	if err := adopt(); err != nil {
		s.logger.Error("signingkeys: adopt peer key failed on issuer, trying next matching-alg issuer",
			"replica_id", replicaID, "kid", kid, "issuer", name, "error", err)
		// A matching-alg issuer rejected an otherwise-decodable key (e.g. a
		// local kid collision). Count it so a kid clash that silently shrinks
		// the verify-set is observable; the caller still tries the next issuer.
		s.recordAdoptionError(metrics.AdoptionReasonAdopt)
		return false
	}
	return true
}

// recordAdoptionError increments the bounded adoption-error counter. Guarded:
// nil metrics (no WithMetrics wired) is a no-op, preserving the opt-in zero-
// overhead contract. reason is bounded to {decode, adopt}.
func (s *Server) recordAdoptionError(reason string) {
	if s.metrics == nil {
		return
	}
	s.metrics.SigningKeyAdoptionErrorsTotal.WithLabelValues(reason).Inc()
}

// isEdDSAJWK / isECJWK / isRSAJWK classify a peer JWK by its key type so
// adoptPeerKey routes it to the right decoder. Classification is by kty (the
// authoritative JWK key-type discriminator, RFC 7517 §4.1), not by alg — the
// alg-match gate already ran, and kty selects the wire shape (X vs X+Y vs N+E).
func isEdDSAJWK(jwk core.JWK) bool { return jwk.Kty == jwkKtyOKP }
func isECJWK(jwk core.JWK) bool    { return jwk.Kty == jwkKtyEC }
func isRSAJWK(jwk core.JWK) bool   { return jwk.Kty == jwkKtyRSA }

// dropAllAdopted forgets every peer key this replica adopted from replicaID
// and clears its tracking entry. A kid is only actually removed from the
// issuer (DropVerifyKey) when NO live replica still announces it — i.e. when
// its cross-replica refcount falls to 0 (FIX C). This prevents dropping one
// replica from evicting a kid another live replica still holds (fingerprint
// collision / shared key / misconfig), which would break the other replica's
// live tokens. Idempotent.
func (s *Server) dropAllAdopted(replicaID string) {
	s.adoptedPeerMu.Lock()
	kids := s.adoptedPeerKids[replicaID]
	delete(s.adoptedPeerKids, replicaID)
	// Decrement refcounts under the lock; collect only the kids whose count
	// reached 0 — those are the only ones safe to remove from the issuer.
	var toDrop []string
	for _, kid := range kids {
		if s.adoptedKidRefs == nil {
			break
		}
		s.adoptedKidRefs[kid]--
		if s.adoptedKidRefs[kid] <= 0 {
			delete(s.adoptedKidRefs, kid)
			toDrop = append(toDrop, kid)
		}
	}
	s.adoptedPeerMu.Unlock()
	if len(toDrop) == 0 {
		return
	}
	for _, ti := range s.tokenIssuers {
		dropper, ok := ti.(interface{ DropVerifyKey(string) })
		if !ok {
			continue
		}
		for _, kid := range toDrop {
			dropper.DropVerifyKey(kid)
		}
	}
}

// JWK key-type discriminators (RFC 7517 §4.1). The Server classifies a peer
// JWK by kty to pick the right decoder; these mirror the same string values
// the defaultimpl issuers stamp into their JWKS output.
const (
	jwkKtyOKP = "OKP" // Ed25519 (EdDSA)
	jwkKtyEC  = "EC"  // P-256 (ES256)
	jwkKtyRSA = "RSA" // RS256 | PS256

	// jwkCrvP256 is the only EC curve this aggregator adopts — ES256's curve.
	// A peer EC key on any other curve is rejected at decode (it could never
	// have signed an ES256 token the local issuer accepts).
	jwkCrvP256 = "P-256"

	// rsaMinPeerKeyBits is the minimum modulus size for an ADOPTED peer RSA
	// key, mirroring the RSA issuer's own rsaMinKeyBits floor (RFC 7518 §3.3
	// >= 2048). Decoding rejects a sub-floor key so a weak modulus never
	// enters the verify-set via aggregation. Kept in sync with the issuer's
	// constant by value; both cite the same RFC floor.
	rsaMinPeerKeyBits = 2048
)

// decodeEd25519JWK reconstructs an ed25519.PublicKey from an OKP/Ed25519
// JWK's base64url-encoded X coordinate, validating the decoded length so a
// malformed peer key fails closed rather than producing a key that silently
// rejects every signature.
func decodeEd25519JWK(jwk core.JWK) (ed25519.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, &decodeError{kid: jwk.Kid, gotLen: len(raw)}
	}
	return ed25519.PublicKey(raw), nil
}

// decodeECDSAJWK reconstructs a P-256 *ecdsa.PublicKey from an EC JWK's
// base64url X/Y coordinates (RFC 7518 §6.2), REJECTING any point that is not on
// the P-256 curve. On-curve validation reuses the same crypto/ecdh path the
// ECDH JWE encrypter uses (ecPublicFromJWK in ecdh_jwe_encrypter.go): assemble
// the uncompressed SEC1 point 0x04||X||Y and hand it to ecdh.P256().NewPublicKey,
// which rejects off-curve / invalid-curve points. Restricted to P-256 because
// ES256 is the only EC alg this aggregator routes — a peer key on another curve
// could never verify an ES256 token, so it fails closed here rather than
// entering the verify-set as a key that silently rejects every signature.
func decodeECDSAJWK(jwk core.JWK) (*ecdsa.PublicKey, error) {
	if jwk.Crv != jwkCrvP256 {
		return nil, fmt.Errorf("signingkeys: peer EC key %s: unsupported crv %q (want %s)", jwk.Kid, jwk.Crv, jwkCrvP256)
	}
	if jwk.X == "" || jwk.Y == "" {
		return nil, fmt.Errorf("signingkeys: peer EC key %s: missing x/y", jwk.Kid)
	}
	xb, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("signingkeys: peer EC key %s: decode x: %w", jwk.Kid, err)
	}
	yb, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("signingkeys: peer EC key %s: decode y: %w", jwk.Kid, err)
	}
	curve := elliptic.P256()
	byteLen := (curve.Params().BitSize + 7) / 8
	if len(xb) > byteLen || len(yb) > byteLen {
		return nil, fmt.Errorf("signingkeys: peer EC key %s: coordinate exceeds curve size", jwk.Kid)
	}
	// Build the uncompressed SEC1 point and validate it lies on P-256 via
	// crypto/ecdh (rejects invalid-curve / off-curve points). go.crypto's
	// ecdsa wants the affine *ecdsa.PublicKey, so we return that after the
	// ecdh validation succeeds.
	point := make([]byte, 1+2*byteLen)
	point[0] = 4
	x := new(big.Int).SetBytes(xb)
	y := new(big.Int).SetBytes(yb)
	x.FillBytes(point[1 : 1+byteLen])
	y.FillBytes(point[1+byteLen:])
	if _, err := ecdh.P256().NewPublicKey(point); err != nil {
		return nil, fmt.Errorf("signingkeys: peer EC key %s: invalid EC point: %w", jwk.Kid, err)
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// decodeRSAJWK reconstructs an *rsa.PublicKey from an RSA JWK's base64url N
// (big-endian modulus) + E (big-endian public exponent) per RFC 7518 §6.3.
// Rejects an undersized modulus (< rsaMinPeerKeyBits) and a degenerate
// public exponent (< 3 or even) so a weak or malformed peer key fails closed
// rather than entering the verify-set.
func decodeRSAJWK(jwk core.JWK) (*rsa.PublicKey, error) {
	if jwk.N == "" || jwk.E == "" {
		return nil, fmt.Errorf("signingkeys: peer RSA key %s: missing n/e", jwk.Kid)
	}
	nb, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("signingkeys: peer RSA key %s: decode n: %w", jwk.Kid, err)
	}
	eb, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("signingkeys: peer RSA key %s: decode e: %w", jwk.Kid, err)
	}
	n := new(big.Int).SetBytes(nb)
	if n.BitLen() < rsaMinPeerKeyBits {
		return nil, fmt.Errorf("signingkeys: peer RSA key %s: modulus is %d bits, minimum is %d", jwk.Kid, n.BitLen(), rsaMinPeerKeyBits)
	}
	e := new(big.Int).SetBytes(eb)
	// Reject e < 3 and even exponents. e=1 makes RSA verification the
	// identity (sig^1 mod N == sig), so anyone could forge a "signature"
	// with no private key; an even e has no inverse modulo the (odd) RSA
	// totient and is cryptographically degenerate. Go's rsa.Verify{PKCS1v15,PSS}
	// do NOT reject either, so a malicious or garbage peer announcement must
	// be rejected here rather than trusted from the registry.
	if !e.IsInt64() {
		return nil, fmt.Errorf("signingkeys: peer RSA key %s: public exponent too large", jwk.Kid)
	}
	ev := e.Int64()
	if ev < 3 || ev&1 == 0 {
		return nil, fmt.Errorf("signingkeys: peer RSA key %s: degenerate public exponent %d", jwk.Kid, ev)
	}
	return &rsa.PublicKey{N: n, E: int(ev)}, nil
}

// decodeError reports a peer JWK whose decoded public key is the wrong
// length for its key type.
type decodeError struct {
	kid    string
	gotLen int
}

func (e *decodeError) Error() string {
	return "signingkeys: peer key " + e.kid + ": unexpected ed25519 public key length"
}
