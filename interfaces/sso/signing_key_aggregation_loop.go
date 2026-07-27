// Signing-key aggregation loop: subscribe, seed, self-heal consumer, publish, and adopt.
package sso

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/metrics"
	"github.com/yangwb1123/snaplink/platform/signingkeys"
	"github.com/yangwb1123/snaplink/shared/core"
)

// StartSigningKeyAggregation publishes this replica's signing public keys,
// seeds the local verify-set from every peer already in the registry, then
// consumes registry events.
func (s *Server) StartSigningKeyAggregation(ctx context.Context) (<-chan struct{}, error) {
	done := make(chan struct{})
	if s.signingKeyRegistry == nil {
		close(done)
		return done, nil
	}
	if s.replicaID == "" {
		close(done)
		return done, fmt.Errorf("signingkeys: WithSigningKeyReplicaID is required when a registry is wired")
	}
	events, err := s.subscribeAndSeed(ctx)
	if err != nil {
		close(done)
		return done, err
	}
	s.setSigningKeyAggHealthy()
	go s.runSigningKeyAggregation(ctx, done, events)
	return done, nil
}

// subscribeAndSeed publishes this replica's keys, opens a subscription, and
// seeds the local verify-set from every peer already present.
func (s *Server) subscribeAndSeed(ctx context.Context) (<-chan signingkeys.Event, error) {
	if err := s.PublishSigningKeys(ctx); err != nil {
		s.logger.Error("signingkeys: publish failed", "error", err)
	}
	events, err := s.signingKeyRegistry.Subscribe(ctx)
	if err != nil {
		return nil, err
	}
	if anns, listErr := s.signingKeyRegistry.List(ctx); listErr != nil {
		s.logger.Error("signingkeys: peer list failed", "error", listErr)
	} else {
		for _, ann := range anns {
			s.applySigningKeyEvent(signingkeys.Event{Type: signingkeys.EventKeysUpserted, Announcement: ann})
		}
	}
	return events, nil
}

// runSigningKeyAggregation is the self-healing consumer.
func (s *Server) runSigningKeyAggregation(ctx context.Context, done chan struct{}, events <-chan signingkeys.Event) {
	defer close(done)
	attempt := 0
	for {
		for evt := range events {
			s.applySigningKeyEventSafe(evt)
		}
		if ctx.Err() != nil {
			return
		}
		s.setSigningKeyAggDegraded()
		attempt++
		if !sleepCtx(ctx, s.signingKeyAggBackoff(attempt)) {
			return
		}
		next, err := s.subscribeAndSeed(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.logger.Error("signingkeys: resubscribe failed, will retry", "attempt", attempt, "error", err)
			continue
		}
		s.setSigningKeyAggHealthy()
		events = next
		attempt = 0
	}
}

// setSigningKeyAggDegraded flips the replica into the degraded state ONCE per transition.
func (s *Server) setSigningKeyAggDegraded() {
	if s.signingKeyAggDegraded.Swap(true) {
		return
	}
	s.logger.Error("signingkeys: aggregation subscription closed while running; peer-key adoption stalled, resubscribing", "replica_id", s.replicaID)
	if s.metrics != nil {
		s.metrics.SigningKeyAggregationUp.Set(0)
	}
	audit.RecordSigningKeyAggregationDegraded(s.auditor, context.Background(), signingKeyAggDegradedReason)
}

// setSigningKeyAggHealthy clears the degraded state.
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

// SigningKeyAggregationReady reports whether this replica's aggregation subscription is healthy.
func (s *Server) SigningKeyAggregationReady() error {
	if s.signingKeyAggDegraded.Load() {
		return errors.New("signingkeys: aggregation subscription degraded (not adopting peer keys)")
	}
	return nil
}

// signingKeyAggBackoff returns the resubscribe delay for the given 1-based attempt.
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
	jitter := (d / 4) * time.Duration(attempt%5) / 5
	return d + jitter
}

// sleepCtx waits for d or ctx cancellation.
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

// PublishSigningKeys gathers every JWKS-publishing issuer's public keys into a single announcement.
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

// ensureIssuerAlgs builds (once) a map of issuer-name -> signing alg.
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

// applySigningKeyEventSafe wraps applySigningKeyEvent with a recover so a
// panic anywhere in the adoption path — most notably a pluggable, operator-
// supplied core.TokenIssuer's AdoptVerifyKey/DropVerifyKey/JWKS — is
// contained to this ONE event instead of escaping runSigningKeyAggregation's
// bare `for evt := range events` loop. That loop has no recover of its own,
// and an unrecovered panic in ANY goroutine is always process-fatal in Go:
// without this wrapper, one bad peer-key announcement landing on a buggy
// custom issuer would silently crash the entire server, aborting every other
// in-flight request. Mirrors the per-item recover convention already used by
// dispatchBackchannelOne (server_backchannel_logout.go) and
// launchRetireWatcher (server_key_rotation.go).
func (s *Server) applySigningKeyEventSafe(evt signingkeys.Event) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("signingkeys: applying registry event panicked, event dropped",
				"replica_id", evt.Announcement.ReplicaID, "panic", r)
			s.recordAdoptionError(metrics.AdoptionReasonPanic)
		}
	}()
	s.applySigningKeyEvent(evt)
}

// applySigningKeyEvent reconciles a registry event into the local issuers' peer verify-sets.
func (s *Server) applySigningKeyEvent(evt signingkeys.Event) {
	replicaID := evt.Announcement.ReplicaID
	if replicaID == "" || replicaID == s.replicaID {
		return
	}
	switch evt.Type {
	case signingkeys.EventKeysRemoved:
		s.dropAllAdopted(replicaID)
		s.InvalidateJWKSBodyCache()
	case signingkeys.EventKeysUpserted:
		s.ensureIssuerAlgs()
		s.reconcileAdopted(replicaID, evt.Announcement.Keys)
		s.InvalidateJWKSBodyCache()
	}
}

// reconcileAdopted updates replicaID's adopted keyset to EXACTLY the announced
// keys by SET DIFFERENCE, so a key the peer still announces is NEVER transiently
// removed from the verify set mid-update (the prior drop-all-then-readd left a
// window during which a concurrent Validate of a peer token signed by an
// UNCHANGED key failed with "unknown kid"). Every announced key is adopted FIRST
// (AdoptVerifyKey is idempotent), THEN only the kids this peer no longer
// announces — and whose total refcount across peers reaches zero — are dropped.
func (s *Server) reconcileAdopted(replicaID string, keys []core.JWK) {
	announcedSet := make(map[string]struct{}, len(keys))
	announced := make([]string, 0, len(keys))
	for _, jwk := range keys {
		kid, ok := s.adoptPeerKey(replicaID, jwk)
		if !ok {
			continue
		}
		if _, dup := announcedSet[kid]; dup {
			continue
		}
		announcedSet[kid] = struct{}{}
		announced = append(announced, kid)
	}

	s.adoptedPeerMu.Lock()
	toDrop := s.diffAdoptedRefcountsLocked(replicaID, announced, announcedSet)
	s.adoptedPeerMu.Unlock()

	s.dropVerifyKidsFromIssuers(toDrop)
	s.refreshVerifyKeysGauge()
}

// diffAdoptedRefcountsLocked updates replicaID's adopted kid set + the
// cross-replica refcounts by SET DIFFERENCE (see reconcileAdopted's doc above
// for why), stamps lastSeenPeer for PruneVerifyKeys' retention sweep — even on
// a no-op reconcile, so its window measures "how long since we last heard
// from this replica", not "how long since its kids changed" — and returns the
// kids whose refcount reached zero. Caller MUST hold adoptedPeerMu.
func (s *Server) diffAdoptedRefcountsLocked(replicaID string, announced []string, announcedSet map[string]struct{}) []string {
	if s.adoptedPeerKids == nil {
		s.adoptedPeerKids = make(map[string][]string)
	}
	if s.adoptedKidRefs == nil {
		s.adoptedKidRefs = make(map[string]int)
	}
	prev := s.adoptedPeerKids[replicaID]
	prevSet := make(map[string]struct{}, len(prev))
	for _, kid := range prev {
		prevSet[kid] = struct{}{}
	}
	// +1 for kids newly announced by this peer; unchanged kids keep their
	// refcount (and stay installed). -1 for kids this peer dropped.
	for _, kid := range announced {
		if _, had := prevSet[kid]; !had {
			s.adoptedKidRefs[kid]++
		}
	}
	var toDrop []string
	for _, kid := range prev {
		if _, still := announcedSet[kid]; still {
			continue
		}
		s.adoptedKidRefs[kid]--
		if s.adoptedKidRefs[kid] <= 0 {
			delete(s.adoptedKidRefs, kid)
			toDrop = append(toDrop, kid)
		}
	}
	s.adoptedPeerKids[replicaID] = announced
	if s.lastSeenPeer == nil {
		s.lastSeenPeer = make(map[string]time.Time)
	}
	s.lastSeenPeer[replicaID] = time.Now()
	return toDrop
}

// dropVerifyKidsFromIssuers removes the given kids from every issuer's
// peer-verify set (best-effort; issuers without DropVerifyKey are skipped).
func (s *Server) dropVerifyKidsFromIssuers(kids []string) {
	if len(kids) == 0 {
		return
	}
	for _, ti := range s.tokenIssuers {
		dropper, ok := ti.(interface{ DropVerifyKey(string) })
		if !ok {
			continue
		}
		for _, kid := range kids {
			dropper.DropVerifyKey(kid)
		}
	}
}

// refreshVerifyKeysGauge, PruneVerifyKeys, and releaseReplicaKidsLocked
// (the signing-key hygiene sweep) live in options_misc.go, alongside
// WithCoordinatedKeyRotation — this file was at the line budget.

// adoptPeerKey routes one announced JWK to a matching-alg issuer and adopts it verify-only.
func (s *Server) adoptPeerKey(replicaID string, jwk core.JWK) (string, bool) {
	if jwk.Kid == "" || jwk.Alg == "" {
		s.logger.Debug("signingkeys: skipping peer key with empty kid/alg", "replica_id", replicaID)
		return "", false
	}
	for name, ti := range s.tokenIssuers {
		if s.issuerAlgs[name] != jwk.Alg {
			continue
		}
		adopted, decodeFailed, supported := s.tryAdoptIntoIssuer(replicaID, name, ti, jwk)
		if decodeFailed {
			s.recordAdoptionError(metrics.AdoptionReasonDecode)
			return "", false
		}
		if !supported {
			continue
		}
		if !adopted {
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

// tryAdoptIntoIssuer decodes the JWK to the key type the issuer adopts and calls its AdoptVerifyKey.
func (s *Server) tryAdoptIntoIssuer(replicaID, name string, ti core.TokenIssuer, jwk core.JWK) (adopted, decodeFailed, supported bool) {
	switch {
	case isEdDSAJWK(jwk):
		return s.tryAdoptEd25519(replicaID, name, ti, jwk)
	case isECJWK(jwk):
		return s.tryAdoptECDSA(replicaID, name, ti, jwk)
	case isRSAJWK(jwk):
		return s.tryAdoptRSA(replicaID, name, ti, jwk)
	default:
		return false, false, false
	}
}

// tryAdoptEd25519 decodes an OKP JWK and adopts it verify-only into ti. The
// alg-match gate happens in adoptPeerKey BEFORE this is reached; the
// type-assert -> decode -> adopt ordering here is preserved verbatim so a
// wrong-shape/undecodable key is NEVER installed.
func (s *Server) tryAdoptEd25519(replicaID, name string, ti core.TokenIssuer, jwk core.JWK) (adopted, decodeFailed, supported bool) {
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
}

// tryAdoptECDSA decodes an EC JWK and adopts it verify-only into ti. The
// alg-match gate happens in adoptPeerKey BEFORE this is reached; the
// type-assert -> decode -> adopt ordering here is preserved verbatim so a
// wrong-shape/undecodable key is NEVER installed.
func (s *Server) tryAdoptECDSA(replicaID, name string, ti core.TokenIssuer, jwk core.JWK) (adopted, decodeFailed, supported bool) {
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
}

// tryAdoptRSA decodes an RSA JWK and adopts it verify-only into ti. The
// alg-match gate happens in adoptPeerKey BEFORE this is reached; the
// type-assert -> decode -> adopt ordering here is preserved verbatim so a
// wrong-shape/undecodable key is NEVER installed.
func (s *Server) tryAdoptRSA(replicaID, name string, ti core.TokenIssuer, jwk core.JWK) (adopted, decodeFailed, supported bool) {
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
}

// adoptOne runs an issuer's AdoptVerifyKey and logs a rejection.
func (s *Server) adoptOne(replicaID, name, kid string, adopt func() error) bool {
	if err := adopt(); err != nil {
		s.logger.Error("signingkeys: adopt peer key failed on issuer, trying next matching-alg issuer",
			"replica_id", replicaID, "kid", kid, "issuer", name, "error", err)
		s.recordAdoptionError(metrics.AdoptionReasonAdopt)
		return false
	}
	return true
}

// recordAdoptionError increments the bounded adoption-error counter.
func (s *Server) recordAdoptionError(reason string) {
	if s.metrics == nil {
		return
	}
	s.metrics.SigningKeyAdoptionErrorsTotal.WithLabelValues(reason).Inc()
}

// isEdDSAJWK / isECJWK / isRSAJWK classify a peer JWK by its key type.
func isEdDSAJWK(jwk core.JWK) bool { return jwk.Kty == jwkKtyOKP }
func isECJWK(jwk core.JWK) bool    { return jwk.Kty == jwkKtyEC }
func isRSAJWK(jwk core.JWK) bool   { return jwk.Kty == jwkKtyRSA }

// dropAllAdopted forgets every peer key this replica adopted from replicaID.
func (s *Server) dropAllAdopted(replicaID string) {
	s.adoptedPeerMu.Lock()
	toDrop := s.releaseReplicaKidsLocked(replicaID)
	s.adoptedPeerMu.Unlock()
	s.dropVerifyKidsFromIssuers(toDrop)
	s.refreshVerifyKeysGauge()
}
