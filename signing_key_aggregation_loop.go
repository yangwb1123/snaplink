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

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/metrics"
	"github.com/snaplink/sso/signingkeys"
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
			s.applySigningKeyEvent(evt)
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
		s.dropAllAdopted(replicaID)
		var adopted []string
		for _, jwk := range evt.Announcement.Keys {
			kid, ok := s.adoptPeerKey(replicaID, jwk)
			if ok {
				adopted = append(adopted, kid)
			}
		}
		s.registerAdoptedKids(replicaID, adopted)
		s.InvalidateJWKSBodyCache()
	}
}

// registerAdoptedKids records that replicaID currently announces exactly the given kids.
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
		return false, false, false
	}
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
	kids := s.adoptedPeerKids[replicaID]
	delete(s.adoptedPeerKids, replicaID)
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
