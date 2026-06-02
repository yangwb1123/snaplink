package sso

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"time"

	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/signingkeys"
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
// one across replicas makes them clobber each other's announcement). When
// unset, cmd derives it from the same hostname-based id it uses for the
// service registry. Ignored unless a registry is wired.
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
// consumes registry events until the stream closes (ctx cancelled or
// registry closed). The returned channel closes when the consumer goroutine
// exits, mirroring [Server.StartInvalidationBus] so cmd coordinates shutdown
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

	// Publish our own keys first so peers can adopt them.
	if err := s.PublishSigningKeys(ctx); err != nil {
		s.logger.Error("signingkeys: initial publish failed", "error", err)
		// Non-fatal: a transport hiccup here only delays peers seeing our
		// keys until the next rotation re-publish. Continue to subscribe so
		// we still adopt THEIR keys.
	}

	events, err := s.signingKeyRegistry.Subscribe(ctx)
	if err != nil {
		close(done)
		return done, err
	}

	// Seed from peers already present before our subscription started, so a
	// late-joining replica adopts incumbents immediately rather than waiting
	// for their next renewing Publish.
	if anns, listErr := s.signingKeyRegistry.List(ctx); listErr != nil {
		s.logger.Error("signingkeys: initial peer list failed", "error", listErr)
	} else {
		for _, ann := range anns {
			s.applySigningKeyEvent(signingkeys.Event{Type: signingkeys.EventKeysUpserted, Announcement: ann})
		}
	}

	go func() {
		defer close(done)
		for evt := range events {
			s.applySigningKeyEvent(evt)
		}
	}()
	return done, nil
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
		// just add the new one — without tracking per-key diffs.
		s.dropAllAdopted(replicaID)

		var adopted []string
		for _, jwk := range evt.Announcement.Keys {
			kid, ok := s.adoptPeerKey(replicaID, jwk)
			if ok {
				adopted = append(adopted, kid)
			}
		}
		if len(adopted) > 0 {
			s.adoptedPeerMu.Lock()
			if s.adoptedPeerKids == nil {
				s.adoptedPeerKids = make(map[string][]string)
			}
			s.adoptedPeerKids[replicaID] = adopted
			s.adoptedPeerMu.Unlock()
		}

	default:
		// Unknown event type from a newer peer — ignore rather than error,
		// so a mixed-version cluster degrades gracefully during a rollout.
	}
}

// adoptPeerKey routes one announced JWK to the matching-alg issuer and
// adopts it verify-only. Returns the adopted kid and true on success.
//
// Alg-match is enforced HERE, before adoption: the key is only handed to an
// issuer whose own signing alg equals the key's Alg. A key whose alg matches
// no wired issuer (e.g. an ES256 peer key on an EdDSA-only deployment, until
// the ECDSA follow-up commit) is logged + skipped — not an error. Only
// Ed25519 issuers expose AdoptVerifyKey in this commit; others are skipped.
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
		adopter, ok := ti.(interface {
			AdoptVerifyKey(string, ed25519.PublicKey) error
		})
		if !ok {
			// Matching alg but no adoption support (e.g. ECDSA/RSA in this
			// commit). Skip cleanly; the follow-up commit wires those.
			continue
		}
		pub, err := decodeEd25519JWK(jwk)
		if err != nil {
			// Fail-open: a malformed peer key is logged and skipped, never
			// fatal — the rest of the union still adopts cleanly.
			s.logger.Error("signingkeys: undecodable peer key, skipping",
				"replica_id", replicaID, "kid", jwk.Kid, "error", err)
			return "", false
		}
		if err := adopter.AdoptVerifyKey(jwk.Kid, pub); err != nil {
			s.logger.Error("signingkeys: adopt peer key failed, skipping",
				"replica_id", replicaID, "kid", jwk.Kid, "error", err)
			return "", false
		}
		s.logger.Info("signingkeys: adopted peer verify key",
			"replica_id", replicaID, "kid", jwk.Kid, "alg", jwk.Alg, "issuer", name)
		return jwk.Kid, true
	}
	s.logger.Debug("signingkeys: no matching-alg issuer for peer key, skipping",
		"replica_id", replicaID, "kid", jwk.Kid, "alg", jwk.Alg)
	return "", false
}

// dropAllAdopted drops every peer key this replica adopted from replicaID
// across every issuer that supports DropVerifyKey, and clears the tracking
// entry. Idempotent.
func (s *Server) dropAllAdopted(replicaID string) {
	s.adoptedPeerMu.Lock()
	kids := s.adoptedPeerKids[replicaID]
	delete(s.adoptedPeerKids, replicaID)
	s.adoptedPeerMu.Unlock()
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

// decodeError reports a peer JWK whose decoded public key is the wrong
// length for its key type.
type decodeError struct {
	kid    string
	gotLen int
}

func (e *decodeError) Error() string {
	return "signingkeys: peer key " + e.kid + ": unexpected ed25519 public key length"
}
