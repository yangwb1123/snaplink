package sso

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/snaplink/sso/cluster"
	"github.com/snaplink/sso/metrics"
)

// Cross-replica access-token revocation propagation (opt-in,
// WithCrossReplicaRevocation; nil-bus / unarmed = byte-identical off).
//
// THE GAP. Each JWT issuer holds an in-process revocation deny-set (the
// `revoked` map keyed by the full token, see defaultimpl). /token/revoke adds
// the presented token to that deny-set — but only on the replica that handled
// the request. A token revoked on replica A keeps validating on replica B until
// its own exp. The Redis hot-path peers cover session/refresh/etc. but NOT this
// deny-set; CAEP pushes to external RPs, not the server's own replicas.
//
// THE FIX. A local revoke that hit at least one issuer PUBLISHES a
// cluster.KindTokenRevoked Event; every armed replica that receives it ADDS the
// token to its own deny-set via the SAME local revoke-across-issuers path,
// WITHOUT re-publishing. The publish side and the adopt side are deliberately
// DISTINCT methods so the adopt can never re-emit — there is no broadcast loop.
//
// THE SAFETY MODEL. Propagation is purely ADDITIVE: applying an Event only ever
// ADDS a token to a deny-set (more tokens rejected, never fewer). A token
// rejected because it's in the deny-set returns the SAME invalid_token response
// as any other validation failure — no caller-observable new code path. A
// dropped/garbage Event just leaves a replica at today's per-replica behavior
// (the token still expires on its own exp) — fail-open, never a valid token
// wrongly rejected (beyond the mesh-internal trusted bus, which is trusted
// exactly like KindTenantSuspension). The adopt path takes input ONLY from the
// bus, never from a request.

// publishTokenRevocation broadcasts a KindTokenRevoked Event after a LOCAL
// revoke-across-issuers that actually hit an issuer, so every armed peer adds
// the token to its own deny-set. It is called from the accessor RevokeAcrossIssuers
// (the /token/revoke + /end_session revoke seam) AFTER the local revoke; the
// subscribe arm (applyTokenRevocation) does NOT call it, so adoption never
// re-publishes.
//
// Best-effort + fail-open: a publish error is logged and swallowed (the local
// revoke already succeeded; peers fall back to their own per-replica behavior),
// mirroring PublishSigningKeyRotation / InvalidateTenantSuspensionCache. No-op
// (zero overhead) when WithCrossReplicaRevocation isn't armed or no bus is
// wired, so the caller may invoke it unconditionally.
//
// exp is the revoked token's `exp` (unix seconds) — carried so the receiver can
// record an exp-bounded deny-set entry without re-deriving it, though the
// receiver re-decodes the token anyway, so a missing/garbage exp is harmless.
func (s *Server) publishTokenRevocation(ctx context.Context, token string, exp int64) {
	if !s.crossReplicaRevocation || s.invalidationBus == nil {
		return
	}
	if token == "" {
		return
	}
	evt := cluster.Event{
		Kind: cluster.KindTokenRevoked,
		Payload: map[string]string{
			cluster.MetaRevokedToken: token,
			cluster.MetaRevokedExp:   strconv.FormatInt(exp, 10),
		},
	}
	if err := s.invalidationBus.Publish(ctx, evt); err != nil {
		s.logger.Error("invalidation bus publish failed",
			"kind", string(evt.Kind), "error", err)
		return
	}
	if s.metrics != nil {
		s.metrics.TokenRevocationsPropagatedTotal.
			WithLabelValues(metrics.RevocationDirectionPublished).Inc()
	}
}

// applyTokenRevocation is the cluster.KindTokenRevoked arm of the bus
// subscriber (dispatched from applyInvalidation). It ADDS the carried token to
// this replica's per-issuer deny-set via the LOCAL-ONLY revokeAcrossIssuers —
// which never publishes — so adoption can NOT trigger a fan-out loop.
//
// No-op unless WithCrossReplicaRevocation armed this replica (byte-identical to
// a build without the feature otherwise; the Event may still ride the bus for
// armed peers). The input is the bus Event ONLY — never a request — so this adds
// no request-facing trust surface.
//
// Additive + fail-open: revokeAcrossIssuers only ever ADDS the token to a
// deny-set. A token no local issuer owns is a clean no-op (revoked empty); a
// per-issuer error is swallowed (the local revoke path already classifies it),
// so a malformed/foreign Event can never reject a valid token here.
func (s *Server) applyTokenRevocation(ctx context.Context, evt cluster.Event) {
	if !s.crossReplicaRevocation {
		return
	}
	token := evt.Payload[cluster.MetaRevokedToken]
	if token == "" {
		return
	}
	// LOCAL-only revoke: revokeAcrossIssuers adds to each owning issuer's
	// in-process deny-set and never touches the bus, so adoption does NOT
	// re-publish (no broadcast loop). The (revoked, failed) split is irrelevant
	// here — we don't audit a partial-revoke for a propagated adoption (the
	// origin replica already audited the user-facing revoke); we only count a
	// successful adoption for observability.
	revoked, _ := s.revokeAcrossIssuers(ctx, token)
	if len(revoked) > 0 && s.metrics != nil {
		s.metrics.TokenRevocationsPropagatedTotal.
			WithLabelValues(metrics.RevocationDirectionAdopted).Inc()
	}
}

// jwtExpUnsafe reads the `exp` claim (unix seconds) from a compact-JWS payload
// WITHOUT verifying anything — used only to populate the advisory exp on a
// published KindTokenRevoked Event. The publish site has already validated +
// revoked the token via the issuer, so the payload is trustworthy here; the
// RECEIVER never trusts this value (it re-decodes the token itself), so an
// unverified read carries no risk. Returns 0 for an opaque token, a malformed
// payload, or a missing exp — the receiver tolerates a zero/garbage exp.
func jwtExpUnsafe(token string) int64 {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0
	}
	var p struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return 0
	}
	return p.Exp
}
