package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/snaplink/sso/platform/cluster"
	"github.com/snaplink/sso/platform/metrics"
	"github.com/snaplink/sso/shared/spi"
)

// CrossReplicaDeps is the interface for cross-replica revocation.
type CrossReplicaDeps interface {
	SrvLogger() spi.Logger
	Metrics() *metrics.Metrics
	CrossReplicaRevocationEnabled() bool
	InvalidationBus() cluster.Bus
	RevokeAcrossIssuers(ctx context.Context, token string) ([]string, []string)
}

// JWTExpUnsafe extracts the exp claim from a compact JWT without verifying the signature.
func JWTExpUnsafe(token string) int64 {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return 0
	}
	return claims.Exp
}

// JWTClaimsUnsafe extracts client_id + sub from a compact JWT WITHOUT
// verifying the signature — mirrors JWTExpUnsafe's existing "advisory only,
// never a security decision" contract, extended to the two identifiers the
// token_revoked audit event (see audit.RecordTokenRevoked) annotates itself
// with. The token was already revoked via the verified per-issuer Revoke
// path before either unsafe extractor runs, so a malformed/foreign token (or
// one issued by a strategy that doesn't stamp these claims) just yields empty
// strings rather than an error — a decode failure must never block the
// revocation or its audit record.
func JWTClaimsUnsafe(token string) (clientID, subject string) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ""
	}
	var claims struct {
		ClientID string `json:"client_id"`
		Subject  string `json:"sub"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return "", ""
	}
	return claims.ClientID, claims.Subject
}

// PublishTokenRevocation broadcasts a token revocation to peer replicas so each
// armed replica can add the token to its own in-process deny-set. The detail
// rides Event.Payload (MetaRevokedToken + advisory MetaRevokedExp) per the
// cluster.Bus contract — the receiver re-decodes the token itself, so exp is
// advisory only. Best-effort and fail-open: a publish error is logged and
// swallowed because the local revoke already succeeded and cross-replica
// propagation is purely additive. The success metric is nil-guarded so an
// unwired Metrics is a no-op, not a panic.
func PublishTokenRevocation(d *ServerDeps, ctx context.Context, token string, exp int64) {
	if !d.CrossReplicaRevocation || d.InvalidationBus == nil || token == "" {
		return
	}
	evt := cluster.Event{
		Kind: cluster.KindTokenRevoked,
		Payload: map[string]string{
			cluster.MetaRevokedToken: token,
			cluster.MetaRevokedExp:   strconv.FormatInt(exp, 10),
		},
	}
	if err := d.InvalidationBus.Publish(ctx, evt); err != nil {
		d.Logger.Error("invalidation bus publish failed", "kind", string(evt.Kind), "error", err)
		return
	}
	if d.Metrics != nil {
		d.Metrics.TokenRevocationsPropagatedTotal.WithLabelValues(metrics.RevocationDirectionPublished).Inc()
	}
}

// ApplyTokenRevocation is the cluster.KindTokenRevoked arm of the bus
// subscriber. It ADDS the carried token to this replica's per-issuer deny-set
// via the LOCAL-ONLY revoke seam — d.RevokeAcrossIssuers is wired to the
// unexported local revoke that never touches the bus, so adoption does NOT
// re-publish (no broadcast loop). A token no local issuer owns is a clean
// no-op; per-issuer errors are swallowed because the origin replica already
// audited the user-facing revoke, so a malformed or foreign Event can never
// reject a valid token here. Only a successful adoption is counted, and only
// when Metrics is wired.
func ApplyTokenRevocation(d *ServerDeps, ctx context.Context, evt cluster.Event) {
	if !d.CrossReplicaRevocation {
		return
	}
	if evt.Kind != cluster.KindTokenRevoked {
		return
	}
	token := evt.Payload[cluster.MetaRevokedToken]
	if token == "" {
		return
	}
	revoked, _ := d.RevokeAcrossIssuers(ctx, token)
	if len(revoked) > 0 && d.Metrics != nil {
		d.Metrics.TokenRevocationsPropagatedTotal.WithLabelValues(metrics.RevocationDirectionAdopted).Inc()
	}
}
