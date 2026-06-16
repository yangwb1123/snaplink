package handler

import (
	"context"

	"github.com/snaplink/sso/metrics"
	"github.com/snaplink/sso/spi"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/snaplink/sso/cluster"
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

// PublishTokenRevocation broadcasts a token revocation to peer replicas.
func PublishTokenRevocation(d *ServerDeps, ctx context.Context, token string, exp int64) {
	if !d.CrossReplicaRevocation {
		return
	}
	if d.InvalidationBus == nil {
		return
	}
	evt := cluster.Event{
		Kind: cluster.KindTokenRevoked,
		Key:  token,
	}
	if err := d.InvalidationBus.Publish(ctx, evt); err != nil {
		d.Logger.Error("cross-replica revocation publish failed", "error", err)
		d.Metrics.TokenRevocationsPropagatedTotal.WithLabelValues("publish").Inc()
	}
}

// ApplyTokenRevocation processes an inbound revocation event from a peer replica.
func ApplyTokenRevocation(d *ServerDeps, ctx context.Context, evt cluster.Event) {
	if evt.Kind != cluster.KindTokenRevoked {
		return
	}
	revoked, failed := d.RevokeAcrossIssuers(ctx, evt.Key)
	if len(revoked) > 0 {
		d.Logger.Info("cross-replica revocation adopted", "token_prefix", evt.Key[:8], "revoked", len(revoked))
	}
	if len(failed) > 0 {
		d.Logger.Error("cross-replica revocation adopt failed", "token_prefix", evt.Key[:8], "failed", len(failed))
	}
	d.Metrics.TokenRevocationsPropagatedTotal.WithLabelValues("adopted").Inc()
}
