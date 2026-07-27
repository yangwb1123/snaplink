package health

import (
	"net/http"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

// DefaultCertExpiryWarning is the "expiring soon" alert threshold applied
// when Deps.FederationCertExpiryWarning returns <= 0 (unconfigured). 30 days
// is the conventional operational lead time to renew a TLS certificate.
const DefaultCertExpiryWarning = 30 * 24 * time.Hour

// Deps is what HandleListPeerHealth needs from the host server — the same
// hexagonal seam federation.Deps/FetchDeps use (*sso.Server satisfies it via
// accessors; the handler body lives beside the domain logic it reports on,
// not in the delivery-edge package).
type Deps interface {
	// FederationConnectionHealth returns the wired health store, or nil when
	// health tracking was never configured. The admin route is unmounted
	// whenever this is nil, so a caller reaching HandleListPeerHealth with a
	// nil store only happens on a wiring bug; handled defensively below.
	FederationConnectionHealth() ConnectionHealth
	// FederationCertExpiryWarning is the config-gated "expiring soon"
	// threshold. <= 0 ⇒ DefaultCertExpiryWarning.
	FederationCertExpiryWarning() time.Duration
	// FederationHealthNow is the clock the `cert_expiring` classification is
	// computed against. Injected (not a direct time.Now) so a test drives a
	// fixed instant through both the recorded observations and this handler.
	FederationHealthNow() time.Time
}

// peerHealthView is the wire (JSON) projection of PeerHealth: it adds the
// DERIVED cert_expiring flag (this handler applies the threshold — a
// ConnectionHealth store has no notion of it) and renders zero times as
// omitted fields rather than Go's zero-time string.
type peerHealthView struct {
	PeerID              string     `json:"peer_id"`
	LastSuccessAt       *time.Time `json:"last_success_at,omitempty"`
	LastFailureAt       *time.Time `json:"last_failure_at,omitempty"`
	LastError           string     `json:"last_error,omitempty"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	CertNotAfter        *time.Time `json:"cert_not_after,omitempty"`
	CertExpiring        bool       `json:"cert_expiring"`
}

// HandleListPeerHealth serves GET .../federation/health: every tracked
// federation peer's fetch-path health (last success/failure time,
// consecutive-failure count, last-observed TLS certificate expiry) plus a
// derived cert_expiring flag against the config-gated threshold. This is a
// QUERYABLE LIST, not an active push/alert channel (AGENTS.md: "surfaced as a
// queryable list, not an active push notification system") — PURE
// OBSERVABILITY, never consulted by trust-chain validation.
func HandleListPeerHealth(deps Deps, ctx core.HandlerContext) {
	store := deps.FederationConnectionHealth()
	if store == nil {
		// Defense in depth: the route is unmounted whenever no store is
		// wired, so reaching here means a wiring bug. An empty list is a
		// safe, non-crashing answer either way.
		ctx.JSON(http.StatusOK, map[string]any{"peers": []peerHealthView{}})
		return
	}
	threshold := deps.FederationCertExpiryWarning()
	if threshold <= 0 {
		threshold = DefaultCertExpiryWarning
	}
	now := deps.FederationHealthNow()
	peers := store.List()
	views := make([]peerHealthView, 0, len(peers))
	for _, p := range peers {
		views = append(views, toPeerHealthView(p, now, threshold))
	}
	ctx.JSON(http.StatusOK, map[string]any{
		"peers":                       views,
		"cert_expiry_warning_seconds": int(threshold.Seconds()),
		"generated_at":                now.UTC().Format(time.RFC3339Nano),
	})
}

// toPeerHealthView projects one PeerHealth into its wire shape, applying the
// cert_expiring threshold classification.
func toPeerHealthView(p PeerHealth, now time.Time, threshold time.Duration) peerHealthView {
	v := peerHealthView{
		PeerID:              p.PeerID,
		LastError:           p.LastError,
		ConsecutiveFailures: p.ConsecutiveFailures,
		CertExpiring:        p.ExpiresWithin(now, threshold),
	}
	if !p.LastSuccessAt.IsZero() {
		t := p.LastSuccessAt
		v.LastSuccessAt = &t
	}
	if !p.LastFailureAt.IsZero() {
		t := p.LastFailureAt
		v.LastFailureAt = &t
	}
	if !p.CertNotAfter.IsZero() {
		t := p.CertNotAfter
		v.CertNotAfter = &t
	}
	return v
}
