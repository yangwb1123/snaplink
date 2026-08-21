package webhook

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/yangwb1123/snaplink/shared/core"
)

// MountRoutes registers the webhook-egress admin surface (subscription
// management + dead-letter inspection/replay, all under /api/v1/admin/webhooks)
// on the /api/v1 admin group, wrapped in a core.GatedRouter keyed on the
// AdminAPI live gate. Byte-identical to the registration interfaces/sso
// performed before this direction: the routes mount only when
// WithWebhookEngine supplied an engine. The backchannel-logout failure admin
// surface (protocols/oidc/bcl) stays registered by interfaces/sso — its
// closures call bcl directly and never crossed this package's boundary.
// gate must be non-nil — the Server's live adminAPIGateOn method value; nil
// is a programmer error.
func MountRoutes(r core.Router, d HandlerDeps, gate func() bool) {
	if gate == nil {
		panic("webhook: MountRoutes requires a non-nil gate")
	}
	if webhookRuntime(d) == nil {
		return
	}
	api := core.NewGatedRouter(r.Group(core.PathAPIPrefix), gate)
	api.GET(core.PathAdminWebhookSubscriptions, func(ctx core.HandlerContext) { HandleListSubscriptions(d, ctx) })
	api.POST(core.PathAdminWebhookSubscriptions, func(ctx core.HandlerContext) { HandleCreateSubscription(d, ctx) })
	api.DELETE(core.PathAdminWebhookSubscriptionByID, func(ctx core.HandlerContext) { HandleDeleteSubscription(d, ctx) })
	api.GET(core.PathAdminWebhookDeadLetters, func(ctx core.HandlerContext) { HandleListDeadLetters(d, ctx) })
	api.POST(core.PathAdminWebhookDeadLetterReplay, func(ctx core.HandlerContext) { HandleReplayDeadLetter(d, ctx) })
}

// newID returns a random hex identifier for a subscription or dead-letter
// entry.
func newID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
