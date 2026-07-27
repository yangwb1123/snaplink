package clienttrust

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/trust"
)

// EventClientTrustThresholdCrossed is recorded when a client's freshly
// computed trust score crosses (edge-triggered, see crossedBelow) below an
// operator-configured threshold. It is an OPERATOR SIGNAL, not part of any
// outbound event vocabulary this package forwards — declared here rather
// than filed into platform/audit/auditspi's central catalogue, mirroring
// platform/lifecycle/webhook.EventWebhookDeliveryFailed (also a package-
// local audit.EventType const, also exempt from the auditspi completeness/
// SOC2-bucketing drift tests, which only walk auditspi's own event_types*.go
// files).
//
// This package builds NO new alerting mechanism: recording this event through
// ANY *audit.Recorder that has platform/lifecycle/webhook.Engine wired as a
// sink (sso.WithWebhookEngine, or an Engine composed directly) is enough for
// an operator's registered EventSubscription matching this type to receive a
// signed webhook POST — see updater_test.go / TestUpdateAndAlert_FiresWebhookOnThresholdCross.
const EventClientTrustThresholdCrossed audit.EventType = "client_trust_threshold_crossed"

// UpdateAndAlert recomputes clientID's trust score via scorer, persists it
// directly onto core.Client (ClientTrustScore/ClientTrustSetAt) through the
// EXISTING core.ClientStore.Update — see the note below for why this
// package does not invent a separate "ClientTrustStore" — and, on an edge-
// triggered threshold cross, records an EventClientTrustThresholdCrossed
// audit event via rec (nil-safe: a nil Recorder simply skips the alert,
// fail-open like every other audit-adjacent path in this SDK).
//
// # Why ClientStore.Update, not a new ClientTrustStore
//
// core.Client.ClientTrustScore/ClientTrustSetAt are additive fields on the
// EXISTING Client record (mirroring how core.Session already binds
// TrustScore/TrustSetAt directly on the session struct). Every
// core.ClientStore implementation's Update already replaces the whole
// Client by ID, so persisting a freshly computed score needs nothing more
// than Get -> mutate two fields -> Update: no new interface, no new
// backend-specific wiring beyond the additive SQLite columns already added
// in infrastructure/defaultimpl/sqlite/clients.go. A dedicated
// "ClientTrustUpdater" optional-extension interface (the
// RefreshTokenExpiryLister / clientrotation.ClientRotationLister pattern
// used elsewhere in this SDK for capabilities a backend may NOT support)
// would only be justified if some backends could persist the score more
// cheaply than a full Update, or if trust-score writes needed to bypass
// Update's existing side effects (secret re-hash checks) — neither holds
// here, so the extra interface would be pure ceremony over what Update
// already does.
//
// now is injected (not time.Now()) so callers — and this package's own
// tests — stay deterministic.
func UpdateAndAlert(ctx context.Context, store core.ClientStore, scorer *ClientTrustScorer, rec *audit.Recorder, clientID string, threshold float64, now time.Time) (trust.TrustScore, error) {
	client, err := store.Get(ctx, clientID)
	if err != nil {
		return trust.TrustScore{}, err
	}
	score, err := scorer.Score(ctx, trust.TrustSignals{ClientID: clientID, Time: now})
	if err != nil {
		return trust.TrustScore{}, err
	}

	previous, hadPrior := client.ClientTrustScore, !client.ClientTrustSetAt.IsZero()
	client.ClientTrustScore = score.Value
	client.ClientTrustSetAt = now
	if err := store.Update(ctx, client); err != nil {
		return trust.TrustScore{}, err
	}
	if crossedBelow(hadPrior, previous, score.Value, threshold) {
		emitThresholdAlert(ctx, rec, clientID, previous, score)
	}
	return score, nil
}

// crossedBelow reports whether this recompute is worth an alert:
//   - threshold <= 0 disables the gate entirely (no alert, ever).
//   - The FIRST-EVER score for a client (hadPrior false) is LEVEL-triggered:
//     a brand-new client whose very first computed score is already below
//     threshold (e.g. seeded with pre-existing bad activity) still deserves
//     a signal — there is no earlier "previous" edge to compare against.
//   - Every SUBSEQUENT recompute is EDGE-triggered: only a transition from
//     at-or-above to below threshold fires, so a client parked below
//     threshold across many recomputes alerts ONCE, not on every recompute.
func crossedBelow(hadPrior bool, previous, current, threshold float64) bool {
	if threshold <= 0 {
		return false
	}
	if !hadPrior {
		return current < threshold
	}
	return previous >= threshold && current < threshold
}

// emitThresholdAlert records the operator-facing audit event. rec is
// nil-safe (audit.Recorder.Record already no-ops on a nil receiver, but the
// explicit guard here also skips building the event when there is nowhere
// for it to go).
func emitThresholdAlert(ctx context.Context, rec *audit.Recorder, clientID string, previous float64, score trust.TrustScore) {
	if rec == nil {
		return
	}
	e := &audit.Event{
		Type:     EventClientTrustThresholdCrossed,
		Outcome:  audit.OutcomeFailure,
		ClientID: clientID,
	}
	audit.SetMeta(e, "previous_score", strconv.FormatFloat(previous, 'f', 4, 64))
	audit.SetMeta(e, "current_score", strconv.FormatFloat(score.Value, 'f', 4, 64))
	if len(score.Reasons) > 0 {
		audit.SetMeta(e, "reasons", strings.Join(score.Reasons, ","))
	}
	rec.Record(ctx, e)
}
