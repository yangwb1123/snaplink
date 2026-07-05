// Package webhook implements the generic event/webhook egress engine: an
// operator-facing SPI (EventSubscription + SubscriptionStore) that lets an
// admin register "POST this event vocabulary to this URL, signed with this
// secret" at RUNTIME, plus an Engine that taps the SAME audit pipeline every
// other observability consumer (CAEP/SSF, the realtime SSE admin stream)
// taps.
//
// # Why
//
// protocols/caep already lets the IdP push SIGNED, real-time revocation
// signals to relying parties — but it is a FIXED, narrow event vocabulary
// (CAEP/RISC), scoped to receivers registered on a core.Client's own
// Attributes. Many integrations (SIEM ingestion, a ticketing system reacting
// to admin_credential_compromised, a partner pipeline watching user
// lifecycle events) want an arbitrary SUBSET of the full audit vocabulary
// pushed to an arbitrary destination the OPERATOR controls at runtime — not
// a client, not fixed at compile time. This package is that general-purpose
// fan-out.
//
// # How it reuses existing machinery (zero new wire format)
//
//   - Delivery composes as an audit.Sink exactly like protocols/caep's
//     Transmitter: wired via sso.WithWebhookEngine, the same
//     AddSink/MultiSink seam, so it taps the existing event pipeline with no
//     change to how audit events are recorded elsewhere.
//   - HMAC signing + the retry/backoff delivery loop reuse
//     platform/audit/auditsink's WebhookSink + RetryingSink UNCHANGED — the
//     same primitives platform/audit's own audit.webhook config section uses
//     for the single, statically-configured audit-log webhook. This engine
//     adds the missing piece: MULTIPLE, DYNAMICALLY-REGISTERED destinations,
//     each independently signed, filtered, and retried.
//   - The signature header/format (X-Signature: t=<unix>,v1=<hex>) is
//     shared/security/securityverify's WebhookSignatureHeader — the SAME
//     scheme a receiver already speaks if it verifies the audit-log webhook
//     or an MFA push-transport webhook.
//
// # Event vocabulary
//
// EventSubscription.EventTypes is a set of platform/audit.EventType values —
// the SAME catalog every other audit consumer sees (login, token lifecycle,
// admin mutations, CAEP broadcasts, ...). There is no parallel "webhook
// event" taxonomy: whatever you can audit, you can subscribe to. A
// subscription with no configured EventTypes matches nothing — there is no
// implicit "everything" wildcard, so a newly-registered subscription can
// never surprise its owner with an unexpected firehose.
//
// # Retry + dead-letter
//
// A delivery that exhausts its retry budget (auditsink.RetryingSink,
// jittered exponential backoff) is recorded to a bounded DeadLetterStore —
// queryable via GET /api/v1/admin/webhooks/deadletters and replayable via
// POST .../deadletters/{id}/replay, which re-resolves the subscription
// FRESH (a since-rotated secret or since-edited URL is honored, mirroring
// CAEP's "resolve fresh, no cache" philosophy) and attempts one more
// delivery.
//
// # Opt-in / fail-open
//
// Wire via sso.WithWebhookEngine; unwired ⇒ no admin routes, no sink tap —
// byte-identical to a build without this feature. Wired with ZERO
// registered subscriptions ⇒ Record is a cheap no-match no-op: zero outbound
// traffic, zero goroutines. Matching + dispatch never block the audit
// Recorder's caller, and a delivery failure can never affect the triggering
// operation (fail-open, same contract as CAEP broadcast).
package webhook
