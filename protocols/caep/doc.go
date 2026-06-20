// Package caep implements a dependency-free transmitter for the OpenID
// Shared Signals Framework (SSF) v1 — the CAEP + RISC push profile that
// turns the IdP into a real-time broadcaster of Security Event Tokens
// (SETs, RFC 8417) to relying parties' registered receiver endpoints.
//
// # Why
//
// Without it, "instantly revoke a user across N RPs" relies on access
// token TTL or RPs polling /revoke. CAEP lets the IdP PUSH a signed SET
// the moment a revocation / suspension / refresh-token-reuse event
// occurs, so each affected RP can drop its session immediately instead of
// waiting out a token lifetime.
//
// # How it reuses existing machinery (zero new deps)
//
//   - SET signing reuses the generic-JWT path of the SAME signing issuer
//     that mints access + ID + logout tokens (JWTSigner.SignJWT, typ
//     "secevent+jwt"). The SET verifies against the key already published
//     in JWKS, so an RP validates it with NO new trust setup. It is NOT
//     the access-token Issue path (which stamps typ at+jwt).
//   - Delivery composes as an audit.Sink: the Transmitter taps the audit
//     pipeline, maps the small mapped subset of internal events (see
//     event_mapper.go) onto SSF event URIs, and POSTs SETs ASYNC +
//     best-effort, mirroring the audit Async/Retry/Webhook + CIBA-ping
//     supervision (bounded timeout + recover + metric + failure audit).
//   - Receiver registration lives in core.Client.Attributes
//     ("caep_receiver_endpoint" + "caep_receiver_auth"), validated https
//     at client create/update — the address is NEVER taken from request
//     input (anti-exfil).
//
// # Scoping (the security crux)
//
// A SET is pushed ONLY to the AFFECTED client's receiver, never broadcast
// to every receiver (which would leak one RP's user's revocation to all
// RPs). v1 scopes by:
//
//   - a client-named event (refresh-token-family reuse) → that one
//     client's receiver;
//   - a tenant-wide event (tenant tokens revoked / suspension) → each
//     client OF THAT TENANT, resolved via TenantScopedClientStore;
//   - admin token revoke → the explicitly-named affected client only.
//
// Receivers are resolved FRESH from the ClientStore at send time (no
// cache, no cluster bus) — the simplest design that avoids a
// cache-coherence problem.
//
// # Opt-in / fail-open
//
// Wire via sso.WithCAEPTransmitter; unwired ⇒ no-op, byte-identical.
// Broadcasting is fail-open: it can never affect the triggering operation
// (the revocation already happened locally), and a slow/dead receiver
// drops the SET (metric sso_caep_sets_total{outcome} + caep_broadcast_failed
// audit) without retry on the hot path.
//
// # Out of scope (v2)
//
// Stream Management API (RFC 8935/8936 receiver-driven config), encrypted
// SETs (JWE), richer RFC 9493 subject identifiers, and multi-RP-per-subject
// fan-out via the BCL subject-client index. v1 deliberately does NOT
// broadcast-to-all as a substitute for that fan-out.
package caep
