# Design: user lifecycle transitions over the CAEP/SSF event channel

Design for the deferred-backlog "User lifecycle" future-work boundary:
*A standardized event channel for resource servers that validate JWTs fully
offline remains future work.* All file/line references were verified against
executable code before writing.

Goal: when a user's lifecycle state changes (SUSPENDED / INACTIVE / ARCHIVED /
PURGED / INVITED, or back to ACTIVE), the CAEP/SSF transmitter pushes a signed
Security Event Token (SET) to the **affected** relying parties so an RP that
validates JWTs fully offline can terminate/refuse the subject's access (or
resume honoring it) without waiting for token TTL — the standard answer to the
offline-validation gap.

Data flow after the change (no new instrumentation point; both taps already
exist):

```text
admin handler / sweep
  → Store.Append + RecordTransition          # domains/userlifecycle/sweep.go:162
  → audit.Recorder.Record(EventAdminUserLifecycleChanged)
  → [LifecycleEventBus.Record (unchanged)]   # bus.go:162 — reaction dispatch
  → [caep.Transmitter.Record (extended)]     # mapAuditEvent gains one case
  → scopeUser: TenantUserStore.ListByUser → TenantScopedClientStore.ListByTenant
  → mint + sign + async POST SET (per receiver, registered endpoint only)
```

---

## Decision 1 — Event types, SET subject, and affected-client derivation

**Event types: the standard OpenID CAEP/RISC URIs already known to this
codebase — never a custom snaplink event URI.** The whole point of SSF is that
a resource server with an off-the-shelf SET pipeline reacts to events it
already knows; a snaplink-specific URI would force every RP to ship
snaplink-specific handling, which is exactly the interoperability the standard
exists to avoid. The receiver half (`protocols/caep/receiver_receive.go`
`knownReceiverEvent`) already treats `account-disabled` and `session-revoked`
as actionable and safely no-ops any other valid URI, so emitting only standard
URIs keeps the receive side untouched (decision 4).

Per-target-state mapping (from the transition's `to_state` metadata):

| `to_state` | Emitted `events` claim | Semantics the RP acts on |
|---|---|---|
| `suspended`, `inactive`, `archived`, `purged`, `invited` | `risc/account-disabled` + `caep/session-revoked` | refuse further access, terminate sessions — the offline mirror of the local `RevokeAccessOnArchive` reaction |
| `active` | `risc/account-enabled` | resume honoring the subject — the positive counterpart so an RP that disabled the account on `account-disabled` is told to re-enable it (e.g. SUSPENDED→ACTIVE reinstatement, ARCHIVED→ACTIVE restore) |

The active/non-active split reuses the domain's own predicate
`userlifecycle.AllowsAuthentication(state)` (the single source of truth for
"this state may authenticate"), so the mapping can never drift from the
lifecycle semantics. `account-enabled` is deliberately NOT added to the
receiver's actionable set: the stock receiver no-ops it (ack + nothing), and
decision 4 forbids touching the receive side.

**SET subject (`sub_id`)** comes straight from the transition context: the
`target_user` metadata every `RecordTransition` stamps
(`domains/userlifecycle/sweep.go:16-18`, `MetaTargetUser`), carried as the
existing RFC 9493 opaque `{format:"opaque", id:<userID>}` shape. No new
metadata key: `from_state`/`to_state`/`reason` already cover the "who moved
which account" record, and `MetaSubject` stays reserved for admin-actor
events where `ActorID` is not the affected end-user (here `ActorID` is the
admin/system actor — the affected end-user is the target_user metadata).

**Affected clients** derive from the **tenant dimension** — the AGENTS.md rule
"tenant events query only that tenant". A lifecycle transition is a
user-level event, so the broadcaster resolves the affected RPs as:
`TenantUserStore.ListByUser(userID)` → each of the user's own tenants →
`TenantScopedClientStore.ListByTenant(tenantID)` → keep only clients opted
into SSF via their **registered** `AttrReceiverEndpoint`/`AttrReceiverMQTTTopic`
metadata. `ListByTenant` is called per membership and never across tenants, so
a transition for a user of tenant T can never fan out to tenant U's clients
(the existing `TestCAEPNoCrossTenantLeak` invariant, extended to the user
scope). This is a new `scopeUser` in `mappedEvent`; `MetaAffectedClient`
remains the admin_token_revoked-specific single-client override and is not
repurposed.

Conservative silence where the derivation cannot be trusted: no `TenantUserStore`
wired, no membership, an unknown target user, an unrecognized `to_state`, or a
store error → **no broadcast** (the same posture as `admin_token_revoked`
without `MetaAffectedClient`, and `tenant_tokens_revoked` without a tenant
actor). A user with no resolvable tenant is not broadcast to "all clients" —
that would be the wrong-receiver leak decision 2 of `event_mapper.go` exists
to prevent. **Consequence for the stock binary**: `cmd/sso-server` does not
wire a `TenantUserStore` today (verified: no `WithTenantUserStore` call in
`cmd/`), so the stock build resolves lifecycle events to zero receivers —
documented boundary, not a regression; SDK/B2B compositions that wire
membership (the same store `sso.WithTenantUserStore` takes) get the fan-out by
passing it to `caep.WithTenantUserStore`.

## Decision 2 — Wiring point: extend `mapAuditEvent`, not a bus reaction

**Wire by adding one case to the existing broadcaster's audit-event mapping
(`protocols/caep/event_mapper.go`), NOT by registering an `On`/`OnAsync`
reaction on `LifecycleEventBus`.** Evidence, from executable code:

- The CAEP `Transmitter` is already an `audit.Sink` composed into the audit
  pipeline: `interfaces/sso/sso.go:144-159` (`applyAuditSinkTaps`) adds it to
  the recorder whenever `WithCAEPTransmitter` + `WithAuditRecorder` are wired.
- `RecordTransition` (`domains/userlifecycle/sweep.go:162-176`) already emits
  `EventAdminUserLifecycleChanged` for **every** transition — admin- and
  sweep-driven alike — through `rec.Record`. The `LifecycleEventBus.Record`
  (sink path, `bus.go:162-177`) consumes the *same* event; so does the
  transmitter once mapped. **No new instrumentation point at either call
  site**, and the stock bus wiring (store-observer path,
  `cmd/sso-server/build_stores.go:393-410`) needs no change.
- A bus `On`/`OnAsync` reaction would have to re-implement the entire
  broadcast path — SET minting/signing by the trusted JWKS key, fresh receiver
  resolution, tenant scoping, per-receiver async goroutines, retry, delivery
  failure audit (`caep_broadcast_failed`), metrics — a **second emission
  channel**, which is explicitly forbidden. The audit-sink mapping reuses all
  of it unchanged.

**No overlap / no double emission with `RevokeAccessOnArchive`.** The reaction
is a LOCAL revocation: `ObserveTransitions` (store observer, `build_stores.go`)
calls `bus.Dispatch`, and `RevokeAccess` destroys sessions + deletes refresh
tokens directly through the store SPIs (`lifecyclereactions/revoke_on_archive.go`).
Those store operations emit **no mapped audit event** — verified:
`EventAdminTokenRevoked` is only produced by the gRPC admin token-revoke
handler (`interfaces/grpcserver/grpcadmin/admin_tokens.go:182`),
`EventRefreshTokenReuse` only by family-reuse detection, `EventTenantTokensRevoked`
only by tenant suspension (`interfaces/sso/server_tenant.go:347`). The SET
emission rides the lifecycle event itself, so exactly one SET per transition;
the acceptance test asserts this explicitly (single emission, reaction fired
once).

## Decision 3 — Failure modes: fail-open + audit, never blocking

- **Broadcast failures** reuse the existing `caep_broadcast_failed` path:
  `Transmitter.fail` (`broadcaster.go:423-441`) counts the drop, logs, and
  records the internal audit event (receiver + reason) via the
  `WithFailureRecorder` seam. Delivery is best-effort by contract — the
  transition already committed locally, so a dead receiver can never roll it
  back.
- **Resolution failures** (tenant-store lookup error, client-store error, no
  membership) return zero receivers — silent, matching the existing
  scopeTenant/scopeClient fail-open (`resolveClients` returns nil on error).
- **Non-blocking**: `Transmitter.Record` maps cheaply, resolves locally, and
  dispatches each POST to its own supervised goroutine (`context.WithoutCancel`),
  so the admin HTTP handler and the sweep loop are never delayed by a slow
  receiver — the existing `TestCAEPNonBlocking` invariant.
- **Reaction semantics unchanged**: `LifecycleEventBus` dispatch (sync/async,
  timeout, panic containment) and `RevokeAccessOnArchive` are not modified.

## Decision 4 — Hard boundaries

1. **CAEP receive side untouched**: `receiver.go`, `receiver_receive.go`,
   `receiver_construct.go`, `knownReceiverEvent` are unchanged.
   `account-enabled` is emitted but intentionally not actionable
   (`selectActionableEvents` drops it → ack + no-op).
2. **Existing revocation-reaction semantics unchanged**: `lifecyclereactions/`
   is not modified.
3. **No new wire config keys**: the transmitter gains one construction-time SDK
   option, `caep.WithTenantUserStore(core.TenantUserStore)` — the same
   seam family as `WithHTTPClient`/`WithFailureRecorder`, mirroring the
   existing `NewTransmitter` type-assertion pattern. No YAML knob, so
   `docs/config-reference.md` is untouched. `DefaultSSFSupportedEvents`
   (the `/.well-known/ssf-configuration` advertisement) gains the one new
   emitted URI so RPs can subscribe to it.
4. **Zero exemptions, budgets respected**: no new `layerExemptions`,
   `fileSizeExemptions`, or fan-out exemption entries. `protocols/caep` is at
   the 10-file non-test ceiling, so the new code is folded into existing files;
   `broadcaster.go` (499 lines) stays under budget by relocating the
   `resolveClients` method to `broadcaster_retry.go` (201 lines) where the
   `scopeUser` case and tenant resolution live.
5. **No new upward dependency**: `protocols/caep` (rank 3) imports
   `domains/userlifecycle` (rank 2) for the metadata keys + state predicate —
   a downward edge, legal per `architecture_layer_test.go`; the imported
   package imports only platform/shared, so no cycle.

## Decision 5 — Acceptance assertions (implemented as tests)

1. A committed transition to a non-active state → the affected tenant's
   opted-in client receives exactly one signature-verified SET
   (`aud` = that client, `sub_id.id` = the user, `events` contains
   `account-disabled` + `session-revoked`).
2. A client of a different tenant receives **zero** SETs (tenant isolation).
3. A delivery failure (receiver returns 5xx) → `caep_broadcast_failed` audit
   event recorded, and the transition still commits (fail-open).
4. An unresolvable scope (no `TenantUserStore`, no membership, missing
   `target_user`, invalid `to_state`) → zero SETs.
5. A transition back to ACTIVE → SET carries `account-enabled` (and nothing
   else).
6. One transition through a recorder with BOTH the bus and the transmitter
   wired → exactly one SET and exactly one reaction invocation (no double
   emission).
7. Integration: a real `sso.Server` wired with user-lifecycle store + audit
   recorder + CAEP transmitter + tenant-membership store delivers the SET to
   the affected client and only the affected client, for admin-driven and
   sweep-driven transitions alike.

## Implementation surface

| File | Change |
|---|---|
| `protocols/caep/event_mapper.go` | `scopeUser` kind, `mappedEvent.userID`, `mapLifecycleChanged` + switch case |
| `protocols/caep/security_event_token.go` | `EventURIRISCAccountEnabled` URI constant |
| `protocols/caep/broadcaster.go` | `tenants core.TenantUserStore` struct field; `resolveClients` relocated out |
| `protocols/caep/broadcaster_retry.go` | `WithTenantUserStore` option; `resolveClients` + `resolveLifecycleClients` |
| `protocols/caep/receiver.go` | `DefaultSSFSupportedEvents` += `account-enabled` (advertisement only) |
| `protocols/caep/transmitter_lifecycle_test.go` | unit + bus→transmitter tests (1-6) |
| `test/lifecycle_caep_e2e_test.go` | integration test (7) |
| `docs/feature-matrix.md`, `docs/deferred-backlog.md`, `CHANGELOG.md` | contract sync |
