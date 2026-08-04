# Security Review: `domains/tokenexchange` audit observability design

Subject: `docs/auto/domains-tokenexchange-audit-design.md` (deny event,
chain-hop correlation keys, mint jti join, section-4 placement plan).

Method: every line reference and structural claim in the design was
re-verified against the tree by direct read/grep (no Go gates run — this is a
docs-only review; the design's own verification sequence for implementation
is re-affirmed in §5). Claims below are labeled **Verified**, **Partial**,
**Refuted**, or **Proposed** per `ai-dev/prompts/README.md`.

## 0. Verification result headline

The design's two "constraints the spec didn't surface" (file budgets,
10-file ceiling) are **Verified** and materially real:

- `internal/handler/tokengrant/token_exchange.go` = 499 lines,
  `token_exchange_stages.go` = 495 (`wc -l`); `maxFileLines = 500`
  (`maintainability_budget_test.go:34`), `fileSizeExemptions` frozen empty,
  `maxFileSizeExemptions = 0` (`:136-141`).
- `internal/handler/tokengrant` holds exactly 10 non-test `.go` files
  (authcode, ciba, client_credentials, device, exchange, exchange_stages,
  jwt_bearer, refresh, saml2_bearer, refresh_grace); `maxGoFilesPerDir = 10`
  (`directory_fanout_test.go:34`); `tokengrant` is not in
  `dirFileCountExemptions`.

Section 4's placement plan (new helpers + `tokExAuditCrossTenant` move to
`platform/audit/recorder_events.go` 354/500) is the only workable resolution.
**However**, one evidence claim in the design is **Refuted** and changes the
required contract work (Finding 1).

## 1. Assets, trust boundaries, attacker capabilities, entry points

### Assets

| Asset | Where | Trust |
|---|---|---|
| Minted access/refresh/id tokens (RFC 8693) | `tokExState.token`, response | Wire-visible; oracle-collapsed errors |
| Policy rule-set | `domains/tokenexchange/memory.Store` (operator-wired) | Operator-trusted; admin surface |
| Audit trail (hash-chained) | `platform/audit` sinks (SQLite/webhook/syslog) | Operator-side; admin:read + operator webhook |
| Chain store (delegation history) | `domains/tokenexchange/{memory,sqlite}` | Operator-side; admin:read only |
| Chain admin endpoint | `GET /api/v1/admin/tokenexchange/chains/:jti` | admin:read-gated (`accessors_threat.go:197-203`) |

### Trust boundaries

1. **Wire vs audit** — the oracle-safe split is the load-bearing invariant:
   the wire must stay byte-identical `400 invalid_grant`; deny causes belong
   only in audit (`docs/error-codes.md:290` cross-tenant precedent,
   `:278`). The design preserves this (Verified: `tokExEnforcePolicy`
   `token_exchange.go:373-396`, response line untouched by the plan).
2. **Untrusted input boundary** — subject/actor tokens, `resource`/`audience`,
   `scope`, `requested_token_type`, `acr_values` arrive untrusted and are
   validated before the policy gate (`tokExResolveSubject`,
   `tokExResolveTargetsAndScopes`, `tokExValidateRequestTypes`). Everything
   the design records is post-validation.
3. **Operator code boundary** — `Policy` (and the new `DenyReasoner`
   capability) is operator-wired code, type-asserted like `FacetQuerier`
   (`docs/observability.md:76`). In-tree `memory.Store` is the only
   implementation.
4. **Operator-side stores** — audit + chain stores are append-only,
   fail-open observability; never consulted by an authorization decision
   (Verified: `accessors_threat.go:164-188`; `chainstore.go` doc).

### Attacker capabilities

- **A0 unauthenticated network**: reaches only pre-flight gates; the new
  code adds no pre-auth surface.
- **A1 authenticated client + valid subject_token**: can drive policy-gate
  denials and successful exchanges; controls `scope`/`resource`/
  `requested_token_type` only within validated grammars; cannot read audit
  or chain store.
- **A2 admin:read holder**: can read the full chain store and audit stream
  (pre-existing capability; the design widens what it can see — Finding 2).
- **A3 third-party Policy author**: can implement `DenyReasoner`; contract
  consistency is theirs to violate (Finding 4).

### Entry points (affected)

`/token` token-exchange grant (deny + issued audit, chain-hop enrichment);
admin chain endpoint (additive JSON fields); audit sinks (two new event
types).

## 2. Findings

### F1 — Medium — Design refutes itself: the chain endpoint IS documented in `docs/openapi.yaml`; the plan skips a required contract update

**Evidence (Refuted claim):** design §2.4/§4.3 state "the chain endpoint has
no `docs/openapi.yaml` entry today. Do NOT expand scope to add one; report
separately per AGENTS.md §5." Verified: `docs/openapi.yaml:7074` contains a
full `GET /api/v1/admin/tokenexchange/chains/{jti}` operation with a chain
item schema (lines ~7110-7125) listing exactly the current 7 fields
(`jti`, `parent_jti`, `subject_id`, `actor_subject`, `client_id`,
`chain_depth`, `recorded_at`).

**Impact:** AGENTS.md §5 mandates "endpoint → `docs/openapi.yaml`" in the
same change. The four new additive `ChainHop` fields (`scopes`, `resources`,
`requested_token_type`, `session_id`) are serialized by
`HandleTokenExchangeChain` (`interfaces/admin/lifecycle.go:109-140`) and
will ship with a stale documented schema. No automated gate catches it:
`make openapi` / CI `openapi` job (`.github/workflows/ci.yml:357-368`) run
kin-openapi **syntax** validation only, not contract-vs-code drift. The
design's own evidence standard ("all evidence re-verified") failed exactly
here.

**Exploit preconditions/steps:** none (docs-only, no runtime path). A
consumer generated from the stale schema simply won't model the four new
fields; an implementer following the design will skip the update.

**Remediation:** correct the design §2.4/§4.3; add the four `omitempty`
properties to the chain item schema in the same change; keep the "additive,
backwards compatible" framing.

**Regression test:** the design's integration test
(`test/token_exchange_chain_store_test.go`, admin endpoint hop JSON) plus a
manual/CI grep asserting the four property names appear in the
`tokenexchange/chains` operation in `docs/openapi.yaml`.

### F2 — Medium — Chain store gains session-scoped sensitive data with no retention, erasure, or tenant partitioning

**Evidence (Verified):** `ChainHop` gains `SessionID` (the login-session
anchor, propagated unchanged through every hop — locked by
`test/handle_token_exchange_test.go:122-174`), plus `scopes`/`resources`.
The chain store is append-only (no delete in `ChainStore`
`chainstore.go:60-100`; `memory` and `sqlite` backends), non-tenant-
partitioned, and readable through one global admin:read endpoint. The audit
pipeline has a retention story (`audit.retention.*` →
`platform/audit/sqlite.Prune`, `maintenance.go:15`); the chain store has
none. `session_id` is recorded but **unindexed** and not queryable by the
admin surface (session→token indexing explicitly out of scope per design
§2.1) — it is dead weight today and a latent cross-tenant correlation key
tomorrow.

**Impact:** after a user's session/token is erased or its retention window
passes (audit pruned), the chain store still ties `session_id` + scopes +
resources + subject/actor/client across tenants indefinitely. If a future
session→token index is added (direction-1 cascade revocation), the
isolation analysis would need to accompany it; the design should say so
now. Not an authorization bypass — no decision reads the store.

**Remediation (options, pick one and document):** (a) keep `session_id`
out of the SQLite projection until the session→token use case is scoped;
(b) document retention/erasure expectations for the chain store in
`docs/config-reference.md` and the `ChainStore` doc comment; (c) add a
bounded retention sweep like the audit sink. At minimum, add a doc note
that the admin surface is global and the store is append-only.

**Regression test:** a documented decision + test asserting the admin chain
JSON shape is what the OpenAPI schema declares (ties into F1); a retention
test only if (c) is chosen.

### F3 — Low — Rule attribution on the `policy_error` path can mislead SIEM

**Evidence (Proposed design detail):** §1.1 computes `reason` from
`err != nil` but resolves the rule name via the `DenyReasoner` assertion on
**both** terminal outcomes. On the error path the matched rule (if any) did
not cause the failure; reporting its name next to `policy_error` invites a
false attribution. (In-tree `memory.Store` never errors, so this only bites
third-party policies.)

**Remediation:** resolve the rule name only when `err == nil && !allow`;
emit `policy_error` without `rule` metadata (the server log already carries
the error).

**Regression test:** policy returning `(false, err)` yields exactly one
event with `Reason=policy_error` and **no** `rule` metadata.

### F4 — Low — TOCTOU and third-party `DenyReasoner` consistency (acknowledged in design; pin it)

**Evidence (Verified):** `memory.Store.Allow` and the proposed
`DenyReason` take independent `RLock` snapshots (`memory/store.go:43-51`);
copy-on-write `Replace` (`:53-60`) makes the two evaluations see different
rule sets. The design documents this as advisory-only, which is correct —
`DenyReason` is never consulted on the allow path, so the race can only
stale-report a rule name on an already-decided denial, never flip a
decision. The subtle direction: `Allow` under snapshot N (denied), report
under N+1 (rules replaced, no match) → fallback `policy_denied` without
rule — benign and documented.

**Remediation:** add to the capability doc contract: a `DenyReasoner` MUST
be consistent with its own most recent `Allow` evaluation for the same
`Hop` (third-party implementations have no shared `MatchRule`); consider
returning the match result from a single snapshot inside `memory.Store`
(one `RLock` holding both calls) to shrink the in-tree window to zero.

**Regression test:** deterministic test with `Replace` racing between the
two calls asserting the fallback shape (no panic, fixed vocabulary).

### F5 — Low — Audit amplification on the deny path

**Evidence (Verified):** policy denials require a *valid* subject_token +
client credentials (the policy gate is unreachable otherwise —
`token_exchange.go:373` runs after all earlier stages return early). Each
denied request now costs an audit row + optional webhook fan-out where
today it costs one log line. Bounded by `/token` rate limits and token
validity; the audit path is async and fail-open (`docs/observability.md`
Audit pipeline; AGENTS.md §3).

**Remediation:** none required beyond confirming `/token` rate limiting
covers the exchange grant and that the webhook engine's dead-letter/retry
handles sink errors (it does — `platform/lifecycle/webhook` doc). Note in
the design that the denial event volume is attacker-influenceable up to the
rate limit.

**Regression test:** none new; the existing fail-open tests (sink error →
byte-identical wire response) cover it.

### F6 — Info — Deny-event class boundary must be documented to avoid SIEM false negatives

**Evidence (Verified):** `token_exchange_denied` fires **only** at the
policy gate. Actor JTI-replay, step-up failure, chain-lifetime, cycle
detection, cross-tenant-gate denials, and subject validation failures emit
**no** deny event (all return before `tokExEnforcePolicy`). This is the
right asymmetry (no log flooding from garbage; no event-count oracle for
A0/A1), but an operator writing "no deny event = no probing" would be
wrong.

**Remediation:** state the class boundary explicitly in the
`docs/error-codes.md` note the design already plans (§4.3).

**Regression test:** extend the deny harness: assert **zero**
`token_exchange_denied` events for actor-replay, step-up, cycle, and
cross-tenant-gate denials — locks the emission point against accidental
movement.

### F7 — Info — New event types and severity/OCSF mapping

**Evidence (Verified):** `auditsink/severity.go` has an overrides map with a
default; OCSF/CEF sinks fall back to generic mappings; there is **no**
drift gate requiring the new types to be mapped (unlike `auditreport`).
The two new constants will surface as generic-severity OCSF records until
an operator maps them.

**Remediation:** decide severity overrides for `token_exchange_denied`
(failure) and `token_exchange_issued` (success) in the same change if SIEM
severity routing matters; otherwise document as-is.

## 3. Abuse-case table

| # | Scenario | Class | Reachable? | Analysis |
|---|---|---|---|---|
| 1 | Forge `subject_id`/`actor_subject`/`client_id` in chain/audit rows to frame another principal | Identity spoofing | **No** | All recorded identities derive from validated tokens (`tokExResolveSubject`/`tokExResolveActor`) or the authenticated client; `SetMeta` skips empty values (`handler_helpers.go:110`); no raw input reaches event fields. |
| 2 | Replay a stolen actor_token; use deny events as a replay oracle | Replay | **No** | JTI-replay defense unchanged (`tokExActorJTIReplay`); replay fails before the policy gate → no `token_exchange_denied` event → no event-count oracle even for A1; wire stays `invalid_grant`. |
| 3 | Cross-tenant hop abuse; cross-tenant correlation via enriched chain store | Cross-tenant access | **Partial** | Authorization gates unchanged (collaboration store, guest records, roles narrowing — `tokExEnforceTenantCollaboration`). Residual: F2 — session-scoped data of all tenants accumulates in one append-only, globally-admin-readable store with no retention/erasure. No bypass path. |
| 4 | Forge XFF/`X-Real-IP` to poison audit attribution | Proxy/header forgery | **No** | `audit.ClientIP` reads `peertrust.RequestInfoFrom` first (trusted-proxy gated, AGENTS.md §3); design reuses `audit.ClientIP`/`EventFromRequest` — no new header consumption. |
| 5 | Flood audit/chain with deny/issued events | Resource exhaustion | **Bounded** | Deny events need a valid subject token + client creds (F5); issued events cost a full successful exchange; bounded by `/token` rate limits; chain store grows one row per success (pre-existing); audit async fail-open. |
| 6 | Exfiltrate scopes/session ids via new events | Sensitive-data leakage | **No new path** | New data lands only in operator-side stores (audit: admin:read + operator webhooks; chain: admin:read). Wire unchanged. Residual: F2 retention gap; webhook sinks are operator-configured destinations. |
| 7 | Poison audit via `rule`/`reason`/`requested_token_type` | Log/audit injection | **No** | `reason` fixed vocabulary {`policy_denied`,`policy_error`}; `rule` operator-defined; `requested_token_type` validated to 3 values + ""; scopes/resources grammar-bounded before recording (F8). |
| 8 | Race `Replace` between `Allow` and `DenyReason` to flip a decision | TOCTOU | **No** | Advisory-only metadata (F4); `DenyReason` never consulted on allow; worst case is a stale rule name in an already-decided denial. |
| 9 | Space-join collision: scope/resource containing U+0020 splits into extra elements | Data integrity | **Degenerate only** | OAuth scope grammar (`%x21 / %x23-5B / %x5D-7E`) and RFC 8707 URIs exclude U+0020; recorded values are post-validation (`tokExResolveScope`/`AreResourcesAllowed`); worst case is wrong observability, never a decision; round-trip test locks the encoding. |
| 10 | Misattribute `policy_error` to a rule (F3) | Forensics integrity | **Partial** | Only for third-party policies that both error and implement `DenyReasoner`; fix by skipping rule resolution on error. |

## 4. Positive controls verified

| Control | Evidence |
|---|---|
| Oracle-safe collapse preserved; response line untouched | `tokExEnforcePolicy` `token_exchange.go:391-396`; design §1.1 pins `ctx.JSON` unchanged; wire tests extended in `test/token_exchange_chain_policy_test.go` |
| Fail-closed policy; fail-open audit | `tokenexchange.go:16-28` doc; design §1.3 table; nil-`Auditor` short-circuit pattern (`recorder_events.go` all helpers) |
| Bounded `Reason` vocabulary; rule name in Metadata only | Design §1.1; preserves indexed `reason` column cardinality (AGENTS.md §4) |
| `SetMeta`-only metadata, never direct assignment | `handler_helpers.go:110-122`; design §1.1 |
| Trusted-proxy-gated `ClientIP` reused; no new header trust | `handler_helpers.go:123-140` (peertrust first); AGENTS.md §3 |
| Chain store remains append-only, fail-open, never consulted by authorization | `chainstore.go:60-100`; `accessors_threat.go:164-188` |
| JTI join single source: chain row and `token_exchange_issued` derive the same jti from the same minted token at one assembly point (`token_exchange.go:147`); `parent_jti` = inbound subject jti semantics pinned with an acceptance check | Design §3.1/§3.4 |
| Migration discipline: `migrate.validate` enforces monotonic versions; `Run` applies in one transaction; v2 appended after v1; `ALTER ADD COLUMN NOT NULL DEFAULT ''` legal for existing rows | `platform/migrate/migrate.go:100-160`; design §2.2/§2.4 |
| Budget compliance: placement plan keeps `token_exchange.go` under 500 with ≥3-line margin; `recorder_events.go` 354 → ~414-460 | Verified line counts (§0); design §4 |
| Event-type drift gate: both new constants claimed exactly once in CC6.1 same-change | `auditreport/drift_test.go:95`; `control_areas.go:42-59` |
| Architecture: `agentidentity → domains/tokenexchange` import is acyclic; no new package; `Policy` SPI byte-identical | Design §3.1/§4; parent never imports `agentidentity` |
| SID propagation locked by existing test | `test/handle_token_exchange_test.go:122-174` |

## 5. Residual risks and prioritized validation plan

**Residual risks**

1. F1: the openapi claim error means a stale public contract ships silently
   (no automated drift gate exists).
2. F2: chain-store data accumulates without retention/erasure; `session_id`
   is unindexed dead weight with latent cross-tenant correlation value.
3. F3: `policy_error` rule misattribution for third-party policies.
4. F4: two-snapshot TOCTOU (advisory only) and third-party
   `DenyReasoner` consistency is contract, not code.
5. Space-join degenerate case (documented, test-locked, observability-only).
6. Line-count estimates carry ±3-line error bars; the design's step 3
   (SPIFFE/cycle moves) is the agreed margin mechanism — execute before
   feature work, not after a gate failure.
7. No Go gates were run for this review (docs-only change); the design's
   §4.3 sequence is the implementation gate.

**Prioritized validation plan**

1. **Fix the design** (§2.4/§4.3): the chain endpoint is documented; the
   same change MUST update the chain item schema in `docs/openapi.yaml`
   with the four new `omitempty` properties (F1).
2. Per-edit gates: `go build ./... && go vet ./...` and
   `go test -run 'TestMaintainability_|TestArchitecture_' .`
   (design §4.3, reaffirmed).
3. `go test ./platform/audit/auditreport/` — both new constants claimed
   exactly once in CC6.1.
4. Round-trip + migration tests: `domains/tokenexchange/{sqlite,memory}`
   hop correlation fields; v1→v2 with pre-existing rows.
5. Integration: extended `test/token_exchange_chain_policy_test.go` —
   deny-event shape, wire byte-identity, **and the F6 class-boundary
   assertions** (no deny event on replay/step-up/cycle/cross-tenant
   classes); `test/handle_token_exchange_test.go` — exactly one
   `token_exchange_issued` per exchange, none for other grants;
   `test/token_exchange_chain_store_test.go` — admin hop JSON matches the
   updated OpenAPI schema.
6. F3 fix (skip rule resolution on error) with its regression test.
7. Contract updates: `docs/error-codes.md` audit-event notes (incl. the F6
   class-boundary statement) and the corrected `docs/openapi.yaml`.
8. Handoff: `go test ./... -race`, `go test ./test/ -run TestE2E -v`,
   `make ci` (incl. kin-openapi validate on the updated schema).

## 6. Verdict

The design is sound on the load-bearing invariants — oracle-safe wire
behavior, fail-closed policy / fail-open audit, bounded audit dimensions,
single-source jti join, migration and budget discipline. No authorization
bypass, replay, spoofing, or header-forgery path is introduced. Two items
must be fixed before implementation: the **refuted openapi claim** (F1,
required contract work is being skipped on false evidence) and the
**chain-store retention/erasure gap** for the newly added session-scoped
data (F2). F3-F7 are small, cheap hardening items that fit the planned
change surface.
