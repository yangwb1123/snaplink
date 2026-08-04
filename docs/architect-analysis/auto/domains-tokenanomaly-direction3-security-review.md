# Security Review: `domains/tokenanomaly` direction-3 design (FamilyID through detection→response; windowed + subject-dimensioned rate_spike)

Reviewer role: principal security engineer (adversarial production behavior).
Input: `docs/auto/domains-tokenanomaly-direction3-design.md` + the underlying
`domains-tokenanomaly-direction3-spec.md`. Scope: the six decisions — the
`RecordRefreshTokenIssued` seam change, the telemetry-only `handle_introspect.go`
edit (Decision 2), `Finding.FamilyID` → `Threat.FamilyID` → reachable
`revoke_family`, the detector-local capped subject table, the windowed
one-finding-per-client spike, and the byte-identity/fail-open/import invariants.

This is an advisory review of a **proposal**. No `.go` file was changed, so no
Go gate ran; every claim below was re-verified against the current tree at
`HEAD` (`35dee544`) by source inspection. Unrelated worktree modifications
(`cmd/sso-server/*`, `.pi/*`, `ai-dev/*`) were not touched.

## Verification run for this review (all source-level, no gates executed)

- Seam surface: `RecordRefreshTokenIssued` is declared in **six** interfaces
  (`internal/handler/serverdeps.go:157`, `tokengrant/token_refresh.go:30`,
  `token_authcode.go:38`, `token_ciba.go:29`, `token_device.go:29`,
  `token_exchange.go:67`) and called at **five** grant sites
  (`token_refresh.go:206`, `token_authcode.go:232`, `token_ciba.go:252`,
  `token_device.go:169`, `token_exchange_stages.go:491`) plus one test fake
  (`token_ciba_test.go:70`); the Server adapter (`accessors_handlers.go:336,457`)
  and impl (`server_helpers.go:439`) complete the set. The design's "spec file
  list incomplete" claim is **Verified** — omitting `token_device.go`,
  `token_exchange.go`, and `token_ciba_test.go` breaks `go build ./...`.
- Decision 2 reachability: `protocols/oauth/handle_introspect.go` `introspectRefresh`
  offers the event at :358 with `info` = full `*oauthspi.RefreshToken` from
  `RefreshTokenInspector.Inspect` (`oauthspi/refresh_token.go`); `FamilyID` and
  `JTI` are fields of that record and both propagate unchanged through rotation
  (`RefreshAuthContext`, `oauthwire/auth_code_handler.go:238-267`; rotation
  passes both at `token_refresh.go:233`). **Verified**. The second Offer site
  (`protocols/oauth/introspect_body.go:23`, access-token introspection) has no
  family concept and needs no edit. **Verified**
- Family minting: `GenerateAuthCodeBytes` = 32 bytes from `crypto/rand`,
  base64url (`oauthwire/auth_code_handler.go:93-98`). FamilyID is unguessable,
  opaque, non-PII. **Verified**
- Detector: `Record` captures observations only when `ev.Thumbprint != ""`
  (`detector.go:254-260`); `observation` has no `familyID`; `dispatchThreat`
  (`:138-155`) builds `Threat` with zero `FamilyID`; `evidenceFor` (`:157-175`)
  has no family key; `detectRateSpike` returns nil on store error (`detect.go:73-86`);
  `spikeForClient` (`:100-136`) tests only the newest minute; `foldClientMinuteRates`
  keys only on ClientID. **Verified**. Budgets: `detector.go` 442, `detect.go` 155,
  `server_helpers.go` 493 lines. **Verified**
- Executor: `RevokeFamilyExecutor.Execute` (`domains/threataction/actions.go:148`)
  family path iff `families != nil && threat.FamilyID != ""`, else subject
  fallback iff `threat.SubjectID != ""`; both idempotent; `KindTokenRevoked` bus
  event keyed by FamilyID on the family path. **Verified**. Policy `conditions`
  support `eq`/`exists` on evidence keys; a missing key fails closed
  (`domains/threataction/policy.go:116-139`). **Verified**
- Fail-open plumbing: `Recorder.Offer` non-blocking drop-on-full
  (`domains/metering/token_recorder.go:152`); audit evidence bounds
  (`registry.go`: 32 keys / 128 / 1024); threat actions rate-limited per
  (subject, type, action) when a policy sets `rate_limit`. **Verified**
- DedupKey collision claim: `Finding.DedupKey()` = `type\x00thumbprint` or
  `type\x00client` when thumbprint empty (`tokenanomaly.go:74-82`); a
  subject-scoped spike (Thumbprint `""`, ClientID set) keys identically to the
  client-scoped row. **Verified** — the one-per-client rule is load-bearing.
- Introspection auth: any registered **active** client may introspect any token
  it possesses (RFC 7662 semantics, `handle_introspect.go` client gate);
  the Offer records the **token's** client/subject/geo, not the introspector's.
  `Inspect` (`infrastructure/defaultimpl/sqlite/refresh_tokens.go:187`) has no
  tenant predicate — only the introspecting client is tenant-gated
  (`tenant.ClientOK`). **Verified**
- OpenAPI: `/api/v1/admin/tokens/suspicious` exists with `token_thumbprint` /
  `subject_id` schema fields (`docs/openapi.yaml:7346,7393-7395`); the
  `family_id` addition is a doc-only change. **Verified**

## 1. Assets, trust boundaries, attacker capabilities, entry points

### Assets touched by the design

| Asset | Trust level | Notes |
|---|---|---|
| `RefreshToken.FamilyID` / `JTI` (store records) | server-internal, crypto-random | 1:1 per lineage; propagate unchanged through rotation |
| `metering.Event.FamilyID` (new) | recorder drain goroutine | Never marshaled to wire; `Event` has no JSON tags (`token_usage.go:54-72`) |
| Detector observation table (thumbprint → family/subject/geos) | process-local, cap 4096 | Gains a family field with non-empty overwrite (mirrors SubjectID guard) |
| New detector-local `subjectMinuteRates` table | process-local, cap × window | New bounded memory; attacker-growable row space (F3) |
| `Finding.FamilyID` (`family_id,omitempty`) | admin:read API | Opaque non-PII; rides the fresher merge |
| `Threat.FamilyID` + `evidence["family_id"]` | policy engine + audit | New policy condition key; fails closed when absent |
| `RevokeFamilyExecutor` family path | operator-wired, `default_action: revoke` | Blast radius: one lineage vs. every token of (subject, client) |
| `KindTokenRevoked` bus event keyed by FamilyID | cluster bus | Idempotent receiver-side dedup by key |

### Trust boundaries

1. **Client ↔ token store.** Any authenticated active client can introspect any
   token it possesses; the usage event is attributed to the **token's** owner.
   This is RFC 7662 semantics and is the intended detection signal (a stolen
   token being probed), but it makes introspection the only thumbprint-bearing
   event source in the system.
2. **Recorder queue.** Offer is drop-on-full, drain is off-path; the Detector
   decorates the store. No request path reads detection state.
3. **Policy/executor boundary.** `default_action: revoke` turns findings into
   destructive store operations. Blast radius is chosen by finding shape
   (family vs. subject) — the design changes which findings can carry a family.
4. **Admin API.** Findings (incl. `family_id`) are admin:read-gated
   (`interfaces/sso/sso.go:385-390`).
5. **Multi-tenant.** One Detector/finding store per server process; no tenant
   dimension in observations. Pre-existing for SubjectID; FamilyID joins the
   same global channel (F6).

### Attacker capabilities (relevant to this change)

- **C1 — attacker with their own account + a token of any client** (public
  client / device flow / their own registered client): can generate unlimited
  introspection events for their own subject/client at near-zero cost
  (client auth only), and issue tokens for their own subject.
- **C2 — attacker holding a stolen refresh token of a victim**: can introspect
  it (feeds the family-bearing observation — the intended tripwire), rotate it
  at `/token` (issuance events, no thumbprint), or replay it (family-reuse kill,
  unchanged grant path).
- **C3 — attacker with many client registrations** (dynamic registration
  enabled): can grow the (subject, client) row space of the new subject table.
- **C4 — attacker cannot**: set `Event.FamilyID`, `Event.Thumbprint`,
  `Event.SubjectID`, or `Event.ClientID` directly — every field is derived
  server-side from store records or authenticated context. Verified: the only
  two Offer sites in `protocols/` populate from `info`/`claims`; the only new
  FamilyID writers (rotation seam, introspect seam) read the store record.

### Entry points exercised by the change

`/token` (refresh rotation — family into telemetry), `/token/introspect`
(refresh branch — family into observation; access branch unchanged), the
detector sweep (off-path), the admin suspicious-tokens API (read), the threat
executor (off-path), audit (family via `threat.evidence.family_id` and existing
reuse/velocity events). No grant decision or wire byte changes.

## 2. Findings

### F1 — Medium — Family-scoped precision is gated on lineage introspection; the rotation-first attack and every access-token-derived finding stay subject-wide

**Evidence (Verified).** Issuance events carry no thumbprint (jti is minted
inside the issuer), so `recordObservation` (`detector.go:254-260`) can never
see them; the **only** thumbprint-bearing events are introspection Offers
(`handle_introspect.go:358`, `introspect_body.go:23`). Consequently: (a) the
family reaches the observation table only when a refresh token of the lineage
was introspected (Decision 2 — the design's own admission, its central gap
claim); (b) access-token introspection observations (the majority of
introspection traffic in a mesh) can **never** carry a family — access tokens
have no lineage — so velocity/multi_geo findings derived from them still hit
`DeleteAllForSubject`; (c) a stolen refresh token that is rotated but never
introspected produces a subject-dimension finding with empty family → subject
fallback.

**Exploit preconditions/steps.** None needed — this is the *absence* of the
promised narrowing, not an active bypass. The most common stolen-token abuse
(use the stolen **access** token from another geo) produces a finding whose
family is `""` by construction; with `default_action: revoke`, the victim's
every refresh token for the client is still revoked (the exact self-inflicted
DoS the direction claims to fix), while a stolen refresh token that is probed
via introspection first gets the narrow family revoke.

**Impact.** The improvement's headline benefit (kill one lineage, spare the
user) is delivered only for refresh-introspection-derived findings. For the
rotation-first and access-token paths, behavior is byte-identical to today
(which the design documents as "correct scope" for rotation bursts — the
subject *is* the signal there — but for access-token velocity the subject is
**not** the signal; the token is). Blast-radius asymmetry: the same user's
tokens get family-scoped or subject-scoped revoke depending on which endpoint
produced the sighting.

**Remediation.** Required: none for this change (the design's decision to not
reshape the issuer/store contract is proportionate — stamping issuance
thumbprints is a genuinely bigger surface). Recommended: (1) state the
introspection-coverage dependency in `docs/config-reference.md` threat_action
guidance so operators understand when the fallback still fires; (2) track the
asymmetry as a follow-up (e.g., subject table keyed by family where known is
the natural extension — the design's own descope option, which it rejected for
Finding/DedupKey surface; keep it rejected for now).

**Regression test.** Integration (`test/`, package `ssotest`): a velocity
finding fed by an **access-token** introspection (no family) with
`default_action: revoke` still exercises `DeleteAllForSubject` (pins the
fallback as load-bearing), while a refresh-introspection-fed finding with a
family exercises `DeleteFamily` only — the design's own success criteria.

### F2 — Medium — Self-introspection bursts plant attacker-attributed findings under a victim client's DedupKey and pollute the new subject dimension's baseline

**Evidence (Verified).** (a) Any active client can introspect any token it
possesses (`handle_introspect.go` client gate; RFC 7662 §2.1); each successful
refresh introspection Offers one event attributed to the **token's**
client/subject (`handle_introspect.go:358-366`). (b) The new subject table
folds **all** subject-bearing events per (subject, client) minute — the design
explicitly keeps the "all kinds/endpoints summed" uniform definition — so an
attacker's own introspection volume (free, self-authenticated) counts toward
their (subject, client) row. (c) A subject-scoped winner has `Thumbprint == ""`
and `ClientID` set, so it upserts the **same** DedupKey as the client-scoped
winner (`tokenanomaly.go:74-82`), and `mergeFinding` keeps the earliest
`FirstSeen` (`memory/store.go:75-90`) — a planted row is sticky until eviction.

**Exploit preconditions/steps.** Detection + threat_action enabled;
`spikeMinCount` ≤ 20 introspects of the attacker's own token for the victim
client (public client, attacker's own account) within one minute, with a flat
prior baseline. Steps: (1) obtain a token for the victim client via the
attacker's own account; (2) introspect it ~20× in one minute (optionally from
varied egress geos); (3) the next sweep emits a subject-scoped rate_spike
candidate for (attacker, victim-client) that outranks the client winner in a
low-volume client; (4) the row persists under `rate_spike\x00<victim-client>`
with the attacker's SubjectID, and the victim client's minute baseline for the
window is inflated.

**Impact.** Bounded, governance-plane: permanent suspicious-token row for the
victim client attributed to the attacker's subject (alert fatigue, operator
confusion); baseline inflation dampens real spike detection for that client
(the design's own "consecutive bursts dampen" failure mode, now attacker-
amplifiable); a `default_action: revoke` policy with a subject winner revokes
only the **attacker's** own tokens (no cross-user revocation — the executor's
empty-family/subject guards hold). No credential or auth-boundary impact.

**Remediation.** Preferable: fold only issuance events (`EndpointToken`) into
the spike dimensions — rate_spike is an *issuance* signal; introspection
volume is not issuance and should not move spike baselines (client-wide fold
today already mixes introspects in — pre-existing, but the new subject table
should not copy the flaw). Fallback: require the subject-scoped candidate to
exceed a minimum *share* of the client minute, or count distinct thumbprints
per (subject, client, minute) where thumbprints exist.

**Regression test.** Unit: N introspects of one token in a minute (flat
baseline) must NOT produce a subject-scoped finding at the default
`spikeMinCount`/`spikeFactor` — or, if the fold choice is kept, a test that
pins the planted-row DedupKey behavior as accepted-with-documentation.

### F3 — Low — Subject-table row-space churn: detection-quality DoS via (subject, client) eviction pressure

**Evidence (Verified).** The cap (`WithMaxTrackedSubjects`, default 4096)
evicts the row with the oldest most-recent minute (`detect.go` subject table,
per Decision 4). Row keys are (subject, client); a single attacker subject × N
registered clients (dynamic registration, C3) creates N rows, and each new row
can evict a victim's row at cap. The thumbprint table already had this class of
churn (attacker can mint many tokens → evict victims' observations); the
subject table doubles the eviction surface and its eviction is by *recency*,
so a victim's quiet-but-relevant row is the preferred victim.

**Impact.** Bounded memory (cap enforced); degradation of detection coverage
only. No auth decision reads this state. Pre-existing class; the design's cap
is sound.

**Remediation.** Optional: per-subject row budget (a single subject should not
own more than k rows), or weight eviction by activity rather than pure recency.
At minimum, keep the feed guard (empty `SubjectID` excluded) pinned by a test —
the design's own failure-mode 6.

**Regression test.** Unit: fill the table to cap with attacker rows
(deterministic order), assert victims evicted last and sweep output stays
deterministic; assert empty-`SubjectID` events never create rows.

### F4 — Low — Legitimate-burst false positive: one user's multi-device login wave can trip the subject spike and trigger a subject-wide revoke

**Evidence (Verified).** The subject fold includes first-issue events
(Decision 1 first-issue paths pass `""` family but carry SubjectID), and the
windowed test applies the same thresholds (`spikeMinCount` 20, `spikeFactor`
3.0, `detect.go` consts). A user re-authenticating across ~20 devices/clients
in one minute — a legitimate wave (password reset, fleet rollout) — clears the
floor and, against a near-zero prior baseline, clears the factor. The resulting
finding is subject-scoped, family-less by construction → with
`default_action: revoke`, `DeleteAllForSubject` kills every refresh token the
user holds for that client (self-inflicted DoS on a real user). The design's
"subject-spike revoke scope is subject-wide" failure mode documents the blast
radius but not the *false-positive reachability from legitimate bursts*.

**Impact.** Bounded (one client per finding; policies/rate limits mitigate;
severity warn). New surface: the subject dimension makes a **single user's**
burst sufficient — today's client dimension required a whole-client burst.

**Remediation.** Recommend the F2 fold fix (issuance-only and/or distinct-
thumbprint counting) which also narrows this; document the tradeoff in
config-reference; recommend operators pair `revoke` with `rate_limit` and
severity conditions.

**Regression test.** Unit: a 25-event/minute subject series against a flat
baseline yields the finding; assert the emitted finding's shape and that with
a policy `rate_limit` the second sweep's dispatch is suppressed.

### F5 — Low — `detect.go` budget drift risk unlisted in the design's breakage list

**Evidence (Verified).** `detect.go` is 155 lines today; the design adds a
second map type, feed fold, cap eviction, window pruning, a rewritten
windowed candidate scan, and the one-per-client selection — plausibly
150–250 lines against 345 of headroom. The design's "what could break" list
flags `server_helpers.go` but not `detect.go`. `detector.go` also grows ~20–30
lines (442 → ~470) — under 500, fine.

**Impact.** Gate failure at handoff if the estimate is short; process risk,
not security.

**Remediation.** Pre-plan the split (subject table + fold in a new
`domains/tokenanomaly/subject_rates.go` file — the package is at 5 non-test
files, and the budget counts per-file; the spec's placement rule is about
*which* file owns spike analysis, a sibling file for the table is consistent).
Run `go test -run 'TestMaintainability_' .` before handoff.

**Regression test.** The committed maintainability gate itself.

### F6 — Info — Cross-tenant mixing in the global detector: introspection events are not token-tenant-gated

**Evidence (Verified).** `Inspect` has no tenant predicate
(`infrastructure/defaultimpl/sqlite/refresh_tokens.go:187-205`); only the
introspecting client is tenant-checked. One Detector/finding store per server;
no tenant dimension. A tenant-B client possessing a tenant-A refresh token
introspects it → tenant-A subject/family enter the global observation table,
and a finding could revoke tenant-A's family (correct owner — the token's own
lineage — but the governance view mixes tenants). Pre-existing for SubjectID;
FamilyID adds only an opaque non-PII id to the same channel; families are
256-bit random, so no cross-tenant collision/guessing risk.

**Recommendation.** Document for multi-tenant deployments; out of scope for
this change.

### F7 — Info — Exported `Server.RecordRefreshTokenIssued` signature change is an SDK break for direct callers

**Evidence (Verified).** `interfaces/sso` `Server.RecordRefreshTokenIssued`
(`accessors_handlers.go:457`) is exported and gains a parameter. SDK
consumers calling it directly (rare; it is a telemetry helper) break at
compile time. The design's table is complete and honest about the six
internal interfaces; the exported-method aspect is worth a changelog note.

## 3. Abuse-case table

| # | Abuse case | Reachable? | Path | Outcome / control |
|---|---|---|---|---|
| A1 | **Identity spoofing** — forge `family_id`/`subject_id`/`thumbprint` in an Event to poison a victim's observation | **No** | C4: every field is server-derived (store records / authenticated context); the only new FamilyID writers read `info.FamilyID` | Not injectable; no request field maps into Event |
| A2 | **Replay** — replay a stolen refresh token to trigger family-scoped revoke of the victim's whole lineage | Yes (intended) | `/token` reuse → `ErrRefreshTokenReused` → `DeleteFamily` in the grant path (unchanged); introspection of the stolen token → family-bearing finding → `DeleteFamily` | Designed tripwire; narrow blast radius (one lineage) |
| A3 | **Replay** — rotate a stolen token without introspecting it to stay under family-scoped detection | Yes (residual) | Rotation → issuance events (no thumbprint) → subject dimension → subject-wide fallback revoke | F1: the promised narrowing does not cover this path; subject-wide revoke still fires (correct per design, but the user-wide hammer persists for this attack) |
| A4 | **Cross-tenant access** — tenant-B client introspects a tenant-A token | Yes (pre-existing, RFC 7662) | `Inspect` not tenant-gated; event attributed to tenant-A's token owner | F6: governance-view mixing; revoke (if any) hits the token's own family; no credential boundary crossed |
| A5 | **Proxy/header forgery** — spoof geo of an introspection to poison a victim's observation | **No** (for victims) | Geo comes from the introspecting peer/XFF; events are keyed to the **token's** thumbprint, which the attacker cannot choose | Attacker can only move their own observations; pre-existing |
| A6 | **Resource exhaustion** — introspect bursts to inflate the subject table / plant findings | Yes (bounded) | F2/F3: self-attributed rows, cap 4096, eviction, drop-on-full recorder | Bounded memory; detection-quality and admin-list pollution only; no auth impact |
| A7 | **Resource exhaustion** — many-client churn to evict victims' rows | Yes (bounded, C3) | F3 | Detection degradation only; cap enforced |
| A8 | **Sensitive-data leakage** — family_id exfiltration | No (by design) | FamilyID is 256-bit random, opaque, non-PII; `family_id,omitempty`; admin:read-gated; `Event` never marshaled | `FamilyID` already flows in audit reuse/velocity events today (unchanged) |
| A9 | **Sensitive-data leakage** — finding `Detail` drift | No | Nothing matches on `Detail` (design checked); wording change is documented | Low risk; update exact-string tests |
| A10 | **False-positive revoke** — legitimate burst trips subject-wide revoke | Yes (bounded) | F4: subject spike at default thresholds | Self-inflicted DoS on a real user; mitigate via issuance-only fold, rate limits, policy conditions |

## 4. Positive controls verified

- **Unguessable family ids**: `GenerateAuthCodeBytes` (32 bytes `crypto/rand`)
  — no enumeration, no cross-tenant collision, no oracle.
- **Lineage discipline**: JTI and FamilyID propagate unchanged through rotation
  (`RefreshAuthContext`, `token_refresh.go:233`, oauthwire tests) — thumbprint↔
  family is 1:1 per lineage; `recordObservation`'s non-empty family overwrite
  mirrors the SubjectID guard (never cleared by `""`).
- **Oracle safety untouched**: no grant/introspect decision or wire byte
  changes; the `handle_introspect.go` edit is telemetry-only and adds no
  imports; no-store/bearer-challenge surfaces untouched.
- **Fail-open preserved everywhere**: `Offer` drop-on-full; `Record` capture
  cannot fail; `detectRateSpike` nil-on-store-error; `dispatchThreat` logs
  executor errors without blocking the sweep; threat actions rate-limited and
  audit-bounded (32 keys/128/1024); evidence condition failure closes the
  policy match.
- **Zero-value byte-identity**: all family-less paths (`""` family, `""`
  subject) reproduce today's exact behavior; first-issue seams pass `""`.
- **DedupKey integrity**: the one-per-client rule resolves the
  `rate_spike\x00<client>` collision by construction (Verified).
- **Revoke blast radius**: family path → `DeleteFamily` (idempotent) keyed by
  opaque id; subject fallback unchanged; `KindTokenRevoked` keyed by FamilyID
  on the family path.
- **Import direction**: no upward imports; the single `protocols/oauth` edit
  stays within the package (Verified: it already imports `metering`/`geo`).
- **Admin gate**: findings API stays `admin:read`; `family_id,omitempty`
  keeps the wire shape unchanged for family-less rows.

## 5. Residual risks and prioritized validation plan

**Residual risks.** (1) F1 — family precision only for introspected lineages;
access-token-derived and rotation-first findings remain subject-wide (design-
documented, recommend operator-facing docs). (2) F2/F4 — the subject table
folds all event kinds, so introspection volume (attacker-amplifiable) and
legitimate bursts move spike signals; recommend issuance-only fold or
distinct-thumbprint counting. (3) F6 — cross-tenant governance-view mixing,
pre-existing. (4) F5 — `detect.go` budget drift. (5) Repeated dispatch while a
burst is in-window (≤ ~15 sweeps): accepted, idempotent, rate-limitable.

**Prioritized validation plan** (after implementation; gates per AGENTS.md):

1. Unit (`domains/tokenanomaly`): family-bearing observation → finding →
   `Threat.FamilyID` via spy executor; empty-family finding byte-identical.
2. Unit: one-finding-per-client-per-sweep and DedupKey non-collision (pins the
   load-bearing rule); windowed series: burst-at-T−2, flat-spike-flat, brand-
   new client (≥2 prior minutes) — the design's failure-mode 5 pin.
3. Unit: subject-table feed guard (empty `SubjectID` excluded), cap eviction
   determinism, sweep-time pruning.
4. Unit: F2 regression — introspection bursts do not move spike signals at
   default thresholds (or the planted-row behavior is pinned as accepted).
5. Unit (`internal/handler/tokengrant`): rotation Event family == consumed
   `info.FamilyID`; first-issue `""` (zero-value byte-identity).
6. Unit (`domains/threataction`): family path invokes `DeleteFamily` and never
   `DeleteAllForSubject`; empty-family fallback byte-identical to today's tests.
7. Integration (`test/`, `ssotest`): with `default_action: revoke`, one
   family's velocity finding revokes that family while a second token of the
   same subject+client survives; `KindTokenRevoked` keyed by FamilyID; F1's
   access-token-derived fallback pinned.
8. Race: `go test ./domains/tokenanomaly/... ./domains/threataction/... -race -count=10`.
9. Gates: `go build ./... && go vet ./...`; `TestMaintainability_|TestArchitecture_`;
   `make ci` (incl. openapi/config doc checks).
