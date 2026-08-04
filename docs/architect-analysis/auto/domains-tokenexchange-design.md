# Design — Token-Exchange Hop-Policy Operational Loop (Management API + Durable Store + Matching Dimensions)

Source: `docs/auto/domains-tokenexchange-analysis.md` item 2. Three improvements,
one closed loop: the operations face (admin API), the state face (durable
store), and the expression face (matching dimensions). All evidence below was
re-verified against the code; the analysis doc's claim that
`domains/tokenpolicy` has a "sqlite backend" is wrong (that package is
memory-only), so the persistence precedent is the module's own
`domains/tokenexchange/sqlite` chain store.

Scope guardrails honored: changes confined to `domains/tokenexchange`,
`config` (existing file), `interfaces/admin` (new file allowed — no ceiling),
`interfaces/sso` (existing files only, 60-file ceiling), `cmd/sso-server`
(existing files), `shared/core` (consts), `platform/audit` (event
registration), `docs/`. Wire oracle safety unchanged: `/token` failures keep
collapsing to the same `invalid_grant`; rule details reach only audit + admin.

---

## Decision 1: A minimal mutable-policy seam (`MutablePolicy`)

**Interface.** Define in `domains/tokenexchange/tokenexchange.go`, next to
`Policy`:

```go
// MutablePolicy is the admin-manageable superset of Policy: the active rule
// set can be read (governance view) and atomically replaced (admin API).
// Implementations MUST be safe for concurrent use: Allow runs on the token-
// exchange hot path (opt-in) while Replace swaps the set.
type MutablePolicy interface {
	Policy
	Replace(rules []Rule) error // atomic, all-or-nothing; error = no change
	Rules() []Rule              // snapshot, read-only for the caller
	DefaultAllow() bool         // no-match fallback; immutable after construction
}
```

**Why `Replace` returns `error`.** The sqlite backend must surface a
persistence failure as "no change" (fail-closed, AGENTS.md §3). `memory.Store`
can never fail but must satisfy the same interface. This is a **free
signature change**: `Replace`/`Rules` have zero production callers (verified
by grep — the "dynamic-update path" is dead code today); only
`memory/store_test.go` needs `if err := ...` in the same change.

**Why `DefaultAllow()` is in the interface.** The GET response contract is
`{default_allow, rules[], total}`, but `default_allow` is a constructor
argument with no accessor today. It stays **config-only** (immutable after
construction) — an incident response needs deny rules, not a global fallback
flip; keeping it out of PUT avoids a second mutation path and keeps
`Replace([]Rule)` single-argument per the requirement. `memory.Store` gains a
trivial accessor; the sqlite store's constructor takes `defaultAllow` and does
not persist it (see Decision 4).

**Byte-identity.** `WithTokenExchangePolicy` still accepts any
`tokenexchange.Policy`. Only when the wired value additionally satisfies
`MutablePolicy` are the admin endpoints mounted. A custom immutable Policy,
or nil (unwired), mounts nothing — byte-identical to today.

---

## Decision 2: Admin API surface — `GET/PUT /api/v1/admin/tokenexchange/policies`

**Path constant.** `PathAdminTokenExchangePolicies = "/admin/tokenexchange/policies"`
added to `shared/core/consts_wire.go` beside `PathAdminTokenExchangeChain`
(same const pattern; `interfaces/sso/aliases.go`-style re-export not needed
because the mount lives in `accessors_threat.go`, which uses `core.` consts
directly).

**`GET` — `admin:read`.** Response `200`:

```json
{ "status": "ok", "default_allow": true, "rules": [ ... ], "total": 2 }
```

- `rules` in **evaluation order** (the order `Evaluate` walks).
- Governance metadata only — no secret material (same argument as
  `tokenpolicy.HandleAdminPolicies`), serialize `Rule` verbatim via the new
  tags.
- Envelope keys as literals, matching `HandleAdminPolicies`'s `"total"`
  precedent (`core.KeyStatus` for `status`).

**`PUT` — `admin:write`.** Body: `{ "rules": [ ... ] }` — the complete rule
set, full-replace semantics (idempotent; ordering preserved). `default_allow`
is not accepted (config-owned).

Validation, all before any store call — **failure = `400 invalid_request`,
zero store mutation**:
1. body decodes (else `400`);
2. `len(rules) <= MaxTokenExchangePolicyRules` (new const, 1000 — bounded
   audit cardinality, bounded table size; matches "admin-sized rule sets" in
   the memory store doc);
3. every rule has non-empty `Name` (audit/display key);
4. structural sanity of `scopes`/`resources` (JSON arrays, per-entry
   wildcard shape `*` only as trailing suffix — reject `"*x"`, reject `""`
   entries).

On success: `Replace` atomically swaps the set, then an audit event is
recorded (below), response `200` echoes the new `{status, default_allow,
rules, total}` so a management tool can confirm without a second GET.

**Errors.** `400 invalid_request` (validation), `500 internal_error`
(store failure — Replace error, logged with detail), `401`/`403` via the
existing `/api/v1/admin/` middleware. No new error code needed in
`docs/error-codes.md` (reuses `invalid_request`/`internal_error`).

**Audit.** New event type `token_exchange_policy_updated`
(`auditspi.EventTokenExchangePolicyUpdated`), following
`recordAdminConnectionAction` (`interfaces/admin/connections.go`) exactly:
`ActorID` from `ActorFromContext(ctx.Request().Context())`, `ActorIP` from
`audit.ClientIP`, plus `audit.SetMeta` with `rules_before`, `rules_after`
(counts) and `rule_names` (comma-joined, truncated to a bounded prefix — the
rule-count cap bounds cardinality). Registration (all required, else `make
ci` fails): `auditspi` `KnownEventTypes` map, `auditreport/drift_test.go`
`wantUncategorizedEventTypes`, `auditsink/cef.go`, `auditsink/ocsf.go`. Audit
recording is fail-open (recorder already swallows sink errors; a failed
audit must never roll back an applied PUT — the mutation already happened).

**Handler placement.**
- `interfaces/admin/tokenexchange_policies.go` (new file — `interfaces/admin`
  has no file ceiling and owns `ActorFromContext`): `HandleTokenExchangePolicies(store,
  log, ctx)` for GET and `HandlePutTokenExchangePolicies(store, log, auditor,
  ctx)` for PUT, mirroring `HandleTokenExchangeChain(store, log, ctx)`'s
  explicit-deps style. Validation helpers (`ValidateRules`) live here or in
  the domain package — domain placement is preferred so the sqlite store's
  boot load and the YAML parser share them.
- `interfaces/sso/accessors_threat.go`: two ~4-line wrappers
  (`handleAdminTokenExchangePolicies`, `handlePutTokenExchangePolicies`) plus
  `mountAdminTokenExchangePolicies()` gated on
  `s.tokenExchangePolicy != nil` AND a `MutablePolicy` type assertion — the
  same `core.NewGatedRouter(..., s.adminAPIGateOn)` pattern as the chain
  mount. Called from `Mount()` (`server_routes.go:101`, +1 line; file is 488
  → 489 ≤ 500). Budget math: 427 + ~38 = ~465 ≤ 500. **No new `interfaces/sso`
  file** (60-file ceiling honored).

---

## Decision 3: Matching-dimension extension — Scopes / Resources / RequestedTokenType

`Rule` gains three fields with `json`/`yaml` tags (tags are additive and
wire-neutral: nothing serializes `Rule` today — verified):

```go
Scopes             []string `json:"scopes,omitempty" yaml:"scopes,omitempty"`
Resources          []string `json:"resources,omitempty" yaml:"resources,omitempty"`
RequestedTokenType string   `json:"requested_token_type,omitempty" yaml:"requested_token_type,omitempty"`
```

All existing fields get tags too (they have none today).

**Matching semantics — written into `ruleMatches`' doc comment as the
constraint anchor:**

| Dimension | Semantics | Empty |
|---|---|---|
| `SubjectID` / `ActorSubject` / `ClientID` | exact (unchanged) | wildcard |
| `RequestedTokenType` | exact (unchanged pattern) | wildcard |
| `Scopes` | **ALL-of**: every entry must be present in `hop.Scopes` (hop set is a superset); each entry supports a trailing `"*"` prefix wildcard — identical to `tokenpolicy` selector semantics | wildcard |
| `Resources` | **ANY-of**: hop touches any listed resource/audience → match; each entry supports the same trailing-`"*"` wildcard | wildcard |

The Resources ANY-of divergence from Scopes ALL-of is deliberate and must be
documented: a deny rule naming a resource is a defensive default ("this
audience is off-limits, period") — requiring exact-set equality would let a
hop evade the deny by adding an unrelated resource. `Evaluate`'s
first-match-wins and `defaultAllow` fallback are untouched.

**Implementation.** Extract two small helpers so `ruleMatches` stays well
under budget (currently 12 lines; target ~25):

```go
func scopeMatches(want, have []string) bool    // ALL-of + trailing-"*" prefix wildcard
func resourceMatches(want, have []string) bool // ANY-of + same wildcard
```

Both reject malformed patterns (`"*"` not trailing, empty entry) by
validation at ingest (Decision 2 / Decision 5), so the hot path needs no
defensive re-check — `Evaluate` stays pure, I/O-free, clock-free, fully
table-testable.

**Backward compatibility.** Rules with all three new fields empty match
exactly as today — byte-compatible; existing tests pass unchanged (they stay
as regression pins, plus new truth-table cases in `tokenexchange_test.go`
and `tokenexchange_types_test.go` Hop construction): scope prefix-wildcard
hit/miss, partial-subset miss, resource ANY-of hit, `requested_token_type`
exact match, deny-short-circuits-later-allow, empty-new-fields-identical-to-
old-behavior.

---

## Decision 4: Storage model — sqlite policy store

**New file `domains/tokenexchange/sqlite/policy_store.go`** (root-module
package, same as `chain_store.go`). Migration namespace
`tokenexchange_policy_rules`, registered via a new
`PolicyStoreMaxVersion()` in `maxversions.go` (pattern: `ChainStoreMaxVersion`).

```sql
CREATE TABLE IF NOT EXISTS tokenexchange_policy_rules (
    position             INTEGER PRIMARY KEY,          -- evaluation order, 1..N
    name                 TEXT NOT NULL,
    subject_id           TEXT NOT NULL DEFAULT '',
    actor_subject        TEXT NOT NULL DEFAULT '',
    client_id            TEXT NOT NULL DEFAULT '',
    requested_token_type TEXT NOT NULL DEFAULT '',
    deny                 INTEGER NOT NULL DEFAULT 0,   -- 0/1
    scopes               TEXT NOT NULL DEFAULT '[]',   -- JSON array
    resources            TEXT NOT NULL DEFAULT '[]'    -- JSON array
);
```

- **Columns for scalars, JSON for the two lists** — the chain store's
  rationale inverted deliberately: `Replace` rewrites the whole table (never
  queries by scope/resource), so there is no index benefit in normalizing the
  lists; JSON keeps `Rule` ↔ row mapping mechanical. Governance metadata
  only, no secrets — encryption is not required (same position as
  `tokenpolicy`).
- **In-memory snapshot + copy-on-write**, mirroring `memory.Store`: `Allow`
  takes `RLock`, copies the slice header, evaluates the pure function —
  **zero I/O on the hot path**, so `Evaluate` semantics and performance are
  identical across backends.
- **`Replace`**: one transaction — `DELETE` all, `INSERT` each rule with
  `position = i+1` — commit, then swap the snapshot under the write lock.
  Any failure (constraint, lock timeout, disk) rolls back and leaves both
  disk and snapshot on the OLD set; the error propagates to the admin handler
  (`500`). Never a partial set on either side.
- **Boot load**: `New(dsn string, defaultAllow bool)` opens, pings,
  migrates, `SELECT ... ORDER BY position`, decodes JSON columns (normalize
  `null` → `[]`), builds the snapshot. Any failure (unreadable file, corrupt
  JSON) is a **loud boot error** — the server refuses to start, consistent
  with every other sqlite store. `default_allow` is not persisted: it is
  config-owned (Decision 1), so disk and config cannot disagree.
- `DB()` accessor (pattern: `chain_store.go:100`) so
  `serverbuildsign.CheckSQLiteSchema` gates schema drift at boot, plus `Ping`
  for `/readyz` + storage-health via `AppendReadyCheck` /
  `AppendStorageHealthSource` (pattern: `wireRefreshToken`).

**Multi-replica note (documented limitation).** Replicas sharing one DSN
file each hold their own snapshot; an admin PUT on replica A updates A
immediately and persists, but B serves its stale snapshot until restart.
Mitigation: SQLite's file lock serializes writers (no torn rows); governance
data is low-churn; a future invalidation-bus hook (AGENTS.md §3 cross-replica
invalidation) is the natural extension — explicitly out of scope here.

---

## Decision 5: Config + cmd wiring

**`config/config_oauth2.go`** — extend `OAuthTokenExchangeConfig` (config/
is at its frozen file-count ceiling; this file already owns the section):

```yaml
oauth:
  token_exchange:
    backend: ""        # "" | "memory" | "sqlite" — "" inherits oauth.backend
    default_allow: true
    policies: []       # inline rules (same schema as the bundle)
    policies_file: ""  # strict-YAML bundle; mutually exclusive with policies
    max_chain_lifetime: 0   # existing
```

- `backend: sqlite` uses `oauth.sqlite.dsn` (reuse of `OAuthSQLiteConfig` —
  no new DSN knob); missing DSN → boot error. `backend: redis` (inherited
  from `oauth.backend`) → boot error: the policy backend supports
  memory/sqlite only — fail loud, never silently fall back to memory.
- `policies` decodes via the config loader's strict unmarshal
  (`config/source.go:264` `DisallowUnknownField`) — unknown rule keys already
  reject at boot for inline rules.
- `default_allow` defaults `true` (byte-identical default behavior: no rules
  → every hop allowed).

**New `domains/tokenexchange/yaml.go`** — `ParseYAML(data) ([]Rule, error)`
for the bundle file, top-level `token_exchange_policies:` list (mirror of
`token_policies`). **Deliberate deviation from `tokenpolicy.ParseYAML`**:
that parser is lenient (`yaml.Unmarshal`); the requirement mandates
unknown-field rejection, so use the strict loader (`conditionalaccess`
precedent — `yaml.UnmarshalWithOptions(..., yaml.DisallowUnknownField())`).
Rule-level validation (Name non-empty, count cap, wildcard shape) runs here
too, shared with the admin PUT path.

**`cmd/sso-server/serverbuildplatform/build_governance.go`** — new
`BuildTokenExchangePolicyStore(cfg config.OAuthConfig, oauthBackend string)
(MutablePolicy, error)` modeled on `BuildTokenPolicyStore`: absent section →
`(nil, nil)`; file+inline mutual exclusion; backend selection; sqlite store
construction. **Budget**: file is 430 lines; the builder must stay ≤ ~45
lines (parse and validate live in the domain package, not here) → ≤ 475.
Placement next to `BuildTokenPolicyStore` keeps the two governance builders
co-located.

**`cmd/sso-server` wiring — budget conflict (flagged).**
`build_app_oauth.go` is 487 lines; a `wireTokenExchangePolicy` function
(doc + builder call + nil check + `sso.WithTokenExchangePolicy` + log ≈ 15
lines) plus a call site does **not fit** in 13 lines of headroom, and the
zero-exemption 500-line gate is enforced repo-wide
(`maintainability_budget_test.go` walks every directory). Resolution —
**relocate `wireTokenExchangeChainLifetime` (10 lines + call site stays) into
a new `cmd/sso-server/build_app_tokenexchange.go` alongside
`wireTokenExchangePolicy`**. This is not "while-here cleanup": it is the
budget price of the feature and co-locates the whole token-exchange
governance wiring in one cohesive file (`build_app_oauth.go` nets −10 + ~13
= ~490). `cmd/sso-server` already carries 23 non-test files, so the
AGENTS.md §2 ten-file budget is not an active gate there (its enforcement is
the `>16` drift tolerance). Fallback if the team rejects any new cmd file:
inline the ~10-line policy-wiring into `wireOAuthGrantStores`
(487 + 10 = 497 ≤ 500; function stays < 50 lines) — at the cost of the
requirement's named function.

`wireTokenExchangePolicy` calls `serverbuildplatform.BuildTokenExchangePolicyStore`,
wires `sso.WithTokenExchangePolicy(store)` when non-nil, and — because the
builder returns a `MutablePolicy` — the server's `mountAdminTokenExchangePolicies`
automatically mounts the endpoints (Decision 2). Log line mirrors
`wireTokenPolicy`'s cadence.

---

## Decision 6: Failure modes

| Failure | Behavior | Rationale |
|---|---|---|
| sqlite open/migrate/load at boot | Server refuses to start | Loud boot failure, same as all sqlite stores; a wrong rule set is worse than no server |
| `Replace` tx failure (constraint, lock, disk) | `500` to admin; disk + snapshot both on old set | Fail-closed; never partial application |
| Admin PUT validation failure | `400`, no store call | Requirement: no change on invalid payload |
| `Policy.Allow` error at `/token` | Deny → `invalid_grant` (existing `tokExEnforcePolicy`) | Unchanged oracle collapse; rule detail only in log/audit |
| Store outage at `/token` (sqlite backend, DB gone after boot) | Snapshot still serves — read path is memory-only | Read path has no I/O by design; the snapshot is the availability unit |
| Audit sink error on PUT | Mutation stands, event dropped/queued | Fail-open per AGENTS.md; recorder owns sink errors |
| Config: file+inline both set / sqlite without DSN / redis backend | Boot error | Fail loud (BuildTokenPolicyStore precedent) |
| Schema drift (live DB newer than binary) | `CheckSQLiteSchema` boot gate fails | `migrate` invariant; `PolicyStoreMaxVersion` |
| Multi-replica staleness after PUT | Stale snapshot until restart; documented | Accepted limitation (Decision 4); no torn reads ever |
| Corrupt JSON in `scopes`/`resources` column | Boot load error | Fail loud — a silently-widened deny rule is a security hole |
| Concurrent `Allow` during `Replace` | Copy-on-write snapshot; sees old or new set, never a blend | Same discipline as `memory.Store` |

---

## Decision 7: What could break the design

1. **The 500-line gate is the #1 risk.** Zero exemptions exist
   (`fileSizeExemptions` is empty and capped at zero). Every touched file's
   headroom was measured: `build_app_oauth.go` 13 (hence the relocation,
   Decision 5), `accessors_threat.go` 73 (wrappers + mount ≈ 38 — OK, but no
   room for the validation logic; keep it in `interfaces/admin`/domain),
   `build_governance.go` 70 (builder must stay lean — parsing lives in the
   domain package), `server_routes.go` 488 (+1). Any drift over these
   estimates fails `TestMaintainability_FileSizeBudget` and `make ci`.
2. **The requirement's own placement is internally inconsistent.**
   "`build_app_oauth.go` 新增 `wireTokenExchangePolicy`" contradicts the
   file budget; the design resolves it by relocation. If review rejects the
   new cmd file, the inline fallback (Decision 5) keeps the gates green but
   abandons the named function.
3. **`Replace` signature change.** Safe today (zero production callers) but
   it is an exported API change: any out-of-tree caller of
   `memory.Store.Replace` breaks. Accepted; the interface is the point of the
   change.
4. **Audit classification gates.** A new `EventType` without simultaneous
   registration in `KnownEventTypes`, `auditreport/drift_test.go`
   (`wantUncategorizedEventTypes`), `auditsink/cef.go`, and
   `auditsink/ocsf.go` fails `make ci` loudly. `event_types_completeness_test.go`
   also pins coverage. All four must land in the same change.
5. **`interfaces/sso` 60-file ceiling.** The design adds zero files there.
   The moment anyone proposes `handlers_tokenexchange.go` in that package,
   the gate fails — the wrappers must stay in `accessors_threat.go`.
6. **Strict-YAML deviation.** `tokenpolicy.ParseYAML` (the cited precedent)
   is lenient; the requirement demands unknown-key rejection. Using the
   strict loader (conditionalaccess precedent) is a deliberate divergence —
   reviewers should not "simplify" it back to lenient parsing, or typos in
   rule files silently no-op rules (a widened allow = security hole).
7. **`default_allow` read-only at admin.** GET returns it, PUT cannot change
   it. A management tool doing GET→PUT round-trips must not echo
   `default_allow` into the PUT body (extra fields ignored by design). If
   operators later need runtime fallback flips, that is a separate,
   deliberate surface — not a silent extension of this one.
8. **Semantics traps in the matcher.** (a) Resources ANY-of vs Scopes
   ALL-of — a deny on `resources: [aud1]` also matches hops carrying
   `aud1` plus unrelated audiences; intended, but the truth-table tests must
   pin it so a future "optimization" to ALL-of doesn't silently widen
   allows. (b) First-match-wins + wildcard ordering: an empty-field deny
   rule shadows every later rule — ordering is operator responsibility;
   GET returns evaluation order so the admin can audit it. (c) Wildcard
   shape validation must reject `"*x"` and `""` at ingest (both PUT and
   config), else the hot path needs defensive checks and the pure-function
   guarantee erodes.
9. **E2E restart coupling.** The acceptance E2E (admin PUT deny rule via
   sqlite → restart → exchange denied `invalid_grant`) requires the test
   harness to boot two servers against one temp DSN and to drive the admin
   API over HTTP — feasible (`test/` boots real servers; `admin_*` tests
   already do HTTP admin calls) but it is new harness surface; if the second
   boot shares the DSN with the first while it is still open, WAL/locking
   must be handled (close server 1 first).
10. **`tokenpolicy`-precedent drift in docs.** The analysis doc's false
    "sqlite backend" claim must not be copied into the new
    `docs/config-reference.md` section; cite the chain store as the actual
    precedent.
11. **Rule-count cap vs config file.** The 1000-rule cap applies to PUT
    *and* config ingest; a config bundle over the cap fails boot. Document
    the cap in `docs/config-reference.md` so operators are not surprised.
12. **OAuth backend inheritance.** `token_exchange.backend: ""` inheriting
    `oauth.backend: redis` must fail boot loudly, not silently fall back to
    memory — a silent fallback would turn persisted rules into per-replica
    volatile state without anyone noticing.

---

## Contract updates in the same change

- `docs/openapi.yaml`: `GET`/`PUT /api/v1/admin/tokenexchange/policies`
  (admin:read/admin:write), request/response schemas, 400/401/500; note
  persistence semantics on the sqlite backend.
- `docs/config-reference.md`: `oauth.token_exchange` section — `backend`,
  `default_allow`, `policies`, `policies_file`, rule schema (incl. new
  dimensions), bundle file shape, cap, mutual exclusion.
- `docs/error-codes.md`: no new codes (reuses `invalid_request` /
  `internal_error`).
- `platform/audit`: event registration per Decision 2.
- `shared/core/consts_wire.go`: `PathAdminTokenExchangePolicies`.
