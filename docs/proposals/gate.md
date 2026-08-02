All contested claims are now verified against the tree. Here is the gatekeeper cross-check.

---

# Gatekeeper Review — `domains-tokenexchange-audit-design.md` vs. review findings

**Independent verification performed this session** (beyond the reviewers'): openapi.yaml:7074-7129; `platform/audit/sqlite/sink.go:85-114` (schema + indexes + migration machinery); `auditspi/query.go:14-27`; `architecture_layer_test.go:105` (internal/handler → interfaces); `recorder_events.go` (imports, literal-key style); `migrate.go:196-204` (pragma no-op comment); `chain_store.go:40-75` (bare pool, no pragmas); `token_exchange.go:373-399`; `lifecycle.go:109-131`; `event_types.go:67-70,179,319-321`; `control_areas.go:55-56`; `error-codes.md:278`; `test/token_exchange_chain_policy_test.go` (zero `WithAuditRecorder`); `interfaces/admin/tokenexchange_chains_test.go` (exists); `agentidentity/grant.go:189-213`; `observability.md:76`; line counts 499/495/10.

## Findings cross-check: resolved vs. dismissed

| Finding | Verdict on design | Basis |
|---|---|---|
| **F1 all reviewers: chains endpoint IS in openapi.yaml (7074)** — design §2.4/§4.3 "no entry today, report separately" | **UNRESOLVED, contradicts the tree.** The design actively instructs the implementer to *not* update a mandatory contract (AGENTS.md §5). Four additive `ChainHop` properties must be added to the existing 7-field item schema in the same change; design's §4.3 omits the openapi validation step | Verified: full entry incl. operationId `getAdminTokenExchangeChain` and explicit 7-field 200 schema |
| **Architect F2: consts in `internal/handler/tokengrant`** | **UNRESOLVED, unbuildable as written.** The new `SetMeta` keys are consumed inside the `platform/audit` helpers; `platform/audit` importing `internal/handler/tokengrant` is an upward import (`architecture_layer_test.go:105`), `layerExemptions` frozen. Placing consts in tokengrant without that import = dead code. Existing house style is literal keys in `recorder_events.go`; `consts_wire.go` has `KeyScope`/`KeyOriginalSubject` only | Verified: zero `internal/` imports in platform/audit; helpers use string literals |
| **DB/Perf/QA F1/H1/F2: "indexed" claim false** | **UNRESOLVED.** `session_id`/`token_id`/`reason` are first-class columns but unindexed (indexes only on ts/type/actor/client/request/trace/tenant); `audit.Query` has no TokenID/SessionID/Reason filters; design's §3.2 join story ("suspicious jti → row via token_id") has no product API path, and §4.3 never exercises a `token_id` lookup. Design must either add Query filters + audit migration v4 indexes or declare the join offline-SQL-only — and delete the false "indexed" wording (§1.2, §3.2) | Verified sink.go:99-114, query.go:14-27 |
| **QA F1: deny-event tests have no vehicle** | **UNRESOLVED.** Design's §4.3 acceptance ("extended chain-policy harness asserts event shape + byte-identity") is unexecutable: harness wires no audit recorder, and no error-returning `Policy` double exists — the `policy_error` class would ship untested | Verified: zero `WithAuditRecorder` in `test/token_exchange_chain_policy_test.go` |
| **Protocol F4: `RecordTokenExchangeDenied` signature vs. its own spec** | **UNRESOLVED self-contradiction.** Signature lacks `subjectID` yet spec requires `SetMeta: subject_id` + `ActorID` fallback to `st.claims.Subject`; helper cannot do either with listed params | Verified against design text §1.1 |
| **Architect F4: budget step 3 is conditional, math says mandatory** | **PARTIALLY resolved.** 499 +~20 −15 ≈ 504 ⇒ step 3 is not a contingency; coupling requires SPIFFE out of stages (−21) before cycle check in. Design §4.4 says "before feature work" but §4.2 frames step 3 as "if ≥497". Must be restated unconditional | Verified counts and arithmetic |
| **DB F3 / Sec F2: chain store has no retention; memory backend unbounded** | **UNRESOLVED.** Design adds 4 columns + a row per exchange with no lifecycle story; no DELETE/Prune exists in either chain backend | Verified: no prune path in sqlite/memory chain stores |
| **DB F2 / Perf H2: documented DSN pragmas silently ignored** | **UNRESOLVED (pre-existing, per AGENTS.md §5 must be reported).** Design's "durable, cluster-shared" framing leans on a DSN that runs DELETE-journal + synchronous=FULL under modernc; `chain_store.New` is a bare pool. Reviewers recommend fixing pragmas in `New` in the same change since the design doubles write rate into that store | Verified migrate.go:203 comment; chain_store.go:52-73 |
| **QA F3: design points at wrong admin-JSON test file** | **UNRESOLVED.** Real HTTP suite is `interfaces/admin/tokenexchange_chains_test.go` (exists); `test/token_exchange_chain_store_test.go` is store-level only | Verified |
| **QA F4 / Architect F3 / Protocol F5: line-ref drift** | **UNRESOLVED (Low).** `chainMigrations` at 44-46 (design: 19-21), `tokExEnforcePolicy` 373-399 (design: 373-425). Budget analysis unaffected; "every line reference re-verified" claim overstated | Verified |
| **Protocol F2: space-join by convention, not grammar** | **PARTIALLY resolved.** Design documents the U+0020 invariant in §2.3 + round-trip test, but "symmetric by construction" is overstated (no charset enforcement on config/registration values); degenerate-value test needed | Consistent with my read |
| **Protocol F3: `sid` mis-cited as RFC 9068 §2.2** | **UNRESOLVED (Low, doc fix).** `sid` is OIDC Core §2; tree's `types_token.go:62` cites it correctly. Behavior itself is locked and correct | — |
| **Sec F3: rule attribution on `policy_error` path** | **UNRESOLVED (Low).** Design resolves rule name via type assertion even when `err != nil`; reviewer recommends skipping rule resolution on the error path to avoid misleading SIEM attribution | — |
| **Architect F6 / Protocol F7/F9, Sec F4/F5/F7, Perf M2** | **RESOLVED or acceptable.** parent_jti ≡ ChainHop.ParentJTI (design already pins semantics + acceptance check); deny-coverage scope correctly bounded; TOCTOU documented as advisory-only (acceptable per AGENTS.md §3); SDK-only reach is a documentation correction, not a design defect | Verified |

## Blocking issues (design must be corrected before implementation)

1. **OpenAPI contract instruction is wrong and mandates a violation.** The chains endpoint *is* documented (openapi.yaml:7074); the "pre-existing drift, report separately" instruction must be replaced with a same-change schema update (4 additive properties) plus an openapi validation step in §4.3.
2. **Consts placement is unbuildable as written.** New metadata-key consts must be co-located in `platform/audit` (or `shared/core` for cross-package keys); `internal/handler/tokengrant` placement fails the layer gate or produces dead code.
3. **False "indexed" claim and no retrieval path for the core join story.** §1.2/§3.2 must be corrected; the design must pick and pin: `audit.Query` TokenID/SessionID filters + audit migration v4 indexes, or an explicit offline-SQL-only contract — and §4.3 must exercise the chosen path.
4. **Deny-event acceptance tests have no vehicle.** Design must specify audit-recorder wiring in the chain-policy harness and an error-returning `Policy` double, or its own acceptance criteria remain unexecutable.
5. **`RecordTokenExchangeDenied` signature contradicts its own spec** (missing `subjectID`).

Plus mandatory-before-implementation mediums: step 3 restated as unconditional with the SPIFFE-before-cycle-copy ordering; chain-store retention/eviction story; DSN/pragma defect reported (and, per DB/perf reviewers, fixed in the same change).

**Strengths confirmed:** budget analysis (499/495/10, placement targets) is accurate to the line; migration v2 is SQLite-safe append-only; oracle-safe collapse preserved; drift-gate same-change rule correct (CC6.1 at 55-56 verified); fail-open/deny fallback mechanics consistent with `RecordDeviceCodeDecision`; `agentidentity` jti join feasible (`grant.go:200-213`); single call site for `RecordExchangeHopFailOpen` verified.

---

VERDICT: FAIL - design contains false premises (openapi entry exists; "indexed" columns) that produce mandatory-contract and acceptance-criteria violations, an unbuildable consts placement, a self-contradictory helper signature, and a deny-event test plan with no vehicle; plus unresolved retention, pragma, and budget-ordering corrections required before implementation.
