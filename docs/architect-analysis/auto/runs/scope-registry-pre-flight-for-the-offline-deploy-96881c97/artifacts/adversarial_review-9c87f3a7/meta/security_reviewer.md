All evidence claims re-verified against HEAD before reviewing. The design is largely faithful (every E1–E16 citation checks out, including the U7 column-order pin, the gate-before-write placement at main.go:52-60, and the seam at server_token.go:132), but the review of the four requested dimensions surfaced one material misattribution (D2's mechanism), one real predicate-mirror gap, and several smaller consistency issues.

## 1. D2 repair: mechanism misattributed, repair still correct

The design's D2 rationale (§1, §7.3) claims the original REQ-6 negative leg (clean `AllowedScopes: ["admin:read"]`, request `scope=legacy:menu:1:view`) "would 400 via the allowlist gate (GrantedScopes rule 1), masking the registry seam." This is false as written and contradicts the design's own verified E4.

Trace of the wired harness (the REQ-6 shape): `handleToken` → `dispatchTokenGrant` (server_token.go:122) splits request scopes and calls `s.rejectUnregisteredScopes` at server_token.go:132 → `RejectUnregistered` (reject.go:31-43) **before** `dispatchGrantBranch` → `HandleClientCredentialsGrant` → `GrantedScopes` (oauthvalidate/scope.go:80). `legacy:menu:1:view` is request-borne and unregistered, so the seam 400s first; rule 3 is never reached. A clean allowlist therefore *already* pins the registry predicate in the wired harness.

The repair is nonetheless **required, but for two different reasons the design never states**:

- **Positive leg reachability.** With a clean allowlist, even with `legacy:*` registered, rule 3 rejects the request (scope not in allowlist) — the extra-reconciliation leg could never return 200. The dirty seed is what makes the 200 leg possible.
- **Negative-leg registry causality.** With a clean allowlist, an *unwired* or registry-broken server 400s identically via rule 3, so the test cannot detect removal of registry enforcement. With the dirty seed, unwired → 200, wired → 400 — the rejection is now attributable to the registry.

Note the seed pins *registry enforcement* (seam + post-resolution, same predicate), not the seam specifically: if the seam were removed but the post-resolution check kept, the dirty-seed negative leg still 400s. That is fine for the design's purpose (the preflight mirrors the shared `Registered` predicate), but the doc's "the registry seam this test pins" wording and its rationale sentence should be rewritten to stay internally consistent with E4.

## 2. Predicate mirror: CLI registry is not construction-identical to the runtime registry

The design's central claim — "construction-identical to the runtime server registry … the exact expression at build_stores.go:306 … so the pre-flight can never disagree with /token" — holds only under two unstated assumptions:

- build_stores.go:306 and config_oauth2.go:52 both build from `cfg.OAuth.ScopeRegistry.MatrixOrDefault()` (config_oauth2.go:138-143), which returns the **provisioned config matrix when non-empty**, not `scopecontract.Matrix()`. A custom-matrix deployment (documented at docs/config-reference.md:20 as "present = the provisioned table REPLACES the built-in") gets a preflight predicate that disagrees with its server.
- The runtime extras come from the server YAML `extra_scopes`; the CLI extras are per-invocation with **no mechanism to load or verify the server config**. The dangerous direction: CLI extras ⊋ server extras (e.g., Phase 2's "extend `--scope-registry-extra` until the dry-run passes" without a lockstep server-config change) → preflight passes while `/token` still 400s. This is exactly the "partial registry silently widening grants" bypass: the gate's guarantee silently evaporates while looking green.

Recommendation: add a fail-closed `--scope-registry-config <server.yaml>` (load `oauth.scope_registry.matrix`/`extra_scopes`; error if the block is absent/disabled — you cannot mirror a disabled registry), or, minimally, restate the invariant as an explicit constraint and print the resolved registered-set fingerprint in the dry-run report so drift is visible. As designed, "can never disagree" is overstated in both directions: the preflight is fail-strict on sets the runtime never checks (S2/S3, see §4) and fail-loose when flag fidelity breaks.

## 3. Bypass paths and the dry-run→apply TOCTOU

- **`--apply` without `--scope-registry` (F1)** is the primary bypass and is *deliberate* (T-9 byte-compat, rollback by dropping flags). But the rollout story (Phase 3 "apply with the same flags") is unenforced process discipline: a gated dry-run followed by an unwired `--apply` silently writes the exact dirty plan the dry-run rejected. This is the real "TOCTOU between dry-run and apply" — not a data race but flag-state drift. Data TOCTOU is actually closed: apply re-reads source + target and re-runs the gate fresh (buildReport in both modes), so it never trusts the dry-run — a property worth stating explicitly in §2. Within one invocation there is no check-vs-write TOCTOU either: `validateScopeRegistration` validates the same in-memory plan object that `applyPlan` writes, the target DB is read once, and the write path never touches `clients` (S1's data). Mitigation suggestion: an stderr warning on unwired `--apply` (T-9 pins report/stdout/exit code, not stderr) or a registry-fingerprint line in the dry-run report to diff at apply time.
- **F3 vs §3.1 contradiction on empty extras.** §3.1 step 2 drops empty segments, so `--scope-registry-extra ""` or `","` silently yields a matrix-only registry — `ValidatePattern("")` is never reached. F3 lists "empty" as exit 2. Unreachable as specified. The behavior chosen is fail-closed (narrowing, never widening), so either is defensible — but the doc contradicts itself and no test pins the choice. Fix F3 or §3.1 and pin with a parse test.
- **F4 vs T-9 tension.** The SELECT change is unconditional: a hand-made schema lacking `allowed_scopes` now fails *unwired* runs (exit 1 naming the column), yet T-9/compat §1 claims "byte-for-byte pre-change behavior for every input that succeeds today." Column-less targets succeed today and fail after. Acceptable for server-created targets (column exists since v1, clients.go:42), but T-9 must be restated ("every input that succeeds today **on a server-created schema**"), or the column read must be conditional on wiring.

## 4. Fail-closed audit (F1–F12)

| Row | Verdict |
|---|---|
| F1 | Fail-open **by design** (byte-compat); see §3 for the bypass framing |
| F2 | Fail-closed, exit 2. Correct |
| F3 | Fail-closed for `"*"`/`"admin*"`; "empty" row unreachable (contradicts §3.1) |
| F4 | Loud, fail-closed — but see T-9 contradiction above; U7 pin (tenant_id first) verified against the `testTargetSchemaNoTenantColumn` fixture |
| F5 | Verified unchanged (fixture lacks both columns; SQLite names the first unknown, so tenant_id error text is preserved) |
| F6 | Correct, and server-consistent: `unmarshalClientJSON` errors propagate from the client store load (clients_scan.go:289), so the server also fails to load such a client |
| F7 | Verified: gate precedes the `cfg.Apply` branch (main.go:52-60); no write, no report; dedup/sort deterministic |
| F8/F9 | Correct for `'null'`/`'[]'`; **gap: `'{}'`** — the server treats `'{}'` as empty (clients_scan.go:272 guard list includes `"{}"`), but the design's S1 JSON parse into `[]string` would error on it (false fail). Mirror the server's empty spellings exactly: `""`, `"[]"`, `"{}"`, `"null"`. Same for an `""` allowlist entry (runtime trims it via `dedupeScopes` in rule 4; `Registered("")` is false → false fail) |
| F10 | Verified by construction (single build site at parse time) |
| F11 | Verified; matches tenant-gate shape |
| F12 | Verified; precedence order is deterministic and documented |

## 5. Does the predicate faithfully mirror runtime /token enforcement?

- **S1** is a faithful, fail-strict superset of the registry layer: every allowlist entry either flows into a rule-4 default (checked post-resolution, token_client_credentials.go:44-47) or a rule-3-validated request (checked by the seam). Checking all entries is stricter than any single request needs, which is the correct direction.
- **S2/S3 are not mirrors at all** — runtime never validates role codes/permissions at `/token` (tokens carry requested/defaulted scopes, never `permissions_json` content). They are a forward-looking policy over scope-shaped strings. Defensible (the design says so), but the "can never disagree with /token" framing must be corrected to "fail-closed superset: the preflight rejects a superset of what `/token` rejects, under the assumption CLI matrix/extras equal the server's."
- **The allowlist layer (rules 1–4) is correctly out of scope** — the tool doesn't write `clients` — and the D2-repaired integration legs correctly isolate the registry predicate (unwired → 200, wired → 400, wired+extra → 200), which is exactly the property the preflight mirrors.

**Bottom line:** the design is implementable and its gate placement, predicate reuse, and compatibility discipline are sound. Before handoff it needs (1) the D2 rationale corrected to the real reasons (positive-leg reachability, negative-leg causality), (2) a mechanism to source the preflight registry from the server config (or an explicit invariant + fingerprint), (3) the F3/§3.1 empty-extra contradiction resolved and pinned, (4) T-9 restated for the F4 column case, and (5) the `'{}'`/empty-entry spellings folded into S1's parser to match server tolerances.
