# Adversarial review: built-in-matrix gate soundness boundary

I verified every load-bearing claim against HEAD, including two the deliverable does not cite: `RejectUnregistered`'s nil-registry no-op (`protocols/oauth/scoperegistry/reject.go:31-42`) and the discovery `scopes_supported` projection (`interfaces/sso/server_discovery_cache.go:170`). The verdict: the boundary is real, it is **wider than the doc labels**, and one direction (false *pass*) is effectively unlabeled.

## 1. Can the CLI emit a false verdict? Yes — on three unlabeled classes

The CLI's gate is `NewMemory(Matrix(), nil)`. The server's gate is `NewMemory(MatrixOrDefault(), ExtraScopes)` **only when `scope_registry.enabled` is true** (`build_stores.go:295-314`; `RejectUnregistered` returns false for a nil registry). Truth table:

| Server deployment | CLI false *invalid* (exit 1, server mints) | CLI false *pass* (exit 0, server 400s) |
|---|---|---|
| Registry **not enabled (the default)** | **YES — every non-matrix scope** (server mints any allowlisted scope) | no |
| enabled, built-in matrix, no extras | no — exact (the R3 class) | no — exact |
| enabled, built-in + extras | YES (extras) — FM-7 documented | no (extras only add) |
| enabled, provisioned matrix ⊋ built-in | YES (additions) — FM-5 documented | possibly (if it also drops rows) |
| enabled, provisioned matrix ⊊ built-in | possibly | **YES — dropped rows: CLI OK, `/token` 400s** |
| Version skew (CLI matrix ≠ server matrix) | YES (older CLI) | **YES (newer CLI)** |

Three findings the doc misses:

1. **The `enabled` axis is absent from the boundary.** `enabled: false` is the *default* deployment (the feature is opt-in). There, `validate` exit 1 for `billing:typo` while `/token` mints it — directly contradicting the §2 completion marker ("a scope the CLI rejects is exactly a scope /token would 400 for") and the §10.3 adoption guarantee ("cannot introduce a check that passes while runtime mints 400 (or fails while runtime mints 200)"), whose "built-in-matrix deployments" qualifier lacks the enabled qualifier too. FM-6 acknowledges an unwired registry only for the *vacuous-pass* case; the offender case is undocumented.
2. **The false-pass direction is unlabeled.** FM-5's title says "or drops built-ins", but the Behavior column and §3's non-goal describe only false positives ("may report false positives"). A provisioned matrix that drops `metering:*` rows yields CLI exit 0 for a scope `/token` 400s — the tool masking exactly the drift it exists to catch, with CI green. (Provisioning is full replacement, `MatrixOrDefault`, so removal is a first-class configuration.)
3. **Version skew is unlabeled.** The matrix is compiled into *both* binaries; §8.5's "both directions safe" covers only wire shape. The matrix is expected to grow (`config/scope_registry_test.go`: "after billing:checkout:create joins the built-in table"), so a mixed-version fleet gets both false directions.

**The operator-mutation vector is real.** A false exit 1 is indistinguishable from a true drift signal (same code, same message shape). The two "fixes" it invites are both security-relevant: (a) removing the scope from the client — on default-off deployments a silent restriction of a working client; (b) adding the scope to `extra_scopes`/provisioned matrix — a registry-wide *widening* (the scope-expansion direction AGENTS.md fails closed on server-side), and on a default-off deployment that fix doesn't even work unless `enabled` is flipped — which then activates the gate fleet-wide and starts 400ing every non-matrix scope. `validate` thus has a plausible failure cascade from false verdict to scope-expansion mutation.

## 2. Does the mitigation adequately label the boundary? No — it labels one quadrant

Labeled correctly: FM-5 (provisioned additions), FM-7 (extras), §3 non-goal, §10.3 qualifier. Missing: the enabled axis (default!), the false-pass quadrant, version skew. Additionally, the mitigation itself has a coverage hole the doc doesn't state: **"gate with `config validate` + T-8d" does not cover the CLI's own target class on provisioned deployments.** `validateScopeRegistry` checks only config-declared clients (against `MatrixOrDefault`+extras — exact, but a disjoint population from admin-registry clients), and T-8d probes a randomized scope no allowlist contains, so its 400 is produced by *allowlist-or-registry* (`token.go:376` admits the ambiguity) — it neither detects registry wiring nor validates any client's scopes. Admin-registry clients on provisioned deployments currently have **no correct offline gate at all**; the doc should say that plainly and name the fix path (below) rather than implying `check` covers it.

## 3. Exit-code/oracle concern on unknown/disabled clients? None — but state the reasoning

Verified: `ClientAdminService.Get` 404s only on `ErrNoSuchClient`; **inactive clients return 200** (`grpcadmin/admin_clients.go:199-214`), so `validate` yields a scope verdict, not an existence signal. For unknown clients, `validate` adds no discriminator `get` doesn't already have with the same credential — and the same `admin:read` class already holds `list`, which returns *every* client. Unauthenticated callers are cut off by the admin middleware (401) before the handler, identical for known/unknown ids. Unknown-client and scope-violation both collapse to exit 1 (stderr differs only in caller-supplied names). The design is sound; the doc just never says why — one sentence in §9/FM-2 would preempt the review question.

## 4. Should the predicate compare against the configured matrix?

**It cannot, and an operator-supplied "configured matrix" would not be sound either.** The CLI is a remote admin-API consumer: no config-file access, and no admin surface exposes the registry (snapshots cover clients/users/roles/assignments/menus/netpolicy only). Discovery `scopes_supported` is `FilterRegistered(reg, clientSetUnion)` — a filtered *lower bound* that omits extras never declared by a client — unusable as the gate predicate. A `--matrix`/`--extra-scopes` flag would be configurable, not sound: the operator's file can drift from the running server — the exact drift class the tool exists to catch — with no mismatch detector. (Note the repo's *other* offline gate, `validateScopeRegistry`, already uses the configured matrix; it's exact but for config-declared clients only.)

The soundness-correct predicate is the **effective registry**, obtainable only from the server. Two honest options:

- **Reframe the contract (recommended, in-scope):** change §2's runtime-agreement claim to a *static conformance* contract: "does this client conform to the built-in matrix — the gate an enabled, unprovisioned, no-extras deployment enforces." Verdicts are then never false; they're target-state conformance, with the R3 e2e triple kept as the proof of agreement on the exactness class. The pre-enablement use (validate before flipping `enabled`) is a sound, coherent primary use on default-off deployments.
- **Record the resolution path:** a server admin endpoint exposing the effective registry (enabled flag + registered patterns) would dissolve FM-5/FM-7 and the false-pass class entirely. It's a server change (out of scope here), but the doc should name it as the fix rather than leaving a permanent documented false-verdict class. An in-scope partial lever exists: cross-checking the flagged scope against discovery (`scope ∈ scopes_supported` ⟹ server would mint it, since the validated client's own scopes are in the projection union and the cache has TTL+fingerprint freshness) — a sound false-invalid suppressor, but it adds an issuer-address dependency and cannot detect provisioned removals, so it's a design decision for the next revision, not this one.

## Concrete doc edits (minimal set)

1. §2 completion marker + §10.3: qualify the exactness class — "registry-enabled, built-in matrix, no `extra_scopes`, same-version binary".
2. FM-5: split the Behavior column into both directions (additions → false invalid; **removals → false pass masking drift**); same in §3's non-goal.
3. New FM row: registry-not-enabled (default) — exit 1 does not predict `/token`; define the pre-enablement conformance use as the sound contract there.
4. FM-5/FM-7 mitigation: state that `config validate` covers config-declared clients only and T-8d checks neither client scopes nor registry wiring; name the effective-registry admin surface as the resolution.
5. §8.5: add matrix-content version-skew note (matrix is compiled into both binaries).
6. FM-2: one sentence on the oracle non-issue (same credential class holds `list`/`get`; 401 precedes handler; inactive clients return 200).

Overall: the predicate choice (built-in registry via `NewMemory(Matrix(), nil)`) is correct and correctly implemented — the doc's R1/R2/R3 mechanics are sound. The boundary *labeling* is the defect: it documents one quadrant of a four-quadrant boundary and frames the tool's headline contract as runtime agreement it cannot deliver on the default deployment.
