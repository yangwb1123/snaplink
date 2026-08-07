All claims verified. Here is the validation report.

---

# Validation: B4 grant-scaffold design (run `encode-b4-token-claims-and-scope-registry-invari-dddba3e2`)

**Basis**: repo at `4d93b696` (design stage committed); requirements spec `docs/architect-analysis/cmd-sso-ctl-generate-b4-1-2-grant-scaffold-requirements.md`; design artifact; marker simulations I ran against the actual template text. Every citation was re-verified against code.

## 0. Deliverable completeness (blocking-adjacent finding)

**The design artifact is a summary, not the design.** `task-1-design.md` (26 lines) *references* D1–D6, the FM-1..FM-8 table, the 6 migration steps, the acceptance-mapping table, and the `assertGrantContract` helper — none of it is committed. The implement stage (`from_outputs: design`) receives this summary plus the requirements spec. The requirements spec alone is sufficient to implement (it contains the exact branch code, marker list, file names, and verification plan), so this is not an implementation blocker — but the FM table and design decisions cannot be validated from the deliverable, and the helper code ("gofmt/vet clean, cyclomatic ≈10") is unrecoverable (`/tmp` scratch from this run doesn't exist; unrelated files only). The design gate should require the design body, not its summary.

## 1. R1–R4 → A1/A2/A3 → Given/When/Then mapping

### Verified sound

| Clause | Check | Verdict |
|---|---|---|
| R1 branch (`GrantedScopes`/`SplitScope`/`core.ErrInvalidScope` before `issuer.Issue(`) | A1 presence trio + order | ✓ Testable and deterministic. Simulation on the natural insertion: `GrantedScopes(` 1850 < `core.ErrInvalidScope` 1979 < `Roles(` 2520 < `issuer.Issue(` 2988; each marker occurs exactly once. Single-issuance template makes first-occurrence ordering sound. |
| R1 "never raw `req.Scope`" | D6 `}, grantedScopes)` (design strengthening over R3) | ✓ Sound and necessary: it pins the Issue argument, not just the branch. Unique occurrence at 3213, after `issuer.Issue(`. |
| R2 tenant binding | A2 `TenantID: client.TenantID` | ✓ But note: this passes on the *current* template (line 196). A2 is a pin, not new teaching — the summary's "fails if any of the three regresses" is accurate only for A1/A3 as new-fail→pass. |
| R3 | G/W/T #3 (named per-marker failures), #4 (compile gate unchanged) | ✓ Mechanical, deterministic; `TestGeneratedScaffoldsCompile` is 37 lines, ~50-line budget holds if the helper carries the assertions. |
| R4 | G/W/T #5 | ✓ Process duty (re-run + contract-sync), partially mechanical via the compile gate. Correctly labeled residual risk. |

### Gaps in the mapping

1. **R1's registry-seam note has no acceptance check.** A1–A3 pin the branch, binding, and roles call — nothing pins `rejectUnregisteredScopes`/`RejectUnregistered` teaching. Dropping the note passes every gate. The requirement's own summary advertises "registry-seam note text" as a deliverable; the mapping should give it a marker (cheap: presence of `rejectUnregisteredScopes` or `RejectUnregistered` in the generated text) or explicitly declare it review-only.
2. **R2 says "hand them into the Subject"; A3 only verifies `Roles(` precedes issuance.** A template that calls a roles function and discards the result passes A3. Deferring the handoff marker to B4-1 (R4) is the right call — but the mapping should record that A3 certifies *reference*, not *data-flow*, because the G/W/T wording ("roles-source reference") and R2 wording ("hand them into the Subject") currently disagree.
3. **A1 doesn't pin the error shape.** The branch must be 400 + plain `core.ErrorBody` (oracle-safe, no trace_id — a distinction `server_token.go:191-198` itself calls a byte-compat baseline). The markers pin only the `core.ErrInvalidScope` constant; a regression to `errorBody(...)` (trace-wrapped) or status 500 passes. The composite `core.ErrorBody(core.ErrInvalidScope)` is a contiguous string (verified at idx 1964) and costs nothing to add.
4. **Stale-citation fix is unpinned.** It lives in the template-source doc comment (lines 131-138), which is *not* part of the generated file, so no artifact marker can cover it. Acceptable; state it as review-only.

**Testability verdict**: G/W/T #1–#4 are mechanically testable and deterministic (single occurrences verified). #5 is a process duty with a mechanical core. The mapping is ~80% complete; gaps 1–3 above are each a one-marker fix.

## 2. FM-1..FM-8

**Not in the deliverable** — the artifact enumerates eight failure modes "with detection and mitigation" but contains no table. Reconstructing the coverage from the requirements, the detection matrix is:

- **Detected**: branch removed (A1 presence), branch reordered (A1 order), raw `req.Scope` passed (D6), tenant binding dropped (A2), roles reference dropped (A3), template raw-string breakage (backtick → module compile), budget overflow (maintainability gate), B4-1 contract-sync (R4 re-run — correctly the flagged residual).
- **Not detected by any gate**: registry-note regression (gap 1 above), 400/`core.ErrorBody` semantic regression (gap 3), roles-symbol swap (`ResolveRoles` passes A3 — see §3), seam rename/removal in the server making the note's teaching false.

If FM-1..FM-8's mitigation for the note is "manual review", the table should say so explicitly. Completeness verdict: the *set* plausibly covers the enumerated risks, but the undetected classes above mean the "detection" column is incomplete for R1's note and the error shape.

## 3. Named-marker helper vs the :345→:383 drift, and false positives

**Drift immunity: robust by construction.** The helper asserts on the generated artifact (`device-code_grant.go`) using content markers only — no line numbers, no `server_token.go` references. The :345→:383 drift is an *evidence-layer* fact (the requirements correctly corrected its premise: the seam at line 132 now runs before `dispatchCustomGrant` at 383, so the remaining gap is exactly the per-client `GrantedScopes` gate + claims). The template's own `dispatchCustomGrant` comment is symbol-based, not line-based, so it did not stale from the drift. Any future reflow of the template is equally invisible to content markers — that is the point of the design.

**False positives: yes, three concrete classes, all reproduced in simulation:**

- **FP-1 — prose satisfaction (true positive):** deleting the branch while adding a doc-comment mention passes A1 *only if* the prose also contains `GrantedScopes(` and `SplitScope(` — the trio co-occurrence partially mitigates this (my probe with a lone `core.ErrInvalidScope` mention correctly failed). But a "see also" comment quoting the full branch snippet would pass. Mitigation: the composite `core.ErrorBody(core.ErrInvalidScope)` marker, or window-scoping the search.
- **FP-2 — first-occurrence interference (false negative):** the assertions compare *first* occurrences. A note or doc comment containing the literal `issuer.Issue(` before the branch flips A1/A3 to a spurious failure (probe: ErrInvalidScope 2037 > Issue( 1836). This is a *live* risk, not theoretical: R1 **requires** a registry note whose exact text is uncommitted, and the note must be authored without `issuer.Issue(` and placed after the branch. The design's index simulation (1310 < 1695 < 2450) validated its own note text, but nothing in the test pins the note's wording — a future note edit breaks the gate spuriously.
- **FP-3 — loose `Roles(` matching:** direction-sensitive. `deps.ResolveRoles(` still contains `Roles(` (probe: A3 passes — false positive on symbol identity; the marker cannot distinguish the canonical roles source from any `*Roles(` call). `RolesForUser(` does not contain `Roles(` — false negative on rename. This looseness is a deliberate B4-1-survival tradeoff; record it as such.
- **FP-4 — structural (latent):** first-occurrence ordering only; a second, later `issuer.Issue(` would evade A1. Exactly one occurrence exists today (verified); the helper should assert `count == 1` so the invariant is explicit.

**Recommendations (all within the existing design's scope):** (a) window-scope the search to the example block ("Standard pattern:" → "After filling in your logic") — this kills FP-1/FP-2 doc-comment interference outright; (b) use the composite `core.ErrorBody(core.ErrInvalidScope)` for A1; (c) add a `count==1` guard on `issuer.Issue(`; (d) pin the note's placement/text in the design and require it to avoid `issuer.Issue(`; (e) add a `rejectUnregisteredScopes` presence marker for the note (gap 1).

## 4. Evidence re-verification (all claims hold at HEAD)

`rejectUnregisteredScopes` 189–204 / call at 132 before `dispatchCustomGrant` 383 (drift confirmed, no scope check in body) ✓ · `RejectUnregistered` 31–40 ✓ · `WithScopeRegistry` 494, `ScopeRegistry()` 166 ✓ · `handle_ciba.go` 306/308, `handle_par.go` 197–200, `token_client_credentials.go` 38–40 ✓ · `token_saml2_bearer.go` 53/~108–109 ✓ (one nit: the requirements table cites the bare filename; the file is `internal/handler/tokengrant/`, not `interfaces/sso/`) · `options_saml2_bearer.go` nonexistent, real handler `server_setup.go:271/283` ✓ · `generate.go:82` filename rule ✓ · `templates_handler.go` 215 lines / example 174–215 ✓ · `scaffold_build_test.go` 122 lines, test fn 37 lines ✓ · `buildAccessPayload` (`issue_payload.go:26`) and `ed25519Payload` (`ed25519_types.go:15`) emit no `tenant_id`/`roles` ✓ · `types_token.go:231`, `errors.go:170`, `aliases.go:119-120`, `oauthvalidate/scope.go:27/80` ✓ · `permissions.Provider.Roles` (`provider.go:38`), `accessors_handlers.go:103` ✓ · `WithCustomGrant` (`options_grants.go:75`) and `TokenIssuer.Issue` signature (`spi.go:246`) ✓ · `implementation-gate.md` rows 1–2 (T-8(a) claims incl. tenant_id/roles; T-8(d) registry → 400) ✓. Budget claims verified: template +25 lines stays under 500; test +helper stays under 500, function ≤50, helper cyclomatic ≈10 unverifiable (code absent) but plausible.

**Bottom line**: the mapping is sound and testable where it exists; the helper is drift-immune by construction but has three confirmed false-positive/false-negative classes (prose satisfaction, first-occurrence interference, loose `Roles(`), all fixable with window-scoping + composite markers + a count guard. The two structural gaps — R1's note unasserted and R2's "handoff" wording exceeding what A3 verifies — plus the missing design body (FM table, D1–D6 text) are the items I'd require the design stage to repair before implementation.
