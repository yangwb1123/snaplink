# Disposition of finding F1: response-derived paths in `Status.Message` and the "token-free by construction" claim

Finding (operator_domain_reviewer): the design's "token-free by construction"
claim (D-D/FM4) is overstated — `validatePatch` error text embeds the
response-derived path, and a broken/malicious cluster B (which just received
token B) could echo it into `Status.Message`. Same trust class as today's
`describeAPIError`, so not a new leak class — but soften the claim or omit
raw paths.

**Disposition: CONFIRMED — raw paths must be omitted, and the op value with
them; the claim is corrected to a static-message claim and the design doc
updated (9 edits).** No oracle-safety, leak, or audit regression versus
today's `describeAPIError` behavior with the corrected wording — which is
strictly more conservative than today's 200-byte server-text echo.

## 1. Determination: may the error text embed cluster-B-response-derived paths?

Yes — as written, and the chain to the persisted surface is direct and
unconditional:

1. `validatePatch` errors embed `op.Path` verbatim (design §3.1 example:
   `op[0]: remove path "/missing" does not resolve into the snapshot`) and
   the op value (`op[2]: unsupported operation "move"`). `patch` is the
   parsed 200 body from cluster B (`postClusterDiff`, http.go:108-113) — so
   every echoed byte is cluster-B-authored.
2. `runCheck` wraps it in the static prefix
   `cluster B diff response failed structural validation: %s`
   (design §3.2) → `checkResult.message`.
3. `applyResult` writes `cr.Status.Message = result.message` unconditionally
   (ssoconfigdrift_controller.go:180), and `Reconcile` persists it via
   `Status().Update` on every attempt.

`validateRunningSnapshot`'s error is static (`"running snapshot is empty"`)
— safe as written. The finding is confirmed for `validatePatch`.

## 2. Decision: raw paths must be omitted

Omit op values and paths; errors carry only the op index (a bounded,
content-free integer) and a static reason class. Reasons:

1. **Boundedness regression vs `describeAPIError` (decisive).** Today's
   server-authored echo is capped at 200 bytes (`describeAPIError`
   `maxLen=200` truncation, http.go:129-138) and applies only to non-2xx
   bodies; a 2xx patch body contributes nothing to `Message` (only
   `len(patch)` is counted). The design's echo would be unbounded: the 2xx
   body is `io.ReadAll`-bounded only by the 15s client timeout (FM7), so a
   malicious cluster B could stream a multi-MB path or op string into
   `Status.Message`. `Status().Update` would then push an over-limit CR
   object at the API server, fail, and wedge that CR's reconcile loop into
   controller-runtime backoff — a new persisted-state wedge where today the
   same body leaves `Message` small (the memory spike is the pre-existing
   FM7; the persistence is new). "Same trust class as `describeAPIError`"
   is therefore only half-true as designed: the content class matches, the
   size bound does not. Omitting raw bytes removes the bound question
   entirely.
2. **Claim exactness.** "Token-free by construction" is narrowly true
   (validators receive no tokens), but D-D's blanket "leakage is impossible
   by construction" is false as a construction claim — the construction
   explicitly echoes response bytes. Static reasons make the corrected claim
   literally true: the only non-static content is a bounded integer index.
3. **Zero actionable diagnostic loss.** The superset property rules out
   false rejects (200k fuzz pairs, zero — rfc6901 grammar review), so every
   validation failure means cluster B's server left its documented emit set;
   remediation (upgrade server or roll back, FM2) is identical for every
   shape. `%q`-quoting/truncation would keep attacker-chosen bytes on a
   shared, persisted surface, keep the security claim hedged, and add an
   escaping convention — all for no change in remediation. The op index is
   retained so a human can locate the offending entry when re-running by
   hand.

Content-leak note for the record: omission is not required for *secrecy* —
cluster B already possesses token B (it authenticated the POST with it) and
the full snapshot (it is the request body), and `validatePatch` never echoes
cluster-A-derived bytes (`running` is used only for key lookups; helpers
return bools). The requirement is boundedness of the shared status surface,
not confidentiality.

## 3. Confirmation: no oracle-safety, leak, or audit regression vs `describeAPIError`

| Axis | Baseline today (`describeAPIError`) | After correction | Verdict |
|---|---|---|---|
| Leak class | Non-2xx server-authored text (≤200 B) already flows into `Status.Message` via `fetch/diff ... failed: %s` (http.go:82,118); tokens never appear (`TestReconcile_MessageNeverContainsBearerToken`, CRD doc "NEVER contains a bearer token") | New messages echo **zero** response bytes (static reasons + op index); strictly smaller echo surface than today's 200 B | No regression; strictly more conservative |
| Oracle safety | Failure messages already distinguish causes (fetch vs diff vs decode vs baseURL vs secret) and `failed=true` preserves `DriftDetected`/`PatchOpCount` | Same granularity, same `applyResult` semantics; new messages disclose strictly less (no paths, no op values). The operator is not an authentication oracle: both endpoints and status reads belong to the same CR-author audience, and cluster B already receives the snapshot in the POST body, so any key-existence inference from failure text conveys nothing new | No regression |
| Audit | Operator module has no audit sink or events (no `audit` package usage; `doc.go` lists an audit trail among deliberate non-goals); design non-goals exclude `Err*`/OpenAPI changes | Unchanged — nothing added, nothing removed | No regression |

One improvement beyond "no regression": the corrected wording also removes
the unbounded-persistence wedge described in §2.1 that the as-written design
would have introduced.

## 4. Corrections applied to the design doc

`docs/architect-analysis/cmd-sso-operator-controller-b4-3-truthiness-design.md`
(9 edits; the requirements doc's "token-free reason" at line 30 is accurate
and unchanged — token-freeness survives the correction):

1. §3.1 `validatePatch` doc comment — "cannot leak credentials" replaced
   with: errors are static reason strings plus the op index; response-derived
   bytes are never echoed; nothing server-authored or credential-bearing can
   reach `Status.Message` (D-D).
2. §3.1 error-format paragraph — examples now `op[2]: unsupported
   operation`, `op[0]: remove path does not resolve into the snapshot`;
   explicit "NOT echoed" rule for op values and paths.
3. D-D rewritten — rationale for omission over quoting/truncation
   (boundedness, claim exactness, grep-ability, zero diagnostic loss under
   the superset property); op index retained as content-free locator.
4. FM4 — "Token leakage / Impossible by construction" → "Response-derived
   bytes in `Status.Message` / none — static-only, stricter than today's
   200-byte `describeAPIError` echo".
5. FM2 — "Message names the op" → "names the op index and reason class".
6. §4 invariants bullet — added: new failure messages are fully static, so
   persisted `Status.Message` carries strictly fewer server-derived bytes
   than today.
7. §7 case 1 — asserts message contains op index + static reason and does
   NOT contain the offending op string.
8. §7 case 8 — asserts the exact static message end-to-end:
   `cluster B diff response failed structural validation: op[0]: unsupported
   operation` (stronger than "token-free").

No `.go` files were touched; no gates required for this doc-only change.

## 5. Adjacent items not part of this disposition

- F2 (both reviewers): "4 → 6 total files" arithmetic in §4 → correct to
  "2 → 3 non-test (cap 10); 4 → 7 total" (no total-file gate; 7 < all caps).
  Confirmed by the engineering-gates audit; left for its own disposition to
  keep this change attributable to F1.
- Engineering-gates correction 2 (process): steps 1-3 of §6 lack the
  AGENTS.md fail-fast `go build ./... && go vet ./...` after each `.go`
  edit; wired only at step 4. Confirmed; left for its own disposition.
