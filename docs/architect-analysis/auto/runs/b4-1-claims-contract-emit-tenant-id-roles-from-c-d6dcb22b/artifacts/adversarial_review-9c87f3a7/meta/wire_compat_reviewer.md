Verification complete. Report written to `docs/architect-analysis/auto/runs/b4-1-claims-contract-emit-tenant-id-roles-from-c-d6dcb22b/artifacts/verify-claims-byte-identity/verify.md`. Findings:

## 1. Byte-identical legacy claims — VERIFIED SOUND

- **`ed25519Payload`**: no custom `MarshalJSON`; `encoding/json` emits in declaration order; `Extra` maps are key-sorted (deterministic). Appending `tenant_id,omitempty`/`roles,omitempty` after `RequestedClaims` (the current tail) skips empty values entirely → byte-identical when empty. `omitempty` makes this position-independent when empty; tail-append additionally preserves key order for non-empty emission.
- **`TokenClaims`** (`shared/core/types_token.go:39`): never marshaled to wire in non-test code (only `workload_identity_clientauth_test.go` marshals it in a test) — adding fields is wire-inert when empty.
- **`Subject.Roles`**: `Subject` has zero JSON tags and is never JSON-marshaled — in-memory-only.
- **Compact-single-audience**: `audClaim.MarshalJSON` (len==1 → scalar string) untouched. `ed25519IDPayload` is a separate struct → no ID-token bleed by construction.
- Precedent exists: `serving_region_test.go` already pins the exact "empty → omitted, byte-identical to pre-region builds" pattern across all three signers.

## 2. Cross-repo fixture contract — HOLDS

SDK parse paths are lenient (`rs.Claims.Raw` escape hatch; `DisallowUnknownFields` only in unrelated `quotaprojection`); the RFC 7662 introspector builds its body from an explicit additive list (tenant_id/roles won't leak unless deliberately added); no hardcoded fixture JWTs in this repo break. The T-1.2 fixture (`scripts/mint-token.sh`) lives in the sink repo — this side's contract is stable claim emission + lenient parse, both verified. `KeyTenantID`/`KeyRoles` constants already exist (consts_wire.go:169,277).

## 3. Constraints/migration audit — COMPLETE with one deliverable gap

**Gap: the design artifact is only the 17-line summary** — the claimed 170-line design (10 constraints, 10 failure modes, 6 migration steps, file-by-file API changes) was never persisted (single 17-line commit; no adversarial-review artifacts). I reconstructed and audited the surface against code: all hold — no kid re-add (header already `{alg,typ,kid}`), shared `buildAccessPayload`/`claimsFromPayload` across ed25519/ecdsa/rsa, all 8 mint sites bind `TenantID`, **refresh-family** re-stamps via `refreshRotatedSubject`→`ti.Issue` with fresh roles resolution, only `*Server` implements the 8 Deps interfaces (no mock churn), `config.validate()` is the boot fail-loud seam, and deployment drift is real (`server.issuer_allowlist` declared in 3 ops configs but warn-and-ignored). Two decisions need pinning before implement: (a) empty-allowlist Host-fallback semantics vs. the line-283 `UnsetKnobHonorsForwardedHost` test; (b) special-casing the non-URL `"sso-server"` cmd default in the allowlist boot check (the summary's 200-not-503 self-correction is consistent with the opt-in reading).

## 4. Ceilings — CONFIRMED

`interfaces/sso` 170−110=**60** non-test (at ceiling), `domains/permissions` 21−11=**10** (at ceiling), `internal/handler/tokengrant` 12−2=**10** (at ceiling). The plan adds zero files: `RoleCodes()` extends an existing permissions file (mirrors `ResolveForLogin`), `ResolveMintRoles` + 7 dep accessors extend `accessors.go`/`accessors_handlers.go`, interface methods extend existing tokengrant files. No `.go` files changed, so build gates don't apply (doc-only verification).
