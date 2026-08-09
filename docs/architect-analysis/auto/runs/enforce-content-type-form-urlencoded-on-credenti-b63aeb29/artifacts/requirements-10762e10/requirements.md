Deliverable complete. Two synced files (396 lines):

- `docs/architect-analysis/auto/runs/enforce-content-type-form-urlencoded-on-credenti-b63aeb29/artifacts/requirements-10762e10/requirements.md` (pipeline output)
- `docs/architect-analysis/cmd-snaplink-billing-b4-4-credential-form-only-requirements.md` (named doc, Rev 2 superseding the stale Rev 1)

## Evidence verification (all 4 citations checked at HEAD `18530d0f`)

| Citation | Verdict |
|---|---|
| `oauthwire/bind.go:28-49` JSON-default seam | Confirmed exact — still exists verbatim; strict sibling `BindParamsFormOnly` (`bind_strict.go`) now sits beside it |
| `handle_introspect.go:120, handle_par.go:66, handle_ciba.go:87` | Drift reported — introspect bind moved to `bindCredentialRequest` at :154, PAR at :73 (CIBA :87 **exact**, still dual-mode) |
| `shared/security/client_secret.go:17-31` constant-time compare | Confirmed exact, no work |
| `server_token.go:199-204` oracle-safe body discipline | Confirmed — pattern relocated to the `rejectUnregisteredScopes` seam; the same plain-envelope discipline is what the 415 path reuses |

## Key finding: the direction is mostly landed

The timed-out prior implement (run `0a23f017`) left the strict binder, opt-in config (`server.require_form_content_type` / `WithCredentialFormOnly`), all **four** acceptance-endpoint wirings, contract docs (error-codes.md:332-338, config-reference.md:42, OpenAPI, CHANGELOG), and 27 passing tests in the tree. I verified this by running the gates. The **remaining delta** is the module's distinctive deliverable — the billing-consumer pin (R7): `quota_relay_test.go` asserts the minted form body but never the `Content-Type` header, and no test drives the billing identities' real `NewOAuthTokenSource`/`NewPlatformTokenSource` mints (`relay.go:45-52`, `quota_relay.go:347,427`) against a strict-mode server.

## Drifts reported (per AGENTS.md)

1. **415 vs the acceptance's literal "400"** — the landed, documented, 27-test-pinned contract answers 415 with the identical plain `{"error":"invalid_request"}` envelope; spec ratifies 415 and notes the one-number deviation (oracle-safety properties unchanged).
2. **Missing CT + empty body** — both acceptance branches pinned: strict → 415 (explicit rejection), default → byte-identical legacy 400.
3. **CIBA/device/MFA** — explicitly out of scope (direction names four endpoints; accepted sibling Rev-3 pinned the same); flagged as known remaining dual-mode surface.

## Pre-existing failures reported separately (unrelated, not touched)

- `TestArchitecture_DirectoryDepth` (pipeline's own `auto/runs` artifacts)
- `TestArchitecture_DirectorySubdirFanout` (same; root 24 > frozen 21)
- `TestMaintainability_FileSizeBudget` (`ed25519_jwt_issuer.go`, 539 lines)
- `TestSdkForm_PARClaimsThreaded` — documented deliberate-red sibling decoder interlock, must not be skipped

The acceptance checks are preserved verbatim in §7 as six testable Given/When/Then clauses, each mapped to existing test pins plus the two new R7 tests.
