All citations verified. The spec is complete. Final summary:

## Deliverable

**`docs/architect-analysis/cmd-snaplink-audit-provisioner-b4-4-credential-form-only-requirements.md`** — Revision 2, superseding the 2026-08-07 draft of the same campaign item (which pinned a default-ON flip for a differently-worded direction entry). The analysis file was revised and entry 3 re-selected with the opt-in wording.

## Evidence verification results (all 5 direction citations checked)

| Citation | Verdict |
|---|---|
| `oauthwire/bind.go:30-45` (default → `decodeSingleJSON`) | Exact — dispatch :37, form case :38-42, JSON-default :43-46 |
| `oauthwire/auth_code_handler.go:83-85` (constant-time PKCE) | Exact — both `subtle.ConstantTimeCompare` calls at :83/:85 |
| `server_token.go:204` (`rejectUnregisteredScopes` seam) | 1-line drift — seam body is :201-203, :204 is the closing brace |
| `shared/security/constant_time.go`, `domains/authenticators/apikey.go` | Exact — :5 and :76, no work |
| Sibling billing B4-4 spec | Exists; its shared-surface facts re-verified independently |
| "No strict-mode knob exists" | Confirmed — zero hits for any form-only identifier repo-wide |

Plus: `bind_bench_test.go` (:74/:89), SDK compat tests (`test/credential_sdk_form_test.go`), all four bind sites, Deps-interface/option/config seams, deploy-tree consumers (all four compose `/token` mints are form-encoded: billing, quota, stripe `billing.go:157-165`, provisioner `platform_token.go:151-162`), and the module's own consumer (`run.go:50-58`).

## Key decisions pinned (per direction text)

- **Opt-in, default-off**: `sso.WithCredentialFormOnly` seeds `false`; `server.require_form_content_type` unset = byte-identical baseline. No test migration, no openapi JSON-variant removal (the inverse of the sibling default-ON specs).
- **415** + plain `{"error":"invalid_request"}` on the four named endpoints (`/token`, `/introspect`, `/revoke`, `/par`); device/MFA/CIBA explicitly out of scope.
- **T-8(a-e) preserved verbatim** and expanded into 20 Given/When/Then cases, including the T-9 introspect-401 regression, byte-identical form-path comparison, mode-off pins, and the single deploy-tree flip point (`ops/deploy/compose/config.yaml`) with a new sweep-assertion test.
- **Module pin**: real `PlatformTokenSource` e2e against a strict server → 200, zero changes to `cmd/snaplink-audit-provisioner`.
- Pre-existing condition reported separately: `TestSdkForm_PARClaimsThreaded` is deliberately RED pending a sibling PAR-claims branch (not ours).
