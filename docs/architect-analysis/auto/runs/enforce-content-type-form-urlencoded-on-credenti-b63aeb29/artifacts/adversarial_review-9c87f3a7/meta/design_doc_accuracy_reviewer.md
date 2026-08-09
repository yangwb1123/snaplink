Re-audit complete. All gates re-run at HEAD `880443ef`; both documents corrected. Full report:

## 1. Byte-accuracy verification (stub claims → measured)

| Stub claim | Measured at HEAD `880443ef` | Verdict |
|---|---|---|
| Re-checked at `0aab82b5` | Design commit adds only the stub (`git diff 0aab82b5..HEAD` = 1 file, +18) | ✓ base equivalent to HEAD |
| `bind.go:28-49` JSON-default seam + REGRESSION BOUNDARY | `BindParams` = :29-46; default branch :34-45; REGRESSION BOUNDARY comment :38-43 | ⚠ span drift → `bind.go:29-46` |
| `BindParamsFormOnly`/`ErrFormOnly` (`bind_strict.go`) | `ErrFormOnly` :16, `BindParamsFormOnly` :39 | ✓ |
| constant-time compare `client_secret.go:19-32` | **File is 26 lines; `CompareClientSecret` = :19-26** (bcrypt :20-22, `ConstantTimeStringEq` :23-25) | ✗ → `client_secret.go:19-26` |
| `config_server.go:72` + `WithCredentialFormOnly` `options.go:107-113` | key :72 ✓; option doc :107-111, func :112-114 | ⚠ → `options.go:107-114` |
| 27 tests (8 + 19) green | 8 in `bind_strict_test.go`, 19 in `credential_content_type_test.go`, all PASS; `go build`/`go vet` clean | ✓ exact |
| R7 gap: `:149`/`:94` PostForm-only; no billing e2e | `assertQuotaTokenRequest`:149 (`PostForm` :163-164), `assertRetentionTokenRequest`:94 (:107-108), no CT assert; no `test/billing*_e2e` | ✓ exact |
| introspect :154 / PAR :73 / revoke :82; CIBA :87 dual-mode; `rejectUnregisteredScopes` :202 | all exact | ✓ |
| Pre-existing failures | DirectorySubdirFanout root 24 > frozen 21 (+`docs` 18, `auto/runs` 601), FileSizeBudget `ed25519_jwt_issuer.go` 539, `TestSdkForm_PARClaimsThreaded` red at `credential_sdk_form_test.go:200` (documented-red, never skipped) | ✓ reproduced |
| compose flip at `config.yaml:21`; identities `snaplink-relay`/`billing-quota-relay`/`billing-retention-relay`; OAuth source for audit+quota, Platform for retention | `config.yaml:21` ✓; identities in `config.example.env:35/56`, `quota_relay_test.go:60,81,97,152,195` ✓; constructors `relay.go:46-51`, `quota_relay.go:427-431` (OAuth), `:347-352` (Platform) ✓ | ✓ exact |
| readyz-503 chain | `health.go:54` (503), `health_test.go:31`, `app.go:100,103`, `relay.go:295`, `quota_relay.go:472`/`:407` | ✓ exact |
| "F1–F9" with 8 detections listed | 8 items vs 9 labels; F-labels never defined in stub or named doc | ✗ self-inconsistent → **F1–F8** |
| "7-step verification plan" | Requirements §10 = **six** steps (verified) | ✗ → **6-step** |
| Evidence-inaccuracy note | requirements artifact = 32 lines, named requirements doc = 396 lines; design named doc = 240 lines | ✓ |

## 2. Correction set applied

1. **400→415 envelope** — named doc §3.1 (`ErrFormOnly` row, `Err*` row), §3.4 (mint row, precedence row), §3.6 (rows 1-2/4/5-6/7/9/16), §3.6a (E4b/E5b/E9/E10/E14). Kept as 400 where genuinely 400: form-CT parse errors (E15), empty-form-body downstream validation (E16), `/auth/mfa`, dual-mode sites.
2. **Landed opt-in default-off** — §3.7 now states `WithCredentialFormOnly(true)` is **mandatory, not robustness** (`sso.go:76` seeds false; without it the harness is vacuous legacy dual-mode).
3. **Control arm in §3.7** — raw JSON POST via `rawPost` (`credential_content_type_test.go:119`) to the **same TokenURL + same BasicAuth** as each real source; exact 415 + `exact415Body` (both no-store headers); form-200/JSON-415 pair load-bearing (bind precedes client auth, `server_token.go:30`→:35); `mintCountingIssuer` with exactly **3 `Issue` calls** (no cache masking, JSON arm minted nothing); fresh source per identity.
4. **File-name consistency** — pinned `test/billing_form_e2e_test.go` / `TestBillingFormE2E` (matches requirements §10 step 4); `billing_strict_form_e2e_test.go`/`TestBillingStrictForm` retired in §3.5 step 6, §3.6 case 9, §3.7, §4.
5. **6-step verification plan** — stub now cites requirements §10's six steps (step 6 = `make ci`); §4 notes the plan is that expansion.
6. **Migration bullet qualified** — compose **already ships strict** (`config.yaml:21`, sweep-pinned); the flip runbook applies to **helm/baremetal/k8s adoption**; rollback = drop key/set false.
7. **Superseded warnings** — named doc now carries a top banner plus §3.3 and §3.5 inline warnings: strict-default steps never shipped, steps 4-5 (invert `TestFormEncoded_JSONStillWorks`, eight-endpoint sweep) must never be re-executed; only §3.5 step 6, §3.7, §4 are live.

**Residual corrections (beyond the 7):** citation fixes `client_secret.go:19-32`→`:19-26`, `options.go:107-113`→`:107-114`, `bind.go:28-49`→`:29-46`; F1–F9→F1–F8 (8 enumerated detections); constructor spans corrected to `relay.go:46-51` / `quota_relay.go:347-352` / `:427-431`; "T-1..T-6"→"six §7 clauses (T-8(c/d); clause 5 = billing pin)".

## 3. Files changed (docs only)

- `docs/architect-analysis/auto/runs/enforce-content-type-form-urlencoded-on-credenti-b63aeb29/artifacts/design-a77de8a6/task-1-design.md` — rewritten (21 lines): self-consistent, byte-accurate, implementation-ready.
- `docs/architect-analysis/cmd-snaplink-billing-b4-4-credential-form-only-design.md` — 26 targeted edits: superseded banner + §3.3/§3.5 warnings, 400→415 rows, amended §3.7 (control arm, file name, mandatory option, exact citations), §4 plan.

No `.go` files touched; the 27 tests, billing relay tests, deploy sweep pin, and `go build`/`go vet` all re-verified green this session; the four pre-existing gate failures were reproduced and remain untouched.
