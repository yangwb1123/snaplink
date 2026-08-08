Design delivered: **`docs/architect-analysis/cmd-snaplink-audit-provisioner-b4-4-credential-form-only-design.md`** (328 lines, 69 table rows).

## Verification verdict

All 12 evidence claims re-checked against the tree — **all confirmed**, with three corrections recorded in §2:

| Claim | Verdict |
|---|---|
| `bind.go:28-58` JSON/missing-CT→JSON default (:43-45) | ✅ exact |
| `bindOAuthParams` seam (`server_jar.go:304` → `aliases.go:97`) | ✅ exact |
| `server_token.go` no CT gate; 8 credential BindParams sites | ✅ exact (sites at token:30, introspect:120, revoke:75, par:66, device:53/242, mfa:255, ciba:87) |
| `TestBindParamsJSONDefault` (:148), `FuzzBindParams` (:28) | ✅ exact |
| C1 `/register` is `ctx.Bind` JSON-only (`router.go:137`); C2 blast radius (44 non-credential sites, `payment_ingest.go:99` JSON-required); C3 T-9 bind-before-auth (:120→:134, 1-line drift); C4 config seam (`config_server.go:16`, `ServerOptions()` :301); C5 sweep inventory; C6 OpenAPI; C8 audit-provisioner has zero credential code | ✅ all confirmed |
| **Correction C9** | Requirements R5.5 omitted CIBA from the OpenAPI sweep — it's 8 paths, not 7 (JSON variant at ~:1610) |

## Design decisions (honoring this module's two deltas vs the sibling)

- **API**: additive `oauthwire.BindParamsFormOnly` + unexported `errFormOnly`, shared `normalizedMediaType`/`bindForm` refactor, `oauth.BindCredentialParams` flag dispatch, `sso.WithCredentialFormOnly(bool)` (default **true**, seeded in `NewServer` — verified implementable at `sso.go:58`), `ServerConfig.RequireFormContentType *bool` wired in `ServerOptions()` only when set (anySet precedent). No new `Err*`, no oracle.
- **D-1 (config knob, delta)**: `server.require_form_content_type` default true; legacy fallback is the documented migration window; acceptance case 15 tests both halves.
- **D-5 (delta)**: the two admin BindParams sites (`server_admin_handlers.go:293`, `options_admin.go:414`) stay dual-mode — explicitly NOT flipped.
- **Adopted from sibling decisions**: RawMessage JSON-string form decoding (F11, keeps RAR-over-PAR green on form), MFA `params` fail-loud (F12), SDK form emission in the same change set (D-3, with the gensdk sequencing gate from `cmd-gensdk-tokenfamily-form-emission-design.md` §4).
- **16 failure modes** (F1-F16 incl. config-knob wiring, admin/register accidental flips), **8-step migration**, and **all 18 acceptance cases + F11/F12/D-3/D-5 mapped to named tests**.

## Gate status

`go build ./...` + `go vet ./...` clean. **Pre-existing failure to report separately**: `TestArchitecture_DirectoryDepth` fails on 488 `docs/architect-analysis/auto/**` batch-artifact directories (depth 4-8) — reproduced with my change stashed, unrelated to this work.
