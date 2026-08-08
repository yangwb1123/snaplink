The design is complete. Here's the summary:

## Verification of the untrusted evidence (all 9 claims checked against HEAD)

| Claim | Result |
|---|---|
| `oauthwire/bind.go:28-51` JSON default for missing/unknown CT | ✅ `default:` :43-46 → `decodeSingleJSON` |
| `config_oauth2.go` `OAuthConfig`, no strict field | ✅ (line drift: now :68-101) |
| `ScopeRegistryConfig` default-off precedent | ✅ (now :123-137, called from `config_load.go:220`) |
| A4 schema test + `TestRun_Validate_ScopeRegistry_*` fixtures | ✅ (`main_test.go:185`, :133-285) |
| `server_token.go:17` | ⚠️ imports end; operative facts :22 (no-store) / :30 (`bindOAuthParams`) |
| `bind.go:39-42` form path | ✅ |
| Four endpoints bind via `BindParams` | ✅ introspect :120, revoke :75, par :66, aliases :97 |
| No strict knob; JSON live-tested | ✅ zero code hits; `handle_token_test.go:59,87`, `handle_introspect_test.go:89,237` |
| Loader unknown-key pass warn-only | ✅ `source.go:257-275` |

**New load-bearing finds** (beyond the citations): the form path **silently drops** PAR's `json.RawMessage` RAR/claims fields (`setFormField` has no RawMessage case — the recorded "PAR RAR/claims caveat", which strict mode would otherwise turn into silent authorization-scoping loss); `protocols/oauth` (12/12) and `interfaces/sso` (60/60) fan-out ceilings are frozen (zero new files); `validate-schema` catches misspelled knobs with **no code change** (`additionalProperties:false` at `generate.go:179`); the C3 posture gate must live in `configcmd validate` (loader stays warn-only).

## Deliverable

**`docs/architect-analysis/auto/runs/strict-oauth-wire-content-type-mode-with-config--61f15a91/artifacts/design-a77de8a6/task-1-design.md`** (+ `.meta.json`) — documentation-only, no Go gates triggered:

- **API**: `OAuthConfig.StrictWireContentType` (`yaml:"strict_wire_content_type"`, default-off) → `sso.WithStrictWireContentType()` → accessor on the three Deps interfaces → `oauthwire.BindParamsFormOnly` (+ shared `normalizeContentType`), selection via `aliases.go` helper and a private `Server.bindCredentialParams`; wired in `build_app_oidc.go`; C3 raw-YAML key-family posture scan in `configcmd validate`.
- **Key decisions honored**: `oauth.*` knob (lineage's `security.strict_credential_content_type` rejected); `400 invalid_request` byte-identity (no 415); RFC 9126 §2.1 for `/par`; C3 pinned to "family hit that doesn't resolve to `true` exits 1" (typo → validate-schema, posture → validate).
- **Compatibility**: permissive binder/`bindOAuthParams` untouched; strict-off byte-compat locked by unmodified existing tests; RAR/claims binding is strict-only so the permissive form path stays byte-identical.
- **Failure modes, 6-step migration** (ship off → audit JSON callers → staging flip → new-binary-first fleet flip → remove-key rollback — explicit `false` fails CI), and **AC-1..AC-8** mapping the six supplied checks plus the PAR caveat and T-8(e) timing test to named test homes (`test/credential_strict_test.go`, configcmd fixtures, `oauthwire/bind_test.go`, `shared/security/client_secret_test.go`).
