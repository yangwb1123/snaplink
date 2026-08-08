Both files are in place and identical. Summary of the deliverable:

## Requirements spec produced

**Outputs** (identical content):
- `docs/architect-analysis/auto/runs/form-urlencoded-probe-path-content-type-enforcem-51bdae73/artifacts/requirements-10762e10/requirements.md` (pipeline artifact)
- `docs/architect-analysis/cmd-sso-ctl-apiclient-b4-4-form-probes-requirements.md` (repo-visible mirror, sibling-campaign precedent)

## Evidence verification (all citations confirmed)

| Citation | Verdict |
|---|---|
| `apiclient.go:Do` JSON-only | Confirmed — `json.Marshal` :103, `Content-Type: application/json` :119, no form path |
| `token.go` runT8a/mint/runT8d/revoke/runT9 | Confirmed — all five credential sends JSON (mint :72, revoke :244, post-revoke introspect :259, T-8d :297, T-9 :353-357) |
| `oauthwire/bind.go:28` BindParams | Confirmed exactly — `default:` :43-46 → `decodeSingleJSON` for any unknown/missing CT |
| `check_test.go` golden | Confirmed — `goldenGreenStdout` :32, `TestSweep_GreenPath` :446 |

## Key findings folded into the spec

1. **Baseline is red** — `go test ./cmd/sso-ctl/apiclient/` fails 11 tests (pre-existing; sweep files are untracked WIP, `interfaces/sso` has uncommitted drift). All six root causes enumerated with evidence (REQ-0) — including the `iss "snaplink-sso"` fixture mismatch (missing `WithEd25519Issuer`, production wiring at `build_signing_issuers.go:43` passes it) — since the acceptance's "green sweep" unit test is unverifiable otherwise. This mirrors why the sibling campaign's design gate failed.
2. **T-8(e) body must be JSON** — a form body under a wrong CT 400s today too (vacuous pass); only a JSON body turns red-today (200 mint under every CT) and green under enforcement. Verified against `server_token.go:31-34` (bind failure → 400 invalid_request).
3. **Acceptance preserved verbatim** (§5) and mapped to REQ-1–REQ-8: form transport for mint/revoke/T-8d/T-9 with byte-identical `invalid_scope`/`invalid_client` pins unchanged; new `content_type` group line asserting 4xx JSON-error-envelope rejection (never a 200 token response, body never echoed); `TestSweep_FormOnlyGreen` stub pin + red-today live pin, aligned with the strict-mode contract's `400 invalid_request`.
4. **Scope bounded**: no server-side edits, no absent-CT leg, no byte-identical requirement for the new row, no T-8c; the sibling `cmd-sso-ctl-b4-4` doc is cross-referenced with the deliberate acceptance differences flagged.

No `.go` files were touched, so no build gates were triggered; the spec's verification plan (`go build/vet`, module tests, `-race`, `make ci`) is included in §9.
