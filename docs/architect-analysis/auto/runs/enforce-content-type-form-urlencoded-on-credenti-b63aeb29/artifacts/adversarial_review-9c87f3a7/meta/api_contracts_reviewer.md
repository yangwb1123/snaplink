All green. Here is the decision and verification report.

## Decision: formal `415:` entries were required — added (same-change, zero drift)

**Premise check first:** there are no "landed strict surface commits" yet — the entire surface is uncommitted working-tree state (`protocols/oauth/oauthwire/bind_strict.go` is untracked; `docs/openapi.yaml` +60, `error-codes.md` +27, `config-reference.md` +15, `feature-matrix.md` +2 are all `M` against HEAD `880443ef`, which is the design stage). So the prose-only 415 coverage was an in-flight contract gap, not shipped drift, and closing it now is required by AGENTS.md rule 6 ("update contracts in the same change") at zero incremental cost. The security review's "consistent with existing style" defense for `/token/revoke`'s missing 400 doesn't apply to *new* surface: that omission is pre-existing drift, and the strict 415 is a genuinely new wire shape (`ErrorResponse` does not describe it — the envelope carries no `error_description`/`trace_id`).

**What was added** (`docs/openapi.yaml`):
- Shared component `PlainInvalidRequestError` — exact envelope `{"error":"invalid_request"}`, `enum: [invalid_request]`, with the byte-identical/no-store/no-auth-timing contract in its description. Referenced (not inlined) four times, so byte-identity is stated once.
- Formal `"415":` entries in all four responses maps — `postToken` (after 403), `postIntrospect` (after 401), `postRevoke` (after 401), `postPAR` (after 403) — each with `Cache-Control: no-store` + `Pragma: no-cache` headers and the strict-mode-only trigger. Placed under the correct operations (verified by `operationId` scan).
- Accuracy of "default mode never returns this response" verified against the code: all four bind sites are mode-gated (`bindCredentialRequest` → `d.RequireFormContentType()` at `handle_introspect.go:90-93`, `handle_par.go:73`, `handle_revoke.go:82`; `bindCredentialParams` → `s.credentialFormOnly` at `server_jar.go:314-326`).

**Gate:** `make docs-validate` passes — kin-openapi validate, route/OpenAPI contract (241 routes / 348 operations), capability registry + "feature matrix current".

## Verification of the three contract docs — consistent, one gap closed

| File | Finding |
|---|---|
| `error-codes.md` §Token (332–340) | **Consistent.** Names exactly `/token`, `/token/introspect`, `/token/revoke`, `/par`; opt-in; 415 plain envelope; no-store headers; before-body/before-auth oracle statement; "No new error code is introduced" (`ErrFormOnly` stays internal). No eight-endpoint or default-on claim anywhere. |
| `config-reference.md:42` | **Consistent.** Single row, same four endpoints, default unset/`false` = byte-identical legacy, boot-time-only, rollback-by-key-drop. Matches `config_server.go:72` (`*bool`, append-only-when-set) and `options.go:107-113`. |
| `feature-matrix.md` | **No drift — but a completeness gap:** zero strict-mode rows existed, while the matrix's convention documents comparable opt-in wire features (OAuth 2.1 strict, FAPI 2.0, scope registry with "unwired default = byte-identical"). Added the row (line 133) with the explicit four-endpoint list, `server.require_form_content_type`/`WithCredentialFormOnly` triggers, and opt-in default — making future scope drift (e.g., "eight endpoints") detectable. Capability check still passes. |

## No other contract file needs a strict-mode row

- **Discovery** — no row needed: OIDC/RFC 8414 metadata (`/.well-known/openid-configuration`, `oauth-authorization-server`, `openid-federation` in `openapi.yaml:3568+`) has no field for request media-type strictness; the strict mode changes no discovery value (same endpoints, same methods, same metadata). There is no standalone discovery doc in `docs/`.
- **Errors** — `docs/error-codes.md` is the sole error contract; its §Token strictness row already covers the surface. No separate `errors.md` exists.

**Net:** the only open contract nit is closed (formal 415 entries + shared plain-envelope schema), the three named docs are consistent with the four-endpoint/opt-in scope (feature-matrix now makes it explicit), and discovery/errors need no further rows. No `.go` files were touched, so the Go gates don't apply to this change; the docs gate is the proportional check and it is green.
