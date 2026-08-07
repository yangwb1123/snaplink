Design written to `docs/architect-analysis/cmd-gensdk-tokenfamily-form-design.md`. Summary of what was done:

## Verification results (evidence treated as untrusted)

All 15 evidence entries were re-checked against the tree. The spec's own corrections (C1, C2) are confirmed, plus **four new drifts found**:

- **C3 — the migration surface is 35, not 34.** The 33 enumerated `http.Post` sites match exactly, but two JSON posts via `http.NewRequest`+`Header.Set` on `/token/introspect` were missed (`handle_introspect_test.go:202` `TestIntrospect_AcceptsBasicAuth`, `introspect_batch_signed_test.go:248`). These are precisely the REQ-4.4c introspect-auth regressions and must migrate.
- **C4 — reverses "no schema change".** Only `postToken` (openapi.yaml:1102) is form-only; `postIntrospect` (1280), `postRevoke` (1347), `postPAR` (1477) declare **both** form and JSON. The openapi currently legitimizes JSON on 3 of 4 endpoints, so the JSON siblings must be removed in the same change or doc/code drift is created. The out-of-scope note's "openapi declares form-only for device endpoints" is also wrong — device/MFA/CIBA declare both, matching handlers (no drift there).
- **C5 — two editions, not three.** `cmd/sso-minimal` has only `prototype`/`minimal` runtime editions; "standard" is a build profile resolving to `editionMinimal` (already pinned at `edition_test.go:26`).
- **C6 — `PathOIDCDiscovery` lives in `interfaces/sso/server_discovery.go:18`**, not consts.go.

## Design delivered

- **API changes**: `BindFormParams` in `oauthwire` (form-only, oracle-safe 400s, body-only) + delegate `bindOAuthFormParams` in `server_jar.go`; four bind-site switches; `Operation.FormBody` + shared `usesFormBody` predicate; TS `form?` option (encoding strictly after Basic stripping); Python `_request(form=True)` with `urlencode(doseq=True)`; three openapi JSON-sibling removals; servers-list cleanup.
- **Compatibility constraints**: bounded breaking change to 4 routes, SDK signatures unchanged, `CompareClientSecret`/Basic-precedence/no-store untouched, budget gates checked (no new files, `interfaces/sso` ceiling respected).
- **Failure modes**: 8 enumerated (F1–F8), including the PAR 501-short-circuit trap, TS strip-vs-encode ordering leak, and sweep port flakiness.
- **Migration steps**: M1–M9 ordered, each keeping the tree green.
- **Acceptance mapping**: AC-1..AC-5 mapped to concrete test locations, with the C2-corrected `jwks_uri` assertion and the two-edition sweep.

No code was changed; this is a design/verification deliverable only.
