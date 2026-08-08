Design complete. Summary:

## Evidence verification (all claims checked against HEAD `807719ea`)

Every citation in the requirements artifact verified — **no contradictions**. Key confirmations: `BindParams` default-branch JSON fallback (`bind.go:28-48`), the `bindOAuthParams` alias seam (`server_jar.go:304`), all four endpoints binding via `oauthwire.BindParams` with no-store stamped pre-bind, JSON acceptance live-tested (`test/handle_token_test.go:59,87`, `test/handle_introspect_test.go:89,237`), constant-time precedents (`mesh_authz.go:443`, `server_native_sso.go:102`, `CompareClientSecret`), and the `WithOAuth21StrictMode`/`SecurityConfig` plumbing precedents.

**Five additional load-bearing facts** found beyond the citations, two of which force corrections to the requirements:
1. **C1 — AC-2 was unachievable as written**: `jti` is `crypto/rand`-generated per token, so a success body can never be byte-identical across two exchanges. Re-anchored to structural equivalence (claims set, TTL, headers) + byte-compare on error bodies/headers and the empty `/token/revoke` 200 body.
2. **C2** — `protocols/oauth` is at its frozen fan-out ceiling (12/12): the binder-selection helper must go in `aliases.go`, not a new file.
3. **C3** — `build_app_security.go` is exactly 500 lines (and `build_stores.go` 496): config wiring goes in `wireProfilesAndMetadata()` (`build_app_oidc.go:301`), which already wires `WithOAuth21StrictMode`.
4. `interfaces/sso` is at 60/60 files — existing files only; the three Deps interfaces have exactly one production implementer plus three test structs that must gain the method.
5. Config schema is reflection-generated — no artifact to regenerate.

## Design (written to `docs/architect-analysis/auto/runs/enforce-form-urlencoded-credential-strict-mode-0a8df02f/artifacts/design-0a8df02f/task-1-design.md`)

- **API**: `oauthwire.BindParamsFormOnly` (+ shared `normalizeContentType`), `sso.WithStrictCredentialContentType()` (no-arg), `StrictCredentialContentType() bool` accessor added to `IntrospectDeps`/`RevokeDeps`/`PARDeps`, `security.strict_credential_content_type` config bool, private `Server.bindCredentialParams`; `BindParams`/`bindOAuthParams` untouched.
- **Compatibility**: default off ⇒ byte-identical; all fan-out ceilings and 500-line budgets respected; no new error codes, no OpenAPI change.
- **Failure modes**: JSON/CT-less callers break on opt-in (intended), mixed-version HA window (boot-time knob), config typo (startup log line), binder drift (shared normalization), timing-test flake (anti-flake construction with a 1024-char secret so the 1.5x bound is meaningful), oracle safety (byte-identical 400s).
- **Migration**: ship off → audit JSON callers → staging flip with log-line check → coordinated fleet flip → drop-key rollback.
- **Acceptance**: AC-1..AC-6 mapped to concrete test files (`test/credential_strict_test.go`, `oauthwire/bind_test.go`, `shared/security/client_secret_test.go` extensions), with the AC-2 correction and existing JSON tests as the T-8(c) regression lock.

Documentation-only change — no Go gates triggered.
