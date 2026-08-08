All evidence gathered. Here's the audit.

---

# Audit: default-true `require_form_content_type` flip + 8-step migration

**Verdict: design is accurate and implementable on all four mandated concerns; two gaps (legacy-window semantics, step-6 SDK path) and three nits worth fixing before implementation.**

Every citation below was re-verified against the working tree (HEAD `4ba36040`); no citation drift found in the audit surface.

## 1. Legacy fallback window semantics — **gap (primary finding)**

The design calls the config key "the documented migration window" but leaves it unbounded, unmeasured, and silent. The repo already has a deprecation convention the design doesn't adopt:

- **Convention**: deprecated knobs parse **with a startup warning** and pin removal — `hosted_login.enabled` (`config/config_load.go:154-156`: `slog.Warn("config: hosted_login is deprecated…")`, "Removal lands with the next schema-version bump"), `feature_gates.web_spa` (config-reference.md:765, "parsed with a startup warning… removed with the next schema-version bump"; `CurrentSchemaVersion = 1`).
- **What the design's fallback lacks**:
  1. **No startup warning** when `require_form_content_type: false` / `WithCredentialFormOnly(false)` is set. An operator using the escape hatch gets silent, permanent legacy posture at boot. The `hosted_login` pattern (warn in `validate()`) is the obvious model.
  2. **No removal trigger.** No "removed with the next schema-version bump" commitment, no removal step in the 8-step migration (step 8 is only gates). Terminal behavior if the field is ever deleted is already defined by `decodeStrictWithFallback` (`config/source.go:263-277`): unknown key → startup warning → ignored → **silently reverts to strict**. That's fail-closed (the safe direction) and loud-ish, but it should be documented *now* as the window's terminal semantics, and the window itself needs a bound.
  3. **No measurability.** Strict rejections are wire-indistinguishable from malformed form bodies (oracle-safe by design — good), but the design adds no server-side counter/log for `errFormOnly`. During the window, operators cannot measure JSON traffic and therefore cannot know when enforcement can safely be made unconditional. A wire-invisible `slog` counter on the sentinel path (Info level; not an audit event, never response-visible) closes this without violating oracle safety.

## 2. ServerOptions / anySet wiring when unset — **correct**

- `ServerOptions()` seam verified (`config/config_load.go:301`, append-only blocks; `anySet()` precedent at `config/config.go:200-206`); consumers verified: `cmd/sso-server/build_app_core.go:154`, `docs/examples/basic/main.go:78`.
- The proposed `*bool` semantics are **right where anySet would be wrong**: `nil` → no append → strict default via the `NewServer` seed; `false` → must append (it's a meaningful opt-out). anySet only distinguishes all-nil from any-set, so the design correctly does append-iff-non-nil with dereferenced value. `ServerOptions()` output stays byte-identical for untouched configs, matching the feature-gates precedent.
- `NewServer` field-seeding verified (`interfaces/sso/sso.go:58-77`: assignments precede option application; `WithMaxTokenBytes` precedent at `options.go:103`).
- **Nit**: step 2's green checkpoint is only `go build ./...`, which does not compile test files. Adding `RequireFormContentType() bool` to the four Deps interfaces breaks test doubles in ≥6 files (`protocols/oauth/handle_introspect_test.go`, `introspect_cache_test.go`, `handle_revoke_test.go`, `handle_ciba_test.go`, `introspect_geo_test.go`, `handle_par_test.go` — all implement the interfaces; `grant_handler.go:37-41` composites them). `go vet ./...` (AGENTS.md-mandated) catches it, but the design's checklist should name the stub additions.

## 3. SDK form-emission sequencing vs the gensdk gate — **mostly correct, one under-specified path**

- Gate verified: gensdk design §4 — "This module MUST land before the server form-only flip (T-9(d)). Committed clients must emit form before enforcement ships"; and its step 8 — the server-side `setFormField` `json.RawMessage` case must land before regenerated clients are *released* (F-A). The server design's step 1 (F11) honors the latter. Directionality is consistent.
- **Current state**: gensdk emission has **not** landed — `gen_ts_runtime.go` has no form branch (URLSearchParams only in the query builder, :142); committed `docs/sdks/typescript/client.ts` / `python/client.py` contain 0 form occurrences. So the server change-set's step 6 is *not* verify-only today; if the server lands first, step 6 **is** the implementer.
- **Gap**: step 6 as written ("serialize with URLSearchParams / `urlencode`, set form CT") omits the client-side encoding rules the gensdk design pins in §3.3/§3.4: `authorization_details`/`claims` must encode as a **single JSON-string element** (RFC 9396 §7.1.1), Python must filter `None` scalars (F-B), TS skips `undefined`/`null`, and `client.test.mjs` #2/#4 need updates. Executing step 6 literally reproduces F-A client-side (`[object Object]` in the form body). Fix: make step 6 either (a) hard-depend on the gensdk module landing first (verify-only becomes mandatory), or (b) incorporate the gensdk §3.3/3.4 rules verbatim. Option (a) is cleaner given `cmd/gensdk` owns those files (root module, but separate campaign module per DIRECTORY_MAP).
- Note: the gate is documentary only — `sdk-surface check` never validates media types (gensdk E11), and nothing in `make ci` mechanically prevents the flip from landing while committed clients still emit JSON. Acceptable for an ordered campaign, but should be stated as such.

## 4. Impact on existing deployments and third-party clients — **correct, three refinements**

- Breakage surface verified at exact lines: eight sites (`server_token.go:30`, `server_device.go:53/242`, `server_mfa.go:255`; `handle_introspect.go:120`, `handle_par.go:66`, `handle_revoke.go:75`, `handle_ciba.go:87`), admin two excluded (`server_admin_handlers.go:293`, `options_admin.go:414` — control-plane JSON clients unaffected, D-5 verified), `/register` untouched (`ctx.Bind` JSON-only). OpenAPI: form+JSON at :641/644, :1100/1139, :1278/1281, :1345/1348 + CIBA/PAR/device per C9; "Form + JSON" paragraph :1061-1066. `route-contract`/`docs-validate` are in `make ci` (Makefile:265, :188) so the OpenAPI edit is CI-enforced; there is **no config-reference parity gate** (checks/config.py validates build config only) — the config-reference entry is review-only.
- **Refinement 1 — missing-CT clients break too**: `bind.go:24-25,43-45` default missing Content-Type to JSON. Clients that work today "by accident" (JSON body, no CT header — common in Go/PHP/curl one-offs) also 400. T-8(c) cases 5-6 cover this in tests; the CHANGELOG entry should name missing-CT explicitly, not just JSON.
- **Refinement 2 — 401→400 precedence change is client-visible**: unauthenticated JSON at `/token`/`/token/introspect` moves from 401 (binds today) to 400 `invalid_request` (bind fails first). Form requests still reach the 401 gate (T-9 case 12). This is in-scope per R4/F8, but third-party error-handling that keyed on 401 for missing creds will see 400; the CHANGELOG should state the precedence change explicitly.
- **Refinement 3 — sweep audit filter**: the F1 grep (`'"application/json"' test/` minus `/auth/login`) false-positives on the 74 non-credential JSON posts (135 files mention the media type; only 50 lines hit credential paths). The audit needs the credential-path filter, or it will demand migration of commerce/admin/selfservice tests that must stay JSON.
- Rollback verified sound: config flip (no rebuild) or single-commit revert; pure request parsing, no store state, no data migration; `config-validate-all` (Makefile:400) validates the 7 deploy configs, none of which carry the key → unaffected.

## Bottom line

| Concern | Verdict |
|---|---|
| Legacy fallback window semantics | **Gap**: no startup warning, no removal trigger ("next schema-version bump" convention exists), no measurability (add wire-invisible log/counter); terminal unknown-key behavior already defined by `decodeStrictWithFallback` |
| ServerOptions/anySet wiring | Correct; `*bool` append-iff-non-nil is the right pattern; nit: step-2 checkpoint misses test-double compile breakage (6 files) |
| SDK/gensdk sequencing | Gate verified and directional; **gap**: step 6 under-specified if the server lands first (gensdk emission not yet in tree) — must incorporate gensdk §3.3/3.4 encoding rules or make verify-only mandatory |
| Deployment/third-party impact | Correct; refinements: missing-CT breakage, 401→400 precedence, F1 grep filter, no config-reference CI gate |

Pre-existing gate failure (reported separately, unrelated): `TestArchitecture_DirectoryDepth` on 488 `docs/architect-analysis/auto/**` batch-artifact dirs.
