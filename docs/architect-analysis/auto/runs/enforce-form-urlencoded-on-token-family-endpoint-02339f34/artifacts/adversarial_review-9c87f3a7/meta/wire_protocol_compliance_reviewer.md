All verification complete. Here is the assessment.

---

# Verification report: form-only enforcement (design `cmd-gensdk-tokenfamily-form-design.md`)

## 1. RFC alignment of the four-endpoint enforcement — PASS, with one payload-fidelity gap on `/par`

| Endpoint | RFC mandate | Current bind site | Verdict |
|---|---|---|---|
| `POST /token` | RFC 6749 §3.2 — entity-body MUST be `application/x-www-form-urlencoded` | `server_token.go:29` via `bindOAuthParams` | Aligned; body-only via `r.PostForm` matches §3.2's entity-body semantics; query credentials never bound |
| `POST /token/introspect` | RFC 7662 §2.1 — params as form data | `handle_introspect.go:120` | Aligned |
| `POST /token/revoke` | RFC 7009 §2.1 — form in entity-body | `handle_revoke.go:75` | Aligned |
| `POST /par` | RFC 9126 §3.1 — form per RFC 6749 Appendix B | `handle_par.go:66` | **Format aligned, payload fidelity incomplete (below)** |

- Oracle safety holds: all four sites already map bind failure to the identical `400 invalid_request` (`ErrInvalidRequest`); `TokenNoStoreHeaders` is set pre-bind on all four (`server_token.go:21`, `handle_introspect.go:112`, `handle_revoke.go:68`, `handle_par.go:55`), so the 400 carries no-store/Pragma automatically. No new `Err*` needed — confirmed.
- **Gap A (PAR — `json.RawMessage` silently dropped in form binding).** `parRequestForm` carries `AuthorizationDetails json.RawMessage` and `Claims json.RawMessage` (`handle_par.go:100,105`). `formIntoStruct`/`setFormField` (`oauthwire/bind.go:76-106`) has a Slice case only for `Elem.Kind()==String`; `json.RawMessage` is `[]uint8` and is **silently skipped**. RFC 9396 §2.1 defines `authorization_details` in form requests as a JSON-encoded string, and OIDC §5.5 defines `claims` the same way. Under form-only enforcement, a compliant client's payload would be silently lost: PAR succeeds (201 + `request_uri`), but the stored `PARRequest` has no authorization details — silent data loss, not a 400. This is pre-existing in today's form path, but enforcement makes it the *only* path, and the design's own migration plan would trip it: `parThenLogin` (`handle_par_test.go:349-352`) migrates to form, then the RFC 9396 assertion at `handle_par_test.go:403-405` fails. Zero form-encoded RAR tests exist today (`rar_test.go` has 0 form uses). **Fix required in the design (M2/M4): add a `RawMessage` case to `setFormField` (store `json.RawMessage(raw[0])`) plus a form-encoded RFC 9396 PAR test.**

## 2. Accept-driven signed introspection — feature unaffected; C3 surface count is wrong (36, not 35)

- Feature mechanics are orthogonal to body binding: `WantsIntrospectionJWT` reads the request `Accept` header (`introspect_cache.go:295`), response CT is `application/token-introspection+jwt` (`consts_wire.go:62`); `BindParams` only touches Content-Type/body. Form enforcement cannot reach the feature.
- `TestIntrospectSigned_AcceptHeaderOptsIntoJWTResponse` already posts form (`introspect_batch_signed_test.go:188`) — untouched.
- **Gap B — C3 misses a third `NewRequest`+JSON site.** Verified exactly: 33 direct `http.Post` JSON sites across 14 files (matches the design), plus **three** `NewRequest`+`Header.Set("Content-Type","application/json")` sites on `/token/introspect`: `handle_introspect_test.go:201-202`, `introspect_batch_signed_test.go:245-248`, and `test/introspection_jwt_test.go:66` (`postIntrospectAccept` helper — a 15th file absent from the design's list, used by three RFC 9701 tests at `:89/:162/:180`). True surface: **36 sites, 15 files**. All three `introspection_jwt_test.go` tests fail under enforcement without migration. (The remaining `/token/introspect` `NewRequest` sites — `security_anti_enum_e2e_test.go:136`, `multialg_signing_test.go:105`, `introspect_batch_signed_test.go:188` — are already form.)
- Batch introspection survives form: `tokens` as repeated form keys → `formStringSlice` → `[]string`, and the design's TS/Python form emitters produce repeated keys. `TokenRequest` has no `RawMessage` fields (only PAR does), so no Gap-A analog on `/token`.

## 3. Out-of-scope JSON endpoints — consistent, no drift (C4 correction confirmed)

Handlers `postDeviceCode` (`server_device.go:53`), `postDeviceVerify` (`server_device.go:242`), `postMFAComplete` (`server_mfa.go:255`), `postBackchannelAuthentication` (`handle_ciba.go:87`) all bind via `BindParams`/`bindOAuthParams` (JSON+form), and openapi declares **both** media types for all four (`:643/646`, `:1543/1546`, `:1604/1607`, `:1845-1851`). Handler behavior and openapi agree; nothing to fix. Also confirmed: `postToken` is the only form-only op today (`:1102`); `postIntrospect` (`:1280-1283`), `postRevoke` (`:1347-1350`), `postPAR` (`:1477-1480`) declare both — so the JSON-sibling removal (design M7) is indeed required in the same change, and the `/token` description (`:1063-1065`) referencing the nonexistent `oauth_bind.go` must be rewritten.

## 4. Breaking-change / version-skew story — bounded and one-directional, with two notes

- **New server + old JSON client**: `400 invalid_request` on exactly the four routes — the intended acceptance outcome; regenerated SDKs land in the same commit (`sdk-surface.py` registry is operationId-only; no content-type check, so emit tests are the only wire-format guard — as designed in M5).
- **New client + old server**: form is accepted by the untouched `BindParams` — no breakage. Skew is one-directional.
- **Mixed rolling fleet**: JSON clients see transient 400s from new replicas only, bounded to the upgrade window and four routes; form clients are unaffected.
- **Compliant external clients are largely immune**: RFC 8628 device pollers already send form (§3.3 — note: the design's C7 cites §3.1 for the `/token` poll; §3.1 governs the device-authorization endpoint, which is deliberately out of scope and stays JSON; the poll requirement actually comes from §3.3 + RFC 6749 §3.2. Substance correct, citation imprecise). RFC 7521 §4.2 assertion clients (`private_key_jwt`) already send form at `/token` — unaffected. `Idempotency-Key`: bind failure precedes idempotency and error responses are never cached (`finishTokenIdempotency` commits 2xx only) — no replay poisoning.

## Design-quality findings (non-blocking)

- **Gap C — hardcoded `usesFormBody` duplicates the spec as authority.** `cmd/gensdk/operations.go:189-213` already parses requestBody media types (`contentSchema`, `extractRequestBody` has `content` in hand). After M7 the openapi declares form-only for exactly the four enforced ops; a spec-derived `FormBody` (form-only iff the requestBody declares only `application/x-www-form-urlencoded`) yields exactly the four ops — device/MFA/CIBA declare *both*, so the design's stated objection to generalizing ("would pull in device/MFA/CIBA ops") is inverted. The hardcoded list creates a new unguarded drift surface (nothing checks SDK wire format against the spec), the exact doc/code drift class AGENTS.md §1 forbids.
- C3's 35-site count → **36 sites, 15 files** (Gap B); the design's M4 enumeration must be corrected, and `introspection_jwt_test.go` added to the file list.
- M3a confirmed: `test/token_no_store_test.go` covers `/token`, `/token/revoke`, `/token/introspect` only — `/par` rejection no-store coverage is genuinely missing and the design's extension is right.
- All other design citations verified accurate: bind-site line numbers (`server_token.go:29`, `handle_introspect.go:120`, `handle_revoke.go:75`, `handle_par.go:66`), `TestBindParamsJSONDefault` (`bind_extra_test.go:148`), `TestFormEncoded_JSONStillWorks` (`oauth_bind_test.go:272`), servers list (`openapi.yaml:54-57`, nothing in `docs/docscheck/` asserts on it), `interfaces/sso` at exactly 60 non-test files (ceiling respected — delegate belongs in `server_jar.go`), no JSON callers of the four endpoints outside `test/`.

VERDICT: The design's RFC alignment (6749 §3.2, 7662 §2.1, 7009 §2.1, 9126), out-of-scope consistency, and one-directional breaking-change story verify as sound; the signed-introspection feature itself is unaffected by request-side enforcement. Three corrections are required before implementation: (1) add a `json.RawMessage` case to the form binder or form-only `/par` silently drops `authorization_details`/`claims` (RFC 9396/OIDC payload loss — the one RFC-alignment gap); (2) the C3 migration surface is 36 sites across 15 files, not 35/14 (`test/introspection_jwt_test.go:66` `postIntrospectAccept` is the missed site); (3) prefer a spec-derived `FormBody` over the hardcoded four-op predicate, and fix C7's RFC 8628 §3.1→§3.3 citation.
