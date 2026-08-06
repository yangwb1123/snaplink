All verification is complete. Here is the validation report.

---

# Validation: strict form-only enforcement vs RFC 6749/7009/7591/7592/8628/9126 wire semantics

**Method**: cross-checked the design's 5 focus areas against HEAD code (bind seam, all 10 call sites, auth precedence, DCR/login handlers, openapi, SDK, fuzz seeds) and the RFC texts. Every claimed call-site/line/mapping was re-verified. Two material gaps and one SDK-migration detail surfaced; everything else validates.

## 1. Error code selection (400 `invalid_request` vs 415) — **VALIDATED, 400 is correct**

- RFC 6749 §5.2 defines the token-endpoint error model: default status 400, `invalid_request` = "missing a required parameter … or **otherwise malformed**". A JSON body on a form-only endpoint is malformed per §2.3.1/§3.2. The design's choice is squarely inside the OAuth error vocabulary.
- **415 would be wrong on two counts**: (a) it is an HTTP-layer status (RFC 9110 §15.5.16) absent from every OAuth RFC's error set — OAuth clients key on the §5.2 JSON error body, and 415 gets treated as a transport error; (b) it would create a **media-type oracle**: `application/json` → 415 vs `text/plain`/missing CT → 400 would reveal which CTs the server "recognizes". Uniform 400 keeps the credential family oracle-closed. The same §5.2 vocabulary governs RFC 8628 §3.1/§3.2, RFC 9126 §3.2, RFC 7009, RFC 7662, and CIBA Core §5.1.2 — all map to 400 `invalid_request` here.
- The design correctly notes 415 already exists on `/auth/login` — that endpoint is a browser-flow CSRF gate, not an RFC 6749 endpoint; the status asymmetry is deliberate and must not be "harmonized" (harmonizing login to form-encoding would be a cross-origin form-POST CSRF regression).

## 2. Media-type parsing edge cases — **VALIDATED, with one HIGH gap (PAR)**

Edge-case table (all handled correctly by the proposed gate `strip(';') → TrimSpace → ToLower → exact match`):

| Input | Result | RFC basis |
|---|---|---|
| `application/x-www-form-urlencoded` | accept | RFC 6749 §2.3.1 |
| `…; charset=UTF-8`, `;charset=utf-8`, `; boundary=x` | accept (params stripped) | RFC 9110 §8.3.1 type/subtype case-insensitive; params don't change the type |
| `Application/X-WWW-Form-URLEncoded`, leading/trailing OWS | accept | §8.3.1 |
| `…x`, `application/json`, `text/plain`, `multipart/form-data` | reject, body untouched | no JSON/multipart variant defined for these endpoints |
| missing CT, `""`, whitespace-only | reject | RFC 9110 §8.3 (recipient MAY assume octet-stream) |
| empty body + form CT | zero-value struct, no error (byte-identical) | unchanged |
| empty body + missing CT | 400 today (JSON EOF) **and** 400 after | no wire change |
| malformed percent-encoding + form CT | `ParseForm` error → 400, identical to today | unchanged |

Go's own `ParseForm` re-parses the CT via `mime.ParseMediaType`; the only CTs passing the design's gate are ones `ParseForm` handles (pathological params → `ParseMediaType` error → same 400 as today's form path). No divergence.

**HIGH gap — `json.RawMessage` is unreachable on the form path.** `parRequestForm` carries `claims` (OIDC Core §5.5) and `authorization_details` (RFC 9396 §3.1) as `json.RawMessage` (handle_par.go:100,105), and `setFormField` (oauthwire/bind.go) only handles String/Bool/Int/Pointer-Int/`[]string` — a `[]byte` slice is **silently skipped**. Today JSON-mode PAR is the only working path (verified: handle_par_test.go:112,352 and rar_test.go's `parThenLogin` post JSON with `authorization_details`; the form path already drops them, masked by JSON mode). After the switch, PAR becomes form-only and both parameters become **completely unreachable** — a wire regression against RFC 9126 §3.1 (PAR must carry the same parameters as the authorization request) and OIDC §5.5/RFC 9396 §3.1, both of which define these as JSON-serialized *form values*. The design's migration promise "assertions unchanged" is false for `rar_test.go`/`handle_par_test.go` (the RAR round-trip assertions would fail). **Required amendment**: extend the shared form binder (or the strict variant) to bind `json.RawMessage` fields from form values with JSON validation — invalid JSON → error → 400 `invalid_request` (fail closed; matches OIDC §5.5's error requirement) — plus PAR round-trip tests for claims and authorization_details. The existing downstream `ValidateAuthorizationDetails` (handle_par.go:222) then does shape enforcement as today.

Minor: a non-UTF-8 `charset` param (e.g. `ISO-8859-1`) is accepted — lenient vs §2.3.1's UTF-8 mandate, but identical to today and harmless (no transcoding occurs). The design's claim that RFC 7662 §2.1/7009 §2.1 "mandate" form-encoding overstates those two RFCs (they define POST + form parameters without §2.3.1's explicit format sentence); rejection there is still compliant since the server supports the spec-defined form contract.

## 3. Missing Content-Type breaking change — **VALIDATED; blast radius is smaller than it sounds**

HEAD behavior confirmed (oauthwire/bind.go:51–53 default → `decodeSingleJSON`; fuzz seeds `case 2/3` + comments; `TestFormEncoded_JSONStillWorks` at test/oauth_bind_test.go:272). Population analysis:

| Missing-CT request today | Before | After |
|---|---|---|
| JSON body | **200** (JSON default) | 400 — the intended target |
| form body | 400 (JSON decode of form text fails) | 400 — **no new breakage** |
| empty body (incl. Basic-only) | 400 (JSON EOF) | 400 — **no change** |

So the only newly-broken missing-CT population is JSON-body senders — exactly the population the enforcement targets. Form senders omitting the header were already broken unless their body was accidentally valid JSON. RFC 9110 §8.3 permits assuming octet-stream when CT is absent, and RFC 6749 never requires accepting CT-less requests — rejection is compliant, though stricter than necessary (defaulting missing CT to form parsing would also be compliant and marginally friendlier). T-8(c) mandates the strict choice; keep it, but it must be called out in the CHANGELOG as breaking (the design's docs/SDK steps do this).

## 4. Basic-wins on all 10 endpoints — **VALIDATED**

Basic-wins exists on exactly the 5 client-auth endpoints, all untouched: `/token` (`inspectTokenClientAuth` — any `Authorization` header yields Basic-only evidence, body creds ignored, server_token_clientauth.go:97–117), `/introspect`/`/revoke`/`/par`/`/ciba` (explicit `BasicClientCreds` override after bind). The other 5 have no Basic today (`/device/code` body-`client_id` per RFC 8628 §3.1, `/device/verify` bearer, `/auth/mfa` session, 2 admin bearer) — nothing to preserve. The strict binder never reads the `Authorization` header, so precedence is preserved by construction.

Two wire changes to document explicitly (both intended, both oracle-safe): (a) **Basic + JSON body** works today (bind OK, Basic wins) → 400 after; a JSON body is malformed regardless of auth method per §2.3.1, and Basic+JSON vs anon+JSON produce the identical 400; (b) **malformed-first ordering**: today a JSON introspect without credentials reaches auth and gets 401 `invalid_client`; after, it 400s at bind. T-9's 401 `invalid_client` oracle is preserved for well-formed (form) requests — including the query-string-only case (empty `PostForm` → zero-value → same 401).

## 5. DCR/login exclusions — **VALIDATED; the DCR exclusion is mandatory, not optional**

- `/register`, `/register/{client_id}`: RFC 7591 §2.2/§3.1 and RFC 7592 §2.1 **require** `application/json` for registration/update. Verified they bind via `ctx.Bind` (handle_register.go:201), never the seam. Enforcing form-only there would have been an RFC violation; the exclusion is spec-required. ✓
- `/auth/login`: not an RFC 6749 §3.2 endpoint (OIDC browser flow); the JSON-only 415 gate is a CSRF defense. Exclusion correct; the design's explicit "no harmonization" is a security requirement. ✓
- `/token/revoke-all` (no body, bearer-only) and `/auth/send-code` (ctx.Bind login-support, not on the seam) — correctly untouched. ✓

## Findings requiring design amendment

1. **HIGH — PAR `claims`/`authorization_details` silently dropped under form-only** (see §2). The design must add `json.RawMessage` binding (validated JSON, fail closed) to the form path, or PAR-with-RAR/claims dies silently and `rar_test.go`/`handle_par_test.go` migrations cannot keep "assertions unchanged".
2. **MEDIUM — `/device/verify` has no no-store headers.** `handleDeviceVerify` (server_device.go:229) never calls `tokenNoStoreHeaders` (the design's own evidence ledger lists only 9 of 10 no-store refs), yet its acceptance row claims "no-store on the new 400s … per endpoint class (… device …)". The new 400s on `/device/verify` would be cacheable, violating AGENTS.md's credential-endpoint rule. Add `tokenNoStoreHeaders(ctx)` to that handler in the same change (a strict improvement; today its 200s lack it too).
3. **MEDIUM — MFA `params map[string]string` is JSON-only.** `setFormField` has no map case; the flat `code`/`assertion` fields are the documented form contract (server_mfa.go:236–242 folds them into `Params` downstream). After the change, JSON `params`-based MFA completions break (intended) — but migration step 7 must specify that the Python SDK's `post_mfa_complete` sends **flat fields**, not a naive form-encode of the TypedDict (sending `params` would silently drop it and yield `mfa_invalid`).
4. **LOW — the 2 admin compromise endpoints are not RFC-governed.** Form-only there is a requirements-driven scope decision (faithful to the acceptance criteria, consistent with the seam), but it breaks admin tooling with no RFC mandate; keep it, but list it as API-breaking in the CHANGELOG alongside the credential endpoints.

**Verdict**: the design's core choices — 400 `invalid_request` over 415, uniform media-type gating, missing-CT rejection, untouched Basic-wins precedence, and the RFC-mandated DCR/login exclusions — are all wire-compliant and oracle-safe, with the missing-CT blast radius confined to the intended JSON-sender population. It ships with the three amendments above (PAR RawMessage binding, device-verify no-store, SDK MFA flattening), none of which change the seam architecture.
