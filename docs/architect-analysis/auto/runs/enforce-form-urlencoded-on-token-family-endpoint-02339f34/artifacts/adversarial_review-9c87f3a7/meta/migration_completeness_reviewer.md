All verification complete. Here is the full assessment.

---

# Verification report: revised M4/M6 enumeration (Gap B + consumer Gap 1 absorbed)

## Claim 1 — "exactly 36 JSON post sites across 15 files incl. `test/introspection_jwt_test.go:66`" — **CONFIRMED for the `test/` surface**

Independently re-derived from the tree (not from the design):

- **33 direct `http.Post(…, "application/json", …)` sites** targeting the four endpoints, across **14 files** — exact file:line match with the C3 enumeration: `auth_code_test.go:124,484`; `claims_param_test.go:352`; `handle_device_test.go:130,312,342`; `handle_introspect_test.go:89,237`; `handle_par_test.go:112,352`; `handle_token_test.go:59,87,284`; `introspect_batch_signed_test.go:101,139,163,223`; `introspection_cache_invalidation_test.go:105,122`; `oauth_bind_test.go:276`; `oidc_test.go:228`; `pkce_test.go:130,421,441`; `rar_test.go:265,429,480,527`; `refresh_rotation_claims_test.go:55`; `refresh_token_test.go:118,342,375,496`.
- **3 `http.NewRequest`+`Header.Set("Content-Type","application/json")` sites** on `/token/introspect`: `handle_introspect_test.go:201-202` (`TestIntrospect_AcceptsBasicAuth`), `introspect_batch_signed_test.go:245-248` (`TestIntrospectSigned_UnwiredSignerStaysPlainJSON`), and **`test/introspection_jwt_test.go:66`** inside `postIntrospectAccept` (helper at :61-75, `Header.Set` at :70; consumed by three RFC 9701 tests at :89/:162/:180) — the Gap B site and the 15th file.
- Other `NewRequest`+JSON sites in `test/` were checked and target out-of-scope endpoints (`/logout` at `introspection_cache_invalidation_test.go:133`, `/device/verify` at `handle_device_test.go:111`).

**Total: 36 sites, 15 files.** ✓

## Claim 2 — quickstart migration — **CONFIRMED**

- `docs/examples/quickstart/main.go:163-164` — `exchangeCode` calls `postJSON(base+"/token", …)`; it is the **only** non-test in-tree JSON consumer of the four endpoints.
- `loginForCode` at :144 uses the same `postJSON` helper (declared :214, `http.Post` :216) for `/auth/login` — correctly out of scope; the revision's "keep `postJSON`" is right.
- Payload is flat strings, so `url.Values{…}.Encode()` + form CT is a drop-in; `make examples` only builds the tree (`go build`), so CI would not catch the break — the migration is genuinely required.

## Claim 3 — static-tree scoping — **CONFIRMED facts; the design currently says nothing (revision is required)**

- `ops/deploy/openresty/fullstack/static/` is entirely untracked: `??` in `git status`, zero `git ls-files` entries, **not** gitignored (`git check-ignore` exit 1; no `.gitignore` pattern covers it).
- Stale snapshots confirmed: `client.ts` ("Minimal, hand-scoped", `JSON.stringify` at :636, no `clientAuth`), `client.py` (`json.dumps` at :448), `openapi.yaml` (`localhost:8080` at :53, form+JSON siblings for `postIntrospect` :971+, `postRevoke` :1047, `postPAR` :1177).
- Nothing in the repo references or syncs it (no Makefile/script/CI/nginx hit).
- **Gap**: the current design doc has zero sentences about this tree. The revised patch must add the explicit scoping (source-level regen in the same change; the static copy refreshes only when the external pipeline re-runs — and its openapi carries the same C4 JSON siblings until then).

## Claim 4 — "no remaining in-tree JSON post targets the four enforced endpoints" — **FALSE as a global statement; the four enumerated areas pass, but a major surface was missed**

**Clean (verified):**
- **Nested modules**: `sso-mcp` (local JWKS validation only, zero HTTP to the four), `sso-operator` (admin config GET + cluster-diff only), `sso-ctl` (admin routes), `snaplink-stripe-adapter` (`/token` hit is a mock of the *external billing* API, not the SSO), `saml` (`httptest.NewRequest(POST, "/token", nil)` is a handler-context unit test, no body), plus all `infrastructure/*` — clean.
- **loadtest**: `authcode.js`, `par.js`, `introspect.js`, `token.js` — all four endpoints form (`application/x-www-form-urlencoded`); JSON only to `/auth/login`.
- **smoke.sh**: `curl -d`/`--data-urlencode` on all four; no `application/json` anywhere in `ops/deploy/*.sh`.
- **examples**: quickstart :164 (covered by claim 2); playground `index.html` form-only; `embed-echo`/`embed-gin` JSON to `/auth/login` only.

**Missed (blocking):** the design's companion claim "no JSON callers of the four endpoints outside `test/`" — which the wire reviewer recorded as verified — is **false**. `interfaces/sso/rootcov_flow_test.go:154-172` (`rcovPostJSON` → `rcovDo`, `Content-Type: application/json` at :171) has **67 call sites in 17 `interfaces/sso/` test files** posting JSON to the four endpoints (`/token` ×58, `/token/introspect` ×5, `/token/revoke` ×2, `/par` ×2), plus **3 direct `http.NewRequest`+JSON sites** (`rootcov2_assertion_test.go:207-208`, `quota_test.go:338-344`, and 2 of the 10 JSON-content-type rows in the `rcovTokenAuthRaw` table at `rootcov_flow_test.go:641/645`). All run against `rcovNewServer` → `sso.NewServer` + `httptest.NewServer` (rootcov_flow_test.go:141-142) — the real handler stack. Under `BindFormParams` enforcement every one returns `400 invalid_request` instead of the asserted 200/401/429, breaking the rootcov/rootcov2/quota/break-glass/workload-identity/user-lifecycle suites — and the design's own section-8 verification commands include `go test ./interfaces/sso/...`, so M9 would fail. The helper indirection is why both prior sweeps missed it (no literal `http.Post`+JSON on one line). Mitigation is cheap: migrate `rcovDo` itself (single helper → form-encode + form CT) plus the 3 direct sites.

## Bottom line

- The revised enumeration is **correct for what it counts**: 36 direct sites across 15 `test/` files, with `postIntrospectAccept` as the 15th; quickstart :164 and the static-tree scoping facts are exactly as claimed (and the scoping sentence still needs to be written into the design).
- The "no remaining in-tree JSON post" proof is **incomplete**: ~70 additional JSON post sites in `interfaces/sso/` (67 via `rcovPostJSON` + 3 direct) target the four enforced endpoints and must be absorbed into M4 (as a helper-level migration) or the design's own gates fail. This is a new gap the patch must also absorb — analogous to Gap B but larger and entirely outside `test/`.

VERDICT: Revised M4/M6 enumeration verified as stated (36 sites/15 files incl. introspection_jwt_test.go:66, quickstart:164 migration, static-tree untracked/stale facts), but the "no remaining in-tree JSON post" proof fails: interfaces/sso rootcov/quota/break-glass/workload-identity/user-lifecycle suites post JSON to all four enforced endpoints via rcovPostJSON (67 sites, 17 files) plus 3 direct NewRequest sites, so the patch must absorb this surface before M4/M9 can be considered complete.
