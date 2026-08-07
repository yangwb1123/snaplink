All verification complete. Here's the independent report.

# Verification report: B4-4 design compatibility claims (HEAD 5c8bfcc2 + dirty tree)

Baseline: `go build ./...` and `go vet ./...` both clean on the current tree. Design refactor is **not yet implemented** (no `BindParamsFormOnly`/`normalizedMediaType` anywhere) — all claims below assess the design's inventory and mechanism against the tree.

## Claim 1: 44-site boundary (38 `oauth.BindParams` + 6 `bindOAuthParams`) — **substance OK, counts wrong**

Measured at HEAD (identical in the working tree):

| Surface | Design claim | Measured |
|---|---|---|
| `oauth.BindParams(` non-test lines | 38 | **37** (36 non-credential call sites + 1 delegate body at `server_jar.go:304`) |
| `bindOAuthParams(` | 6 call sites | **6 call sites** + 1 definition = 7 occurrences |
| Total "44" | 44 = 38+6 | 37+7=44 lines only if the definition is counted; 47 lines incl. 4 bare-alias calls |
| Non-credential boundary | "all 44 sites outside the credential ten" | **36 sites** — the 44 includes all six credential `bindOAuthParams` sites (token, device×2, mfa, admin cred-compromise :293, admin key-compromise :413) + the delegate def |

Breakdown of the real non-credential surface (the byte-identical set): commerce ×9 (incl. `payment_ingest.go:99` `normalizedJSON` gate, def :215 ✓), admin ×10 in 7 files (design's "×7 files" ✓; requirements' "8 files, 12 sites" ✗), selfservice **×15 in 11 files** (design's "8 files" ✗), adminuser ×2.

- **Mechanism holds**: `bind.go` default→JSON branch (lines 43–47) is untouched by the refactor plan; extracted `normalizedMediaType`/`bindForm` are pure, order-preserving moves → all 36 non-credential consumers remain byte-identical. Verified `BindParams` itself (:28–53), CT normalization (:31–35), form case (:38–41).
- **Two design errors**: (a) the arithmetic "38+6=44" is a mislabeled 37+7; (b) §3.3's "`bindOAuthParams` remains for non-credential dual-mode consumers" is false — **all six callers are credential**, so after the switch the delegate has zero callers (dead code; `Go` tolerates it, but the justification is wrong).
- The ten-site switch list itself is **complete and correct**: 6 delegate sites + 4 bare-alias sites (`handle_introspect.go:120`, `handle_par.go:66`, `handle_revoke.go:75`, `handle_ciba.go:87` — the design's "`oauth.BindParamsFormOnly` at these four" correctly targets the alias). `/token/revoke-all` confirmed bearer-only with no body (`HandleRevokeAll`, "bearer token only" doc) — correctly excluded. `apiclient.go:102` JSON-to-admin confirmed exact; CLI goes through the gRPC gateway, never the binder.

## Claim 2: `/auth/login` untouched — **confirmed**

`handleLogin` gates on `rejectNonJSONLogin` (server_login.go:27; def :149 — JSON-only, 415 otherwise, no BindParams). No migration step touches it; F3 explicitly excludes login-posts. All 7 login-only JSON files verified (`token_exchange_rar`, `token_exchange_actor_replay`, `device_trust_e2e`, `backchannel_logout`, `token_no_store`, `token_exchange_refresh`, `token_exchange_chain_policy`).

## Claim 3: 16-file sweep inversion — **incomplete; audit command is sound**

- `TestFormEncoded_JSONStillWorks` at `test/oauth_bind_test.go:272–283` ✓ (inversion target exists).
- Measured JSON posts to credential endpoints in `test/`: **17 files, not 16**. The design's inventory omits **`test/introspection_jwt_test.go`** — `postIntrospectAccept` (helper :61–76 sets `Content-Type: application/json` on `/token/introspect`) is used by **three tests** (:89 `TestIntrospectionJWT_SignedResponseWhenRequested`, :162 `TestIntrospectionJWT_PlainJSONWithoutAcceptHeader`, :180). Under enforcement these return 400 and fail. The design's own §4 audit grep catches it (that's how I found it) — so the audit is grep-auditable, but the "16-file inventory is the ground truth, complete" claim fails; it's 17. (`oidc-conformance/results/*.log.json` is also a non-Go hit for the post-change audit, worth an exclusion note.)
- All cited line numbers spot-checked and correct (token :59/87/284, mfa :175/200, rotation :55, cache-inv :105/122, introspect :89/237, auth_code :124, pkce :130 ✓).

## Claim 4: SDK emission + docs/sdks sync — **confirmed**

- `gen_ts_runtime.go:158–159` (`Content-Type: application/json` + `JSON.stringify`), gated by `tsUsesClientAuth` (gen_ts.go:99–101 → postToken/postIntrospect/postRevoke/postPAR) ✓; `gen_py.go:102–103` JSON branch ✓. Generated `client.ts` has exactly 4 `clientAuth: true` ops (:2878–2918); `client.py` JSON CT at :1453 ✓.
- **Regeneration is byte-identical**: `go run ./cmd/gensdk -lang all` produced zero diff on `docs/sdks/typescript/client.ts` (157596 B) and `docs/sdks/python/client.py` (133390 B) — committed artifacts in sync with the generator + embedded spec ✓. `emit_test.go` exists ✓.
- Go client SDK (`ssoclient/remote`) unaffected: `postRevoke` already form-encoded (:327–330); JSON only for `/logout` (:307) — not a credential endpoint ✓.

## Claim 5: openapi.yaml seven paths + error-codes/CHANGELOG same change — **confirmed**

All seven credential paths currently declare **both** content types in requestBody: `/auth/mfa` (:640–646), `/token` (:1099–1141), `/token/introspect` (:1277–1283), `/token/revoke` (:1344–1350), `/par` (:1474+), `/device/code` (:1540+), `/device/verify` (:1848+) ✓; "Form + JSON" paragraph at :1063–1066 ✓. Design §3.5 step 5 drops the JSON variant from exactly these seven paths, rewrites the paragraph, adds the `docs/error-codes.md` note, and the CHANGELOG breaking-wire entry — all in the same change ✓. Both files exist.

## Material findings to report back

1. **Counts are wrong** (claim 1): 38→37 prefixed lines; true non-credential boundary is **36 sites**, not 44; the "44" mixes in the six credential sites being switched and the delegate definition. Per-area counts drift (selfservice 8→11 files). The byte-identity *mechanism* is sound.
2. **Sweep inventory incomplete**: `introspection_jwt_test.go` (3 tests) missing → 17 files, not 16. The §4 audit grep will catch it at CI, but the acceptance mapping (R5 case 10) needs the file added.
3. **`bindOAuthParams` becomes dead code** after the six-site switch — the design's "remains for non-credential consumers" justification is false; plan should delete the delegate or note its removal.
4. Minor: design citations for `server_token.go:30`/`options_admin.go:414` match the dirty working tree (in-flight scope-registry task) while claiming HEAD (:29/:413). Sub-line drift, not material.
