The deliverable is written. Here's the summary of the four hardening asks, all verified against HEAD (`234fdd7b`) in this session:

## Deliverable
`docs/architect-analysis/auto/runs/replace-host-derived-issuer-fallback-with-a-conf-ed324fea/artifacts/wire-hardening-84081c98/task-2-wire-contract-hardening.md`

## (1) Reject-on-empty at the two dormant aud skip-guards — DECIDED, unconditional
- `server_jar.go:248` (JAR) and `server_pairwise.go:343` (RFC 7523) both skip when `asIssuer == ""`. Spec: add a reject-first branch (`asIssuer == ""` → same `aud does not include %q` error family), **not mode-gated** — `requestBaseURL` (middleware/request_url.go:22-48) provably never returns `""` for a real request (minimum `"scheme://"`), so the branch is unreachable in mode-off by construction.
- Wire mapping stays identical: JAR → `400 invalid_request_object` (server_jar.go:396-397), JCA → `401 invalid_client` (server_token_clientauth.go:132-134, handle_par.go:184-186) — covers /token, /introspect, /revoke, /par, CIBA. No new `Err*`, no 503.
- Pinned (not fixed): the JAR empty-`aud` skip vs JCA empty-`aud` reject asymmetry is pre-existing; closing it would break mode-off bytes.

## (2) Discovery emission with empty issuer — 8 decisions pinned (D-A2.1…D-A2.8)
- **Emit** `"issuer":""` (non-omitempty at metadata.go:14; tag change = wire change); **emit** `"iss":""` on authz JSON/form_post/JARM/signed-authz; **omit** RFC 9728 `authorization_servers` when the *derived* value is empty (configured values verbatim — `[""]` is not a valid RFC 8414 URI and `omitempty` exists for exactly this); **omit** FCL `iss` param (existing omit-empty at accessors_feature_gates.go:483-494 — the one surface where `""` is invisible); challenges mask via `realm="sso"` fallback; BuildOPMetadata + signed_metadata inherit automatically.

## (3) Discovery normalization unconditional — CONFIRMED problem, specified fix
`buildBaseMetadata` stamps `base` and the only override is sentinel-conditional (server_discovery_config.go:263-266) — strict mode without `WithIssuer` would re-advertise host-derived `base` while `resolveIssuer` returns `""`. Spec: shared `resolvedIssuerValue(configured, base)` used by both, with the strict branch **assigning** `cfg.Issuer` in all three cases (allowlisted configured → configured; allowlisted base → base; else `""`), exact full-string membership (B3), nil-branch byte-identical to today (M2).

## (4) Zero drift + behavior table
Mode-off proof is 6 independent unreachability claims (M1–M6); the exact wire-visible table (14 rows × L/S1/S2 states) is in the doc, plus 11 test pin locations (P1–P11): `rootcov2_jar_test.go`, `rootcov2_assertion_test.go`, new `interfaces/sso/issuer_allowlist_test.go` (byte-equality + golden bodies), `test/oidc_discovery_test.go`, `test/protected_resource_metadata_test.go`, FCL/federation extensions — all legal under the 60-file ceiling (`_test.go` files don't count), with existing mode-off pins (`rootcov_flow_test.go:235-236`, `TestDiscovery_IssuerComesFromWithIssuer`, `TestPRM_DerivedDefaults`, `issuer_wiring_test.go`) as the regression boundary.

**Residuals recorded:** JAR empty-aud leniency, JAR/JCA asymmetry, PRM `resource` stays base-derived, token `iss`/JWKS out of scope, and the S2 per-request ERROR-log flood vector (flagged for the design gate).
