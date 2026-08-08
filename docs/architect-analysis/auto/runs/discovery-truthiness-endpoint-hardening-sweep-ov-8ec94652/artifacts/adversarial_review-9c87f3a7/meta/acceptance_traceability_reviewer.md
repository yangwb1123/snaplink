All claims now verified against the tree. Here is the end-to-end audit report.

---

# Acceptance-mapping audit — verdict: **2 of 4 dimensions fully hold; 2 have actionable gaps**

## 1. Direction acceptance → REQ → test file, with byte-level assertions — **HOLDS**

| Pin | Verified in tree | In design (§6) |
|---|---|---|
| 28-byte `invalid_request` golden | `wc -c` = **28** for `{"error":"invalid_request"}\n`; emission path verified: `ctx.JSON` (router.go:141-146) → `json.NewEncoder.Encode` (trailing `\n`); `errorBody` (handlers.go:399-401) → `ErrorBodyWithTrace` omits `trace_id` untraced (error_body.go:31-37) | REQ-4 row pins golden + `Cache-Control: no-store`/`Pragma: no-cache` + no `WWW-Authenticate`; ordering structurally guaranteed (server_token.go:22 stamps headers before bind :30) ✓ |
| 401 `invalid_token` header/body pins | middleware.go:364-366 (`missing_token` + realm-only) vs :370-371 (`invalid_token` + `Bearer realm="admin", error="invalid_token"`) — the convergence target is byte-exact; `bearerFromHTTP` collapses malformed→`""` so all four cases land in one branch | REQ-2 row: four-case table (no header/malformed/garbage/valid-shaped-unknown) → identical status, identical body bytes, identical challenge bytes ✓ |
| Mode-proof legs | `TestToken_BadJSON_400` (handle_token_test.go:85-96) asserts **status-only** 400 — CT-gate rejection (strict) and JSON-decode failure (permissive) both 400 | D8/A4 keeps it with explicit `application/json` post ✓ |
| Additive-safety | middleware_test.go has **zero** 401/`WWW-Authenticate`/`missing_token` pins today (grep = 0) — the new table is purely additive; e2e path list at admin_gateway_routing_e2e_test.go:333-338 exists, audit path absent → valid extension | REQ-2 e2e row ✓ |
| Doc targets | error-codes.md:957 = the `missing_token`/`invalid_token`/`forbidden` SCIM parenthetical; openapi.yaml:13056-13057 exact; `Bearer realm="admin"` is unique in openapi.yaml (1 hit); :387 is the Tokens-table `missing_token` row that correctly stays | §2.3, D3 ✓ |
| REQ-3 os.Exit legs | main.go:143-146/488-493 (`usageErr` → exit 2), :452 path hardcode, :461 Bearer, :496-499 (`errorf` → exit 1) — readFromURL-level 401 leg is the correct in-process choice | D5, REQ-3 row ✓ |
| REQ-1/REQ-5 | rootcov_discovery_test.go has 8 existing `TestRcovDisc_*` (additive target); `FeatureGates.AdminAPI *bool` (options_httpstack.go:294) makes the 404 negative control constructible; `newTokenHarness` (handle_token_test.go:23) is the delegation base | REQ-1 and REQ-5 rows ✓ |

## 2. Implementation-gate prescriptions in the test plan — **1 folded, 1 partial, 2 missing**

- **sso_protocol.go single-edit** — ✓ FOLDED. File is exactly 500 lines; `oauth21Strict bool` at :184 (verified); design lists only the combined-field edit (§2.2, §7 step 7 "net 0", §8 re-check). No other sso_protocol.go edit appears anywhere.
- **options.go ≤9-line budget** — ✓ satisfied but only implicitly. The sketch is 8 lines (5 doc + 3 func) → 490+8 = 498 ≤ 499. The design states "490 → ~498" but never states the ≤9-line ceiling as a hard constraint; the "no fallback file (60/60)" risk is likewise unstated. Low risk — the sketch already conforms — but the constraint should be named so a doc-comment trim is the recognized lever.
- **Permissive-contrast leg (status + golden explicitly, vacuous-guard comment)** — ⚠️ PARTIAL. §6 REQ-4 row has "permissive + `text/plain` + non-JSON → 400 **byte-identical to the strict 400**" — that is cross-response equality, not the prescribed per-leg pin (`permCode == 400` **and** `string(permBody) == "{\"error\":\"invalid_request\"}\n"` byte-compared). The golden is anchored *transitively* (strict leg pins it; permissive leg byte-equals strict), and the vacuous-comparison rationale exists in §4's failure-mode table ("permissive + JSON succeeds → no 400, per design C1/AC-2b2") — but not as a test-code guard comment, and the discriminating strict+`text/plain`/absent-CT+JSON legs are present. Recommend one sentence in the REQ-4 row: permissive leg asserts status 400 + the literal golden, with the "comparison would be vacuous under JSON payload" comment in the test.
- **oauthwire bind_test.go AC-6 normalizeContentType matrix** — ✗ **MISSING.** The gate reviewer's prescription #3 (the only test locking the extraction: case variants, `; charset=`, comma lists, quoted-CT rejection, trailing `;`) has zero presence — grep of the design for `bind_test`/`AC-6` returns nothing beyond §0's citation of the reference design; §7 step 5 lists only the bind.go edit; oauthwire has no bind_test.go today (ls verified). The shared-helper extraction is exactly the drift surface the prescription targets. **This is the single clearest omission: one new `_test.go` is fan-out-free and the design already names the file in §7 step 5.**

## 3. Config-layer acceptance for `security.strict_credential_content_type` — ✗ **MISSING**

§6 has **no config row at all**. Verified:

- **Schema/reflection test** — not mapped. `config/security_test.go` exists with `TestSecurityConfig_Parses` (natural home for a `strict_credential_content_type` parse + default-false assertion) but the design never references it; §3.7's "`config validate-schema` unaffected" is a claim, not a planned test.
- **wireProfilesAndMetadata block** — not mapped. The production block target is verified (build_app_oidc.go:301-306, mirroring the `OAuth21StrictMode` block), and the call chain exists (build_stores.go:257), but **zero** test files in cmd/sso-server reference `wireProfilesAndMetadata` today (grep), and the design plans none — so "config true → option appended + `logger.Info`; config false/default → option absent" has no pin.
- **Zero-value-off** — covered only at the server-behavior level (permissive 200 pins in credential_strict_test.go), not at the config parsing/wiring level.

Fix is small: one `config/security_test.go` row (default false; explicit `true` parses) plus one cmd/sso-server build-level assertion on the appended option.

## 4. governance.go:235-236 stale-comment fix in the REQ-2 change — ✗ **MISSING**

Verified the comment at governance.go:233-240: "EXISTING admin_auth_not_configured / missing_token / forbidden / rate_limit_exceeded literals in middleware.go". REQ-2 removes the `missing_token` literal from middleware.go, so the comment goes stale as a direct consequence. The design's §2.3 docs sweep lists only error-codes.md:957 and openapi.yaml:13056-13057; grep confirms **zero** `governance` mentions in the design. (Secondary: `rate_limit_exceeded` is already stale in that comment — it lives in governance.go:244 — pre-existing, but the one-line fix should drop both.)

---

## Bottom line

The acceptance mapping is byte-level correct wherever it exists — golden arithmetic, 401 pins, mode-proof legs, doc targets, os.Exit handling, budget math (sso_protocol.go 500/500 net-0, options.go 498) all verified against the tree. **Four additions are needed before handoff:**

1. **Add `oauthwire/bind_test.go` + AC-6 matrix** to §7/§6 (the gate reviewer's prescription #3, currently absent).
2. **Strengthen the permissive-contrast leg**: explicit per-leg status + literal-28-byte-golden assertion, vacuous-comparison guard comment in the test.
3. **Add a config-layer acceptance row** (`security.strict_credential_content_type`): parse/default-false in `config/security_test.go`, `wireProfilesAndMetadata` block pin in cmd/sso-server, zero-value-off.
4. **Fold the governance.go:235-236 comment fix** into §2.3 (drop both `missing_token` and the already-stale `rate_limit_exceeded`).

Items 1, 3, 4 are absences, not drift; item 2 is a precision upgrade on an existing leg.
