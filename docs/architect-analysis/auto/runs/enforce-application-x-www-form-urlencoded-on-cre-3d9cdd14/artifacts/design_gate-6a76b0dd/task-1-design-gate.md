All D1 line citations verified exact (27 occurrences = 13 migrate + 14 stay, precisely as §3.7 enumerates). Verification complete.

## Independent verification summary

**Resolved with tree-verified evidence** (all re-checked at HEAD `f9ceb251`+):

| Finding (severity) | Resolution status |
|---|---|
| Legacy fallback window semantics (wire_compat primary) | ✅ Resolved — F17/F18/step 9; `validate()` warn mirrors `hosted_login` (config_load.go:152-156 ✅), removal bound to next schema bump (config.go:216 `CurrentSchemaVersion = 1` ✅), terminal semantics via `decodeStrictWithFallback` unknown-key path (source.go ✅), Info-level window gauge (F18) |
| D1 — protocol-unit sweep omitted (HIGH) | ✅ Resolved — §3.7 enumerates all 27 `core.ContentTypeJSON` occurrences **line-exact** (10/7/6/3/1; 13 migrate, 14 stay verified); fakes at :19/:28/:17/:18 + `var _ XDeps` at :58/:78/:38/:47 all exact; store-nil-before-bind ordering verified in introspect/revoke/par; `%ZZ` bad-body logic sound; fake default = true |
| D2 — test-flip contradiction | ✅ Resolved — `TestBindParamsJSONDefault` (:148) kept as legacy pin, `FuzzBindParams` at **:34** (not :28), strict fuzz added; supersession recorded against requirements doc :379-380/:395 (verified) |
| SDK step-6 gap | ✅ Resolved — (a) hard-depend / (b) verbatim gensdk §3.3/§3.4 rules; gensdk JSON-only state verified (gen_ts_runtime.go:159, gen_py.go:103) |
| C1 — governance.go collateral | ✅ Resolved — named with pin test; `Payload json.RawMessage` :35, `oauth.BindParams` :61 verified exact |
| D3, A1, step-2 nit, CHANGELOG (missing-CT + 401→400), F1 grep scoping | ✅ All resolved — D3 via reviewer-accepted "schema note" alternative; A1 bearer-before-bind verified (server_device.go:233/242); go vet added; F1 grep live-runs at 40 lines; OpenAPI 641/644, 1602/1605, 1849/1852 exact |

**Unresolved — B1 (security_reviewer, MEDIUM, explicitly on its "before implementation" list):**
- The F12 `params` fail-loud is specified **unconditional** at `parseMFACompleteRequest` (server_mfa.go:253), yet the design never gates it on `s.credentialFormOnly` **and** never carves `/auth/mfa` form+`params` out of the legacy promise — the §3.2 sentence the reviewer quoted ("byte-identical to HEAD including the JSON default") is verbatim unchanged, and no case-15 row covers legacy-mode form+params (which 400s post-F12 where HEAD silently dropped `params`). Neither requested fix — (a) gate on strict-only, or (b) explicit carve + case-15 row — was applied, and no rejection-with-evidence paragraph engages the finding. The case-15 scoping to "JSON/missing-CT acceptance" is technically accurate but does not name the delta, which is the finding's substance.

VERDICT: FAIL - B1 (F12 params fail-loud vs. the legacy byte-identical promise) is neither resolved nor explicitly rejected: the design specifies the check unconditional at server_mfa.go:253, leaves the §3.2 "byte-identical to HEAD" sentence untouched, and adds no case-15 row for legacy-mode form+params, despite the security reviewer listing it as a required before-implementation fix; all other findings (D1 HIGH, legacy-window primary, D2, C1, D3, A1, step-2 checkpoint, CHANGELOG, F1 grep) are resolved with line-verified evidence.
