All resolved and verified. Here's the summary of the D1/D2 resolution applied to the design document:

## Changes to `docs/architect-analysis/cmd-snaplink-audit-provisioner-b4-4-credential-form-only-design.md` (now 617 lines)

### New §3.7 "Protocol-unit sweep inventory and test-pin resolution (D1/D2)"

**D1 — enumeration (verified against the tree, not just the finding):** the 27 `core.ContentTypeJSON` occurrences split into **13 bind-path posts** (migrate) and **14 non-binding occurrences** (pinned as-is):

- **Migrate (13):** handle_revoke_test.go:93/103, handle_introspect_test.go:115/125, handle_par_test.go:54/63/72/**182/227/243**, handle_ciba_test.go:70/79/88. Precise correction to the finding: only the **three PAR `authorization_details` rows** actually go red under a true-returning fake (they assert specific error codes/201 after a successful bind); the other 10 stay green purely by handler ordering (store-nil checks precede the bind) or generic-400 assertions — all 13 still migrate so the F1 audit can demand zero JSON on bind paths. The "bad body" rows must switch to malformed percent-encoding (`%ZZ`) — a raw `{nope` form body binds and falls through to the 401 auth gate (verified against each handler's check/bind ordering).
- **Stay (14):** 8 `TestHandleRevokeAll` posts (`/token/revoke-all` is bearer-only — handle_revoke.go:181 never binds), 4 response Content-Type header assertions (:508/509/518/519), 2 direct `introspectOne`/`introspectAccess` calls (introspect_cache_test.go:79, handle_introspect_test.go:803).
- **Fake default decided: `true`** — the four fakes (`revokeDeps` :19/:58, `introspectDeps` :28/:78 — reused by introspect_cache_test.go:79 and introspect_geo_test.go:49 — `parDeps` :17/:38, `cibaDeps` :18/:47) gain `RequireFormContentType() bool { return true }`, matching the production default so the strict path is unit-tested. Step-2 checkpoint upgraded to `go build ./... && go vet ./...` (build doesn't type-check test doubles).

**D2 — test pins:** `TestBindParamsJSONDefault` (bind_extra_test.go:148) **stays green** as the legacy/non-credential pin (F9; requirements §7 "Do not modify"); strict rejection (JSON/missing/unexpected CT → `errFormOnly`) lives in `bind_strict_test.go` case 16; R5.2's flip line superseded. `FuzzBindParams` corrected to **:34** (not :28) and **kept on the legacy binder** (panic-safety for the 44 non-credential sites + fallback mode) with a new `FuzzBindParamsFormOnly` (never panics, never binds for non-form CT); **both gain form-path `claims` seeds** (valid/malformed JSON-string) so the F11 RawMessage branch is fuzz-reachable (`fuzzBindTarget.Claims` at :22).

**T-8(b)/T-8(c) bearer verification:** `/device/verify` is credential-first — `authenticateDeviceVerifyBearer` (server_device.go:233) precedes the bind (:242). The strict-rejection rows now carry `Authorization: Bearer <valid access token>`, and §3.1's "before any credential logic" claim is scoped to the seven parse-first sites.

### Wired through the rest of the document
§1 verdict rows (both corrected), §2 new D1/D2 bullet + preamble drift note, F1 detection extended with the `grep 'core.ContentTypeJSON' protocols/oauth/` audit, §3.5 steps 1/2/4 rewritten, §3.6 case 16/17 + T-8(b)/T-8(c) rows, §4 gains the protocol-unit test line and the second sweep grep.

No `.go` files touched — no build gates triggered. Note: the document was concurrently evolved by sibling work (F17/F18 deprecation window, SDK step-6 options, scoped F1 audit); my edits merged cleanly with all of it (my earlier §3.2 device/verify note survived). Pre-existing `TestArchitecture_DirectoryDepth` failure on `docs/architect-analysis/auto/**` dirs remains unrelated and separate.
