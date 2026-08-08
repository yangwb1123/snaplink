All verified. Line 83 is the terminating blank line after the table (GFM-correct); the three edited rows each have 4 pipes (5 columns) — well-formed.

## Summary

Resolved the primary gap (legacy fallback window semantics) plus the three accompanying items in `docs/architect-analysis/cmd-snaplink-audit-provisioner-b4-4-credential-form-only-design.md` (untracked deliverable; all citations re-verified against the tree):

**1. Deprecation convention (hosted_login pattern) — §3.1, §3.3, F17, step 9**
- `validate()` emits `slog.Warn` when `server.require_form_content_type` is explicitly `false` (code block added beside the `ServerOptions()` wiring, mirroring `config_load.go:152-156`); `WithCredentialFormOnly(false)` warns at option construction for embedders (options.go gains `log/slog`).
- **Removal trigger**: key + option + flag dispatch removed with the next schema-version bump (`CurrentSchemaVersion = 1`, `config.go:216`) — same convention bounding `hosted_login`/`feature_gates.web_spa` (config-reference.md:765). Made concrete as new **step 9** of the migration (the reviewer's "no removal step" finding), explicitly not part of this change set.
- **Terminal semantics documented now**: stale configs carrying the key after deletion hit `decodeStrictWithFallback` (source.go:263-277) — warn → ignored → nil → strict default. Fail-closed, no silent legacy resurrection; config-reference entry pins it (step 7).

**2. Wire-invisible window gauge — §3.1, §3.2, F18, §3.6**
- `BindParamsFormOnly` emits an Info-level log immediately before the `errFormOnly` return; sole attribute is the normalized class (`json`/`missing`/`other`, bounded cardinality); never body/raw header/credentials, never an audit event, never response-visible. New F18 failure mode pins the oracle-safety boundary; new test `TestBindParamsFormOnly_RejectionLogsInfo` in step 1 + acceptance table.

**3. CHANGELOG entries pinned — step 7**
- Both client-visible deltas named: (a) missing-Content-Type requests (today defaulted to JSON per bind.go:24-25/43-45) now 400 on all eight credential endpoints; (b) the 401→400 precedence change at `/token` and `/token/introspect` for unauthenticated JSON/missing-CT requests (bind precedes the client-auth gate, T-9).

**4. F1 sweep grep scoped to credential paths — §3.4 F1, §4**
- Audit command now filters to the eight credential paths. **Validated live**: returns exactly 40 lines across 16 files — all in the design's step-4 sweep inventory; the 77 non-credential JSON post lines (login/admin/commerce/selfservice) are untouched and stay JSON. `Header.Set`-style calls noted as covered by the named-file inventory (line-scoped heuristic caveat).

New test rows added for the warn sites (`TestConfigValidate_LegacyFormOnlyWarns`, `TestWithCredentialFormOnlyFalseWarns`); case-15 deprecation rows and the config verification line extended.

Note: the file was concurrently extended by a sibling batch task (the C1 governance pin and step-6 gensdk encoding detail from the other reviewer findings) — edits landed in disjoint regions with no conflicts; final state is 453 lines, tables well-formed.

Documentation-only change — no `.go` edits, so no build gates apply.
