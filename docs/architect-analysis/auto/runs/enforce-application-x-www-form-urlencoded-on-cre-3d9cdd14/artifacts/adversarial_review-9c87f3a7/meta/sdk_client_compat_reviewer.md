Done. The gensdk sequencing gap is resolved in `docs/architect-analysis/cmd-snaplink-audit-provisioner-b4-4-credential-form-only-design.md` (campaign deliverable, untracked like the gensdk sibling). Six edits, all grounded in re-verified tree facts:

## 1. Step 6 — hard-dependency made explicit (§3.5, rewritten)

Verified current state first: gensdk form emission has **not** landed — `gen_ts_runtime.go:158-160` and `gen_py.go:102-104` are JSON-only body branches, and both committed clients contain **zero** `x-www-form-urlencoded` occurrences. Step 6 now executes exactly one of:

- **(a) Hard-depend (preferred)**: gensdk module lands first → step 6 is verify-only regeneration, with the explicit rule "**Form-only enforcement must not ship while committed clients still emit JSON**".
- **(b) Implement in this change set**: carries the gensdk §3.3/§3.4 encoding rules **verbatim** — `authorization_details`/`claims` as a single JSON-string element per RFC 9396 §7.1.1 (`params.append(k, JSON.stringify(v))` / `form_data[k] = json.dumps(v)`, exactly one element, never `String(v)`/repr — the `[object Object]` guard); string arrays → repeated keys (`doseq=True`); TS `undefined`/`null` skip; Python `None` filter; plus `client.test.mjs` **#2** (form-body + no-credentials pin) and **#4** (single JSON-string elements, `getAll(...).length === 1`), and the gensdk §3.6 emit-test pins.

## 2. F11 ↔ client-emission parity verified (§3.4 row + §3.5 step 6 + §3.1)

- The shared-decoder RawMessage branch and step-6 emission are now pinned as a byte-exact pair: `JSON.stringify`/`json.dumps` output is always `json.Valid` text → the branch's verbatim store + downstream unmarshal can't diverge; `client.test.mjs` #4 ↔ T-9(g) round-trip asserts the pair.
- **Second line of defense stated**: a regressed encoder emitting a non-JSON literal (`[object Object]`) fails the branch's `json.Valid` gate with the site's 400 — fail-loud, never a silent wrong-grant — so F-A is impossible while step 6 honors the verbatim rules.
- **governance.go:35 named** (previously unnamed consumer): `proposeChangeRequest.Payload json.RawMessage` (bound via dual-mode `oauth.BindParams` at governance.go:61, NOT in the flip surface) today silently drops a form `payload`; after the branch it binds. Since the change is in the shared decoder it can't be scoped to PAR — now documented as such with a new pin test `TestAdminChanges_FormPayloadBinds` (binds valid, 400 on malformed, JSON path unchanged), also referenced from step 1's unit-test scope.

## 3. sdk-surface gate stated documentary-only (§3.3 bullet + §4 caveat)

Verified `ops/scripts/sdk_surface.py` `validate_registry` reconciles registry membership against openapi.yaml/capabilities.json only — never media types, never emitted output — and no other `make ci` target does either. The design now states explicitly, twice, that **nothing in `make ci` mechanically prevents the flip while committed clients still emit JSON**, and names the real gates: step 6's hard dependency (or verbatim rules), the gensdk emit-test pins, and the T-9(c) committed-diff review.

Markdown tables verified unbroken (no stray `|` in code spans); this is a docs-only edit, so no Go gates apply.
