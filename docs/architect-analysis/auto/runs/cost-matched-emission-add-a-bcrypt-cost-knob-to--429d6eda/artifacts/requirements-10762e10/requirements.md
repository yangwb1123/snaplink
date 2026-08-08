Requirements spec produced at `docs/architect-analysis/auto/runs/cost-matched-emission-add-a-bcrypt-cost-knob-to--429d6eda/artifacts/requirements-10762e10/requirements.md`.

## Evidence verification (all 10 citations re-checked against HEAD)

Every cited file/symbol confirmed, with minor line drift reported in the spec's evidence table:

- **hashcmd/main.go:33–35** — only `-password`/`-quiet` flags; `rg '"cost"' cmd/sso-ctl/` → 0 hits. `HashPassword` call is at **line 51**, not 56 (drift 5).
- **password_hash.go:94–100** — `HashPassword` → `bcrypt.GenerateFromPassword(..., bcrypt.DefaultCost)` at line 95. Exact.
- **stored_hash_verifier.go:25** — `DefaultStoredHashDummyCost = 12`; cost resolution at 100–108 (pin wins, hasher only when unpinned, range fallback). Exact.
- **build_authenticators_helpers.go:86–91** — `WithHasher(NewBcryptHasher(bcrypt.DefaultCost))` wired only when `ImportedHashDummyCost <= 0` (lines 90–92); pin at 82–84. Confirms the "effective dummy is 10, not 12, in the default wiring" claim.
- **build_audit_secrets.go:222–245** — `BuildBcryptPasswordVerifier` first-seed dummy at 238–242 (`if seeded == 0`), no error channel. Confirmed.
- **importer.go:115–118** — `password_hash`/`password_hash_format` attribute seam. Confirmed; reported (not fixed) drift: literal keys vs. the `AttrPasswordHash` constants.
- **Drift found:** `docs/config-reference.md` has no rows for `imported_hash_login`/`imported_hash_dummy_cost` — reported, out of scope (no config keys added).
- **Stability check:** bcrypt corpora are never lazy-rehashed (`NeedsRehash` non-bcrypt-only, stored_hash_verifier.go:149), so the `--cost N` + pin-N pairing is stable across first logins — no scope expansion needed.

## Requirements (acceptance preserved, made testable)

- **R1** — `--cost` flag (4–31, default 10, absent ⇒ T-9 byte-identical, out-of-range ⇒ exit 2 before hashing), emitting via a new `authenticators.HashPasswordAtCost` domain seam.
- **R2** — testability seams: `StoredHashVerifier.DummyCost()` accessor + extracted `resolveSeedDummyCost` in serverbuildauthn (dummy cost is otherwise unobservable).
- **R3** — mixed-cost YAML corpus **fails boot** (chose acceptance option 1 over error-log: logging alone leaves the N2 timing distinguisher live; `--cost` makes the failure actionable), via `BuildBcryptPasswordVerifier` gaining an `error` return.
- **R4** — nine conformance tests mapping the three wiring modes; cross-module conformance via transitivity on cost N since `cmd/`→`cmd/` imports are forbidden.
- Explicit non-goals: no `--format`, no stdin/argv-secrecy changes (other directions in the same analysis), no dummy-cost constant changes, no timing/benchmark tests.
