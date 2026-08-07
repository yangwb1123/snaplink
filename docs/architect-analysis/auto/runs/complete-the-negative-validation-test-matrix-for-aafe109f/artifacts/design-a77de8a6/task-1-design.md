Design complete. Both copies written:
- `docs/architect-analysis/snapshot-encryptionpassphrase-negative-validation-design.md`
- `docs/architect-analysis/auto/runs/complete-the-negative-validation-test-matrix-for-aafe109f/artifacts/design.md`

## Verification verdict (all evidence claims re-checked at HEAD `dbccd8bc`)

**Confirmed as claimed:**
- `Open`'s four validation branches at passphrase.go:137 (version), 140 (salt), 143 (zero-KDF), 154 (nonce); nonce check is post-KDF (argon2 at 146)
- Exactly 6 tests in `passphrase_test.go`, zero negative-branch coverage; aesgcm version branch already covered by `TestSealer_PluggableInPipeline` (version 99), leaving only nonce-length + error-class untested
- `chacha20poly1305.go:72` in the pinned x/crypto v0.51.0 — the spec's line-72 citation is exact; aesgcm analog `cipher: message authentication failed` (stdlib gcm.go:273)
- No KDF memory/time cap at HEAD; baseline suite green; `math.MaxUint32` usable

**Design decisions beyond the spec (D1–D9):** one low-cost envelope (~0.61 ms/derivation, measured) for *all* tables, not just R1d/R3; mirror structs whose JSON-tag drift is self-detecting; exact-string oracle pinning with the library-string sensitivity made a deliberate tripwire; scan mechanics with collected violation reporting; fuzz property honestly narrowed to Seal-no-error + roundtrip (passphrase is fixed non-empty, so the empty-passphrase branch stays with the existing unit test); R3a scan measured at ~154 positions × 0.6 ms ≈ 0.1 s.

**Deliverable sections:** API changes (none — test-only, wire formats byte-identical), compatibility constraints (must pass at HEAD, no KDF-cap assertions, stdlib-only, fuzz seeds run under plain `go test`, both test files stay < 500 lines), 10 enumerated failure modes (FM-1…FM-10, including the wire-bump re-pin tripwire and mirror-drift detection), ordered 7-step migration, and a 10-row acceptance table mapping every direction bullet to a named test with concrete assertion strings.
