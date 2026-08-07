The requirements specification is complete and verified. Summary of what was produced and what the verification found:

**Artifact**: `docs/architect-analysis/snapshot-encryptionpassphrase-negative-validation-requirements.md`

**Evidence verification results** (all citations re-checked against HEAD):

- **Confirmed**: `passphrase.go` `Open` contains all four validation branches — version (135–137), salt length (139–140), zero-KDF (142–143), nonce length (153–154) — with small line drift from the analysis's cited 136-144/150-154. `passphrase_test.go` has exactly 6 tests, zero negative-branch coverage.
- **Two corrections folded into the spec**:
  1. The aesgcm sibling's version branch is *already* covered by `TestSealer_PluggableInPipeline` (version 99, aesgcm_test.go:150–166) — the genuinely untested sibling branches are nonce length and the oracle-stable error class. R4 is trimmed accordingly.
  2. The T-8(b)/T-8(e) mapping is campaign attribution only — `audit-contract-batch-snaplink.md:18` explicitly marks the per-letter semantics as unverified ([PROPOSED]). Recorded as attribution, not a gate.
- **New verified facts that shape the tests**: the nonce-length check runs *post-KDF* (so nonce rows and the mutation scan need a low-cost envelope, ~1 ms vs ~70 ms per derivation); the AEAD failure string is a constant (`chacha20poly1305.go:72`), making the oracle-stability assertion *byte-identical* across wrong-passphrase/tampered-cipher/swapped-salt/swapped-nonce; oversized memory/time KDF values are NOT rejected at HEAD (direction 1's gap), so no test may assert a cap — oversized coverage is restricted to version/salt/nonce/blob, which the existing checks do reject.

**Requirements** (R1–R4, all test-only): table-driven negative matrix (version 0/2/MaxUint32, salt 0/15/17/100, each zero-KDF dimension, nonce 0/23/25/100, oversized blobs), attacker-swapped params + byte-identical oracle-stable error class, deterministic per-position single-byte mutation scan + `FuzzSealOpenRoundtrip` with CI-run seeds, and the trimmed aesgcm sibling consistency tests. Every direction acceptance bullet is mapped to a named testable assertion; non-goals exclude the KDF-cap and Close/wipe directions. Budgets are respected (no production files touched, no new packages, test files stay under 500 lines).
