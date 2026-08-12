# Requirements Spec: complete the negative-validation test matrix for `encryptionpassphrase.Open` (B4-4 verification half)

- Direction: entry 2 of `docs/architect-analysis/auto/analyses/interfaces-snapshot-encryptionpassphrase-61397dc0.json` (selected; test-only direction, "verification half of B4-4 hardening")
- Module: `interfaces/snapshot/encryptionpassphrase` (+ sibling `interfaces/snapshot/encryptionaesgcm` for wire-behavioral consistency)
- Status: requirements (evidence-verified against HEAD `b3c839bb`)

## 1. Evidence verification

Every citation in the direction was re-checked against the repository. Verdicts:

| Citation | Measured reality | Verdict |
|---|---|---|
| Validation code exists — `passphrase.go:136-144, 150-154` (version, salt length, zero-KDF, nonce length) | `Open` checks at actual lines: version `if p.Version != kdfVersion` (135–137, error "unsupported KDF version %d"), salt `if len(p.Salt) != saltLen` (139–140, "bad salt length %d"), zero-KDF `if p.KDF.Time == 0 \|\| p.KDF.Memory == 0 \|\| p.KDF.Threads == 0` (142–143, "zero KDF param"), nonce `if len(p.Nonce) != aead.NonceSize()` (153–154, "bad nonce length %d"). Constants: `kdfVersion = 1`, `saltLen = 16`; XChaCha20-Poly1305 nonce size is 24 (`chacha20poly1305.NonceSizeX`). Small line drift (analysis cites 136-144/150-154; actual 135–143/153–154) — same branches | Confirmed |
| `passphrase_test.go` covers only roundtrip, non-determinism, wrong passphrase, tampered cipher, empty passphrase, empty params — zero negative-branch coverage | File has exactly 6 tests: `TestSealOpenRoundtrip`, `TestSealNotDeterministic`, `TestOpen_WrongPassphrase`, `TestOpen_TamperedCipher`, `TestSeal_RejectsEmptyPassphrase`, `TestOpen_RejectsEmptyParams`. No test exercises `p.Version != kdfVersion`, `len(p.Salt) != saltLen`, zero-KDF, or `len(p.Nonce) != aead.NonceSize()` — those four branches are dead code from the test suite's perspective | Confirmed |
| `aesgcm.go:107-110` — sibling sealer, same untested branches | Actual lines: unmarshal (114–116), version (117, "unsupported version %d"), nonce length (127–129, "bad nonce length %d (want %d)"), AEAD open class (131–132). **Correction to the direction**: the version branch IS already covered — `TestSealer_PluggableInPipeline` (aesgcm_test.go:150–166) opens with `{"version":99,...}` and asserts failure + "version" in the error. The genuinely untested aesgcm branches are the nonce-length check and the oracle-stable AEAD error class | Partial — nonce-length and error-class branches untested; version branch already covered |
| B4-4 contract pattern in `docs/campaigns/implementation-gate.md` row 4 ("only add tests") | Row 4 (snaplink deploy tree, /token endpoint hardening) is the B4-4 row and lists T-8(b)(c)(e) as the verification checks; its pattern is "validation already exists — remaining work is tests/verification". Caveat: `docs/proposals/audit-contract-batch-snaplink.md:18` explicitly marks the exact per-letter semantics of T-8(b/c/e) as unverified annotations ("不冒充 Verified", [PROPOSED]) | Confirmed in substance; the T-8(b)/T-8(e) mapping is campaign attribution, not a verified contract — must not be treated as a gate |
| Baseline green | `go test ./interfaces/snapshot/encryptionpassphrase/ ./interfaces/snapshot/encryptionaesgcm/` → ok (passphrase 0.100s, aesgcm 0.003s) at HEAD | Confirmed |

Additional verified facts the tests must respect:

1. **Check ordering in `Open`** (passphrase.go:135–160): version → salt length → zero-KDF → argon2 derivation → nonce length → AEAD open. The nonce-length check runs *after* one full argon2 derivation, so every nonce-length row and every mutation-scan iteration costs one KDF. The mutation scan must therefore seal with a low-cost envelope (see R3) or CI time blows up (~70 ms/derivation at the 64 MiB default × ~200 positions ≈ 14 s).
2. **AEAD failure string is a constant**: `golang.org/x/crypto@v0.51.0` `chacha20poly1305.go:72` — `errOpen = errors.New("chacha20poly1305: message authentication failed")`. So wrong passphrase, tampered cipher, swapped salt, and swapped nonce all produce the *byte-identical* error `snapshot/passphrase: open: chacha20poly1305: message authentication failed`. The aesgcm sibling analog (`cipher: message authentication failed`) is likewise constant. This makes the oracle-stability assertion exact, not fuzzy.
3. **Envelope JSON shape** (`envelopeParams`): `{"version":uint32,"kdf":{"time":uint32,"memory_kib":uint32,"threads":uint8},"salt":"<base64>","nonce":"<base64>"}`. `[]byte` marshals to base64; salt (16 B) and nonce (24 B) decode back to fixed lengths regardless of which base64 char an attacker flips, so raw byte flips in params can change salt/nonce *values* but never their *lengths* — the length checks can only be exercised by crafted JSON (R1), while raw flips exercise the AEAD/unmarshal/version paths (R3).
4. **Test package is external** (`package passphrase_test`), so the tests cannot read unexported `kdfVersion`/`saltLen`; they must self-derive the fields from a sealed envelope (unmarshal → mutate → re-marshal), which also mirrors the real attacker model (tamper an existing envelope).
5. **Oversized params at HEAD**: oversized *version* (`math.MaxUint32` → "unsupported KDF version"), oversized *salt* (100 B → "bad salt length"), oversized *nonce* (100 B → "bad nonce length"), and an oversized raw blob (invalid JSON → "unmarshal params") are all rejected by existing checks. Oversized *memory/time* KDF values are NOT rejected at HEAD — that is direction 1's gap (restore-path resource exhaustion) and is explicitly out of scope here; no test may assert a memory/time cap.

## 2. Goal and user outcome

`Open`'s four validation branches (version, salt length, zero-KDF, nonce length) are the only defense between an attacker-controlled envelope and the argon2 KDF, and they currently have zero test coverage; the tampered-params path (attacker swaps salt/nonce/version inside otherwise-valid params JSON) and the oracle-stability of the AEAD error class are likewise unasserted. The direction is the verification half of B4-4 hardening: the validation code already exists and is correct at HEAD — what is missing is the regression lock.

Completion marker: any future edit that (a) drops, reorders, or loosens a validation check in `Open`, (b) changes the error class of AEAD failures (e.g., leaking "wrong passphrase" vs "tampered cipher"), or (c) diverges the aesgcm sibling's rejection/error-class behavior, fails a named test in `passphrase_test.go`/`aesgcm_test.go`. This is also the regression gate direction 1 (KDF caps) will stand on.

## 3. Product boundary

- Surface: tests only — `interfaces/snapshot/encryptionpassphrase/passphrase_test.go` (primary), `interfaces/snapshot/encryptionaesgcm/aesgcm_test.go` (sibling consistency). No production `.go` file is edited: `passphrase.go`, `aesgcm.go`, `pipeline.go`, and the wire formats stay byte-identical.
- Default: the new tests run unconditionally in the existing suite; they add no new dependencies (stdlib `encoding/json`, `math`, `testing` only).
- Explicit non-goals (do not implement):
  - No KDF cap (memory/time upper bounds) on Seal or Open, and no test asserting one — that is direction 1 of the same analysis (restore-path resource exhaustion); such a test would fail at HEAD.
  - No partial-zero-KDF Seal panic fix or test — also direction 1's secondary vector (`effectiveKDF`, passphrase.go:83).
  - No `Close`/`Destroy`/wipe lifecycle work — direction 3.
  - No pipeline, codec, storage, or `cmd/sso-ctl`/`cmd/sso-server` changes; no new `Err*` constants; no `docs/error-codes.md`, OpenAPI, config, or feature-matrix updates (the errors asserted are pre-existing and already shipped).
  - No change to the external `package passphrase_test` style, no new packages, no new production imports, no `t.Parallel` removal.
  - The T-8(b)/T-8(e) mapping is recorded as campaign attribution only ([PROPOSED] per the audit pack); no gate outside this module is claimed.

## 4. Module classification

- [x] Testing only (regression lock; no production behavior change)
- Owning layer/package: `interfaces/snapshot/encryptionpassphrase` (+ `encryptionaesgcm`). No import-graph change, no new package → no `layerName()` classification or exemption needed. File budgets: `passphrase_test.go` grows ~83 → ~300 lines, `aesgcm_test.go` ~168 → ~230 lines; both stay under the 500-line/file budget; test files are exempt from the 10-files/directory fan-out gate.

## 5. Requirements

### R1 — Table-driven negative matrix for `Open` (passphrase_test.go)

One sealed envelope is produced per test with `passphrase.NewFromString("k")`; each row derives its params by unmarshalling the sealed params JSON into a test-local struct, mutating one field, and re-marshalling (self-derivation — no access to unexported constants, mirrors the attacker-tamper model).

- **R1a — `TestOpen_RejectsUnsupportedVersion`**: versions `0`, `2`, `math.MaxUint32` (oversized) → error contains `"unsupported KDF version"` and the offending number.
- **R1b — `TestOpen_RejectsBadSaltLength`**: salt lengths `0`, `15`, `17`, `100` (oversized) → error contains `"bad salt length"`. Lengths derived by truncating/padding the sealed salt so the rest of the envelope is valid.
- **R1c — `TestOpen_RejectsZeroKDFParam`**: four rows — `Time:0` only, `Memory:0` only, `Threads:0` only, all three zero (other fields kept nonzero where the row targets one dimension) → error `"zero KDF param"`.
- **R1d — `TestOpen_RejectsBadNonceLength`**: nonce lengths `0`, `23`, `25`, `100` (oversized) → error contains `"bad nonce length"`. The nonce check runs post-KDF (passphrase.go:153), so this table seals with the low-cost envelope from R3's sealer to keep CI fast.
- **R1e — `TestOpen_RejectsOversizedParamsBlob`**: (1) a 1 MiB non-JSON blob → error contains `"unmarshal params"`; (2) valid JSON with a 1 MiB base64 salt → error contains `"bad salt length"`. Both reject pre-KDF.

### R2 — Tampered-params JSON and oracle-stable error class (passphrase_test.go)

- **R2a — `TestOpen_TamperedParams`** (attacker-swapped fields, valid JSON): (1) salt replaced with a different 16-byte value → Open fails; (2) nonce replaced with a different 24-byte value → Open fails; (3) version set to `0` → fails with `"unsupported KDF version"`; (4) version set to `2` → same. Rows (1)(2) must fail in the AEAD class (see R2b); rows (3)(4) in the version class.
- **R2b — `TestOpen_ErrorClassOracleStable`**: with the same low-cost envelope, collect the error strings for wrong passphrase, tampered cipher, swapped salt, swapped nonce; assert all four are byte-identical to `"snapshot/passphrase: open: chacha20poly1305: message authentication failed"` (verified constant, §1.2). This pins the oracle property: an attacker cannot distinguish "wrong passphrase" from "tampered envelope/cipher" from the error text.

### R3 — Single-byte mutation scan + roundtrip fuzz

- **R3a — `TestOpen_AnySingleByteMutationFails`** (deterministic, replaces a probabilistic random fuzz for the mutation property): seal with a low-cost sealer `&passphrase.Sealer{Passphrase: []byte("k"), KDF: passphrase.KDFParams{Time: 1, Memory: 1024, Threads: 1}}` (~1 ms/derivation); then for every byte index `i` of the params JSON and of the ciphertext, flip one bit (`b[i] ^= 0x01`) and assert `Open` fails. This covers "any single-byte mutation of params or cipher fails" exhaustively over positions, deterministically, in well under a second. Every path is covered: JSON-structure flips → `"unmarshal params"`, version-digit flips → `"unsupported KDF version"`, digit-to-zero flips → `"zero KDF param"`, base64-value flips → AEAD class, cipher flips → AEAD class. The only theoretical escape is an AEAD tag forgery (2^-128 for XChaCha20-Poly1305), the standard bound for all AEAD negative tests.
- **R3b — `FuzzSealOpenRoundtrip`**: native Go fuzz target, external test package; seed corpus: empty plaintext, `"the quick brown fox"`, binary bytes, 4 KiB random, and a large 64 KiB payload; property: `Seal` → `Open` returns the original plaintext, and `Seal` errors only when the passphrase is empty. Seeds run as a normal test in CI (go test without `-fuzz`); the low-cost sealer is used so the fuzzer spends its budget on structure, not argon2.

### R4 — aesgcm sibling consistency (aesgcm_test.go)

Direction scope ("keep the two sealers wire-behaviorally consistent"), trimmed to the branches the direction correctly flags as untested — the version branch is already covered by `TestSealer_PluggableInPipeline`:

- **R4a — `TestSealer_OpenRejectsBadNonceLength`**: nonce lengths `0`, `11`, `13`, `100` → error contains `"bad nonce length"` (AES-GCM nonce size is 12).
- **R4b — `TestSealer_OpenErrorClassOracleStable`**: wrong key, tampered cipher, swapped nonce → all byte-identical `"snapshot/aesgcm: open: cipher: message authentication failed"` (asserted against the string constant, mirroring R2b's formulation for passphrase).

## 6. Acceptance criteria (direction's checks, made testable)

| Direction's acceptance | Testable form |
|---|---|
| Version 0/2 rejected | R1a — `Open` with `version` 0, 2 (and `math.MaxUint32`) returns `snapshot/passphrase: unsupported KDF version N` |
| Salt len 15/17 rejected | R1b — salt lengths 0/15/17/100 → `snapshot/passphrase: bad salt length N` |
| Zero Time/Memory/Threads rejected | R1c — each dimension zero individually and all-zero → `snapshot/passphrase: zero KDF param` |
| Nonce len 23/25 rejected | R1d — nonce lengths 0/23/25/100 → `snapshot/passphrase: bad nonce length N` |
| Tampered params JSON (bit-flipped salt or version) fails Open; error text oracle-stable (`snapshot/passphrase: open:` class) | R2a/R2b — swapped salt/nonce fail in the AEAD class; swapped version fails in the version class; wrong-passphrase/tampered-cipher/swapped-salt/swapped-nonce errors are byte-identical, so an attacker learns nothing from the error text |
| Oversized params | R1a (version MaxUint32), R1b (salt 100), R1d (nonce 100), R1e (1 MiB blob / 1 MiB salt) — all fail fast, pre-KDF or with the low-cost envelope |
| Fuzz: Seal→Open roundtrip; any single-byte mutation of params or cipher fails | R3a (deterministic per-position bit-flip scan over params and cipher, all positions fail) + R3b (native fuzz roundtrip property with seeds run in CI) |
| Sibling consistency (aesgcm.go:107-110 class branches) | R4a/R4b — nonce-length and error-class branches, trimmed by the verified correction that the version branch is already covered |
| Maps to T-8(b)/T-8(e) hardening verification | Recorded as campaign attribution only — exact per-letter semantics are marked [PROPOSED] in `docs/proposals/audit-contract-batch-snaplink.md:18`; no gate depends on it |

## 7. Verification plan

Test-only change, so the standard gates apply with no exemption expectations:

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./interfaces/snapshot/encryptionpassphrase/ ./interfaces/snapshot/encryptionaesgcm/ -run 'TestOpen_|TestSealer_|TestSeal|Fuzz' -v
go test ./... -race
make ci
```

`make ci` is the handoff gate. The negative matrix must be green against HEAD *before* any future direction-1 KDF-cap change, so it lands as a pure regression lock.

## 8. Risks and notes

- **KDF cost**: every nonce-length row and every mutation-scan iteration runs one argon2 derivation (the nonce check is post-KDF). R3's low-cost sealer and R1d's use of the same envelope keep the suite well under 1 s; the version/salt/zero-KDF/blob rows reject pre-KDF and cost nothing.
- **Probabilistic bound**: R3a asserts failure for ~200 deterministic single-bit mutations; the escape probability is the XChaCha20-Poly1305 tag-forgery bound (2^-128), the same assumption every AEAD negative test in the tree makes.
- **Line drift**: the analysis's citations (passphrase.go:136-144/150-154, aesgcm.go:107-110) are 1–7 lines off HEAD; the branches themselves are confirmed present (verified locations in §1). No re-analysis needed.
- **One direction correction is folded in**: the aesgcm version-rejection branch is already covered by `TestSealer_PluggableInPipeline` (aesgcm_test.go:150–166), so R4 does not duplicate it.
