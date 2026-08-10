# Design: negative-validation test matrix for `encryptionpassphrase.Open` (B4-4 verification half)

Companion to `docs/architect-analysis/snapshot-encryptionpassphrase-negative-validation-requirements.md`.
This document treats that spec as untrusted evidence, records what was independently
verified against HEAD (`dbccd8bc`), folds in the corrections the verification surfaced,
and turns R1–R4 into a concrete, ordered design with API changes, compatibility
constraints, failure modes, migration steps, and testable acceptance mapping.

## 1. Evidence verification verdict

Every citation in the requirements spec was re-checked against the tree at HEAD.

| # | Claim | Verdict |
|---|---|---|
| E1 | `Open` has four validation branches: version, salt length, zero-KDF, nonce length | Confirmed. `passphrase.go` (175 lines): `p.Version != kdfVersion` at 137 ("unsupported KDF version %d"), `len(p.Salt) != saltLen` at 140 ("bad salt length %d"), zero-KDF disjunction at 143 ("zero KDF param"), `len(p.Nonce) != aead.NonceSize()` at 154 ("bad nonce length %d"). `kdfVersion = 1` (line 32), `saltLen = 16` (line 30). Spec-cited lines 135–143/153–154 match HEAD exactly. |
| E2 | Nonce-length check runs *after* the argon2 derivation | Confirmed: `argon2.IDKey` at 146, nonce check at 154. Every nonce-length row and every mutation-scan position costs one full KDF unless a low-cost envelope is used. |
| E3 | `passphrase_test.go` has exactly 6 tests, zero negative-branch coverage | Confirmed by full read: `TestSealOpenRoundtrip`, `TestSealNotDeterministic`, `TestOpen_WrongPassphrase`, `TestOpen_TamperedCipher`, `TestSeal_RejectsEmptyPassphrase`, `TestOpen_RejectsEmptyParams` (83 lines). None touches the version/salt/zero-KDF/nonce branches; `TestOpen_WrongPassphrase`/`TestOpen_TamperedCipher` assert `err == nil`-only, never the error class. |
| E4 | aesgcm sibling: version branch already covered; nonce-length and error-class branches untested | Confirmed. `TestSealer_PluggableInPipeline` (aesgcm_test.go:151–166) opens `{"version":99,"nonce":"AAAA"}` and asserts failure + `"version"` in the error. `aesgcm.go` nonce check at 127–128 ("bad nonce length %d (want %d)"), AEAD wrap at 131–132. Existing `TestSealer_OpenWrongKeyFails`/`TestSealer_OpenTamperedCipherFails` assert only `err != nil` — R4b genuinely adds the class assertion. |
| E5 | AEAD failure strings are library constants, byte-identical across causes | Confirmed. Root `go.mod` pins `golang.org/x/crypto v0.51.0`; `chacha20poly1305.go:72` in that exact version: `var errOpen = errors.New("chacha20poly1305: message authentication failed")` — the spec's line-72 citation is exact. aesgcm analog: stdlib `crypto/cipher` `errOpen = errors.New("cipher: message authentication failed")` (gcm.go:273 on this toolchain). Both are wrapped verbatim (`snapshot/passphrase: open: %w`, `snapshot/aesgcm: open: %w`), so the full strings are byte-identical for every AEAD-class cause. |
| E6 | Oversized version/salt/nonce/blob rejected; oversized memory/time KDF values NOT rejected | Confirmed. `Open` bounds memory/time/threads only against zero (line 143); a `"memory_kib": 4294967295` envelope derives and fails only at AEAD. No test may assert a KDF cap — it would fail at HEAD. |
| E7 | Envelope JSON shape: `{"version":uint32,"kdf":{"time":uint32,"memory_kib":uint32,"threads":uint8},"salt":"<b64>","nonce":"<b64>"}`; `[]byte` marshals to base64 | Confirmed by reading `envelopeParams`/`KDFParams` (passphrase.go:51–68). Length checks are reachable only via crafted JSON (raw byte flips in params change base64 *values*, never decoded *lengths* — except via invalid-base64 unmarshal errors, which are still failures). |
| E8 | External test package (`package passphrase_test`), baseline green | Confirmed: `package passphrase_test`; `go test ./interfaces/snapshot/encryptionpassphrase/ ./interfaces/snapshot/encryptionaesgcm/` → ok at HEAD. |
| E9 | T-8(b)/T-8(e) mapping is campaign attribution only | Accepted as recorded: `docs/proposals/audit-contract-batch-snaplink.md:18` marks per-letter semantics unverified ([PROPOSED]). No gate depends on it. |
| E10 | Budgets | Confirmed: no production files touched; test files start at 83 (passphrase) / 168 (aesgcm) lines, both far under the 500-line/file gate; no new packages; `interfaces/snapshot` fan-out untouched. |

No material defect was found in the requirements spec. Five refinements (D1–D5)
and three failure-mode additions (FM-6–FM-8) below sharpen it for implementation.

## 2. Design decisions (refinements to the spec)

- **D1 — One low-cost envelope for every table.** The spec's R1 preamble says tables
  seal with `passphrase.NewFromString("k")` (64 MiB, ~70 ms) while R1d/R3 carve out a
  low-cost sealer. Validation outcomes are KDF-cost-independent (the four checks are
  arithmetic on the parsed envelope; the KDF only feeds the AEAD stage), so the design
  uses the low-cost sealer
  `&passphrase.Sealer{Passphrase: []byte("k"), KDF: passphrase.KDFParams{Time: 1, Memory: 1024, Threads: 1}}`
  for *all* tables. One shared `lowCostSealer()` helper; the version/salt/zero-KDF/blob
  rows reject pre-KDF anyway, and the AEAD rows get ~1 ms derivations. Whole suite stays
  well under 1 s. `Memory: 1024` is 1 MiB, above argon2's floor, so derivation is valid.
- **D2 — Mirror struct with self-detecting drift.** Tests cannot read unexported
  `kdfVersion`/`saltLen`/`envelopeParams`. Each test file defines a local mirror struct
  with the production JSON tags (`version`/`kdf`/`salt`/`nonce`; `time`/`memory_kib`/`threads`;
  aesgcm: `version`/`nonce`). If the mirror's tags ever drift from production, rows stop
  mutating the field the production code reads and the row *succeeds*, failing the
  assertion loudly — drift is self-detecting by construction, and the comment on the
  mirror says so. Row derivation = unmarshal sealed params → mutate field → re-marshal,
  which is exactly the attacker-tamper model (E7) and always yields valid base64.
- **D3 — Exact-string oracle pinning, with the sensitivity made deliberate.** R2b/R4b
  assert `err.Error()` equality against the full literal strings
  `"snapshot/passphrase: open: chacha20poly1305: message authentication failed"` and
  `"snapshot/aesgcm: open: cipher: message authentication failed"` (E5). This pins the
  oracle property exactly and is the regression lock against future "leak the cause"
  edits. Tradeoff, documented in a comment: if x/crypto or the stdlib ever rewrites its
  AEAD error string, both rows fail together and force a review — the desired tripwire,
  since the byte-identity of the class is the property under test. `errors.Is` is
  unusable here (constants are unexported in external packages), so string equality is
  the mechanism.
- **D4 — R3a scan mechanics.** One test, two loops (params positions, then cipher
  positions) over copies of the sealed envelope; per position flip `b[i] ^= 0x01`; assert
  `Open` fails. Violating positions are collected and reported in a single `t.Errorf`
  listing them (not one error per position), so a regression shows exactly which byte
  positions the code stopped rejecting. No error-class assertion per position — class is
  R2b's job; the scan asserts only rejection (plus no panic). Positions ≈ 154 (137-byte
  params JSON + 17-byte ciphertext for a 1-byte plaintext, measured) × ~0.6 ms ≈ 0.1 s.
- **D5 — R3b fuzz property, honestly narrowed.** The fuzz input is the plaintext; the
  passphrase is fixed non-empty inside the target, so "Seal errors only when the
  passphrase is empty" is not enforceable there (that branch is already pinned by the
  existing `TestSeal_RejectsEmptyPassphrase`). The fuzz target asserts: `Seal` never
  errors and `Open` round-trips to the original plaintext. Seeds (empty, `"the quick
  brown fox"`, binary bytes, 4 KiB, 64 KiB) run in CI as ordinary tests; the low-cost
  sealer keeps each iteration fast. Fuzz targets cannot use `t.Parallel` — noted, since
  every other test in the file is parallel.
- **D6 — aesgcm R4 mirrors are KDF-free.** The aesgcm nonce check (aesgcm.go:127–128)
  is post-cipher-init but pre-AEAD, with no KDF, so R4a/R4b seal with the default
  `aesgcm.New(mkKey(t))` — no low-cost concern.
- **D7 — R1a version rows.** `0`, `2`, `uint32(math.MaxUint32)`; `math.MaxUint32` is an
  untyped constant in stdlib `math` (verified compiles). Rows self-derive the *current*
  version from the sealed envelope, so a legitimate future `kdfVersion` bump to 2 makes
  row `2` valid and the test fails — the matrix re-pin is a deliberate, loud step of any
  wire-format change.
- **D8 — R1e oversized blob rows.** (1) 1 MiB of `0x41` (valid base64 alphabet but not
  JSON) → `"unmarshal params"`; (2) valid JSON carrying a 1 MiB base64 salt → decodes to
  ~768 KiB salt → `"bad salt length"`. Both reject pre-KDF; `bytes.Repeat` keeps them
  one-liners. `memory_kib`/`time` oversized rows are deliberately absent (E6).
- **D9 — Test naming.** Follow the existing file conventions: `TestOpen_*` in
  passphrase_test.go (matching `TestOpen_WrongPassphrase`), `TestSealer_*` in
  aesgcm_test.go (matching `TestSealer_OpenWrongKeyFails`), plus `FuzzSealOpenRoundtrip`.
  Table-driven rows via subtests; `t.Parallel()` kept on all non-fuzz tests.

## 3. Concrete design

### 3.1 File layout

- `interfaces/snapshot/encryptionpassphrase/passphrase_test.go` (83 → ~310 lines):
  helpers `lowCostSealer()`, `sealWith(t, s)`, mirror structs `testEnv`/`testKDF`
  (D2), plus R1–R3 tests and the fuzz target.
- `interfaces/snapshot/encryptionaesgcm/aesgcm_test.go` (168 → ~235 lines): mirror
  `testEnv{Version uint32; Nonce []byte}` + R4 tests.
- No production `.go` file is edited. No new packages. No new dependencies (stdlib
  `bytes`, `encoding/json`, `math`, `testing` only).

### 3.2 R1 — `TestOpen_Rejects*` table-driven negative matrix

Shared pattern per row: `cipher, params := sealWith(t, lowCostSealer())`; unmarshal into
`testEnv`; mutate exactly one field; re-marshal; `_, err := s.Open(cipher, mutated)`.

| Test | Rows | Expected substring |
|---|---|---|
| `TestOpen_RejectsUnsupportedVersion` | version `0`, `2`, `math.MaxUint32` | `"unsupported KDF version"` + the number |
| `TestOpen_RejectsBadSaltLength` | salt `0` (`[]byte{}`), `15` (`salt[:15]`), `17` (`append(salt, 0)`), `100` (`append(salt, make([]byte,84)...)`) | `"bad salt length"` + the length |
| `TestOpen_RejectsZeroKDFParam` | `Time:0` only; `Memory:0` only; `Threads:0` only; all three `0` | `"zero KDF param"` |
| `TestOpen_RejectsBadNonceLength` | nonce `0`, `23`, `25`, `100` (truncate/pad as for salt) | `"bad nonce length"` + the length |
| `TestOpen_RejectsOversizedParamsBlob` | 1 MiB non-JSON blob; valid JSON with 1 MiB base64 salt | `"unmarshal params"`; `"bad salt length"` |

All rows are self-derived from a sealed envelope (D2), so they cannot go stale on
`kdfVersion`/`saltLen`/nonce-size drift — they fail loudly instead (D7).

### 3.3 R2 — tampered-params JSON + oracle-stable error class

- `TestOpen_TamperedParams` — via the mirror struct (valid base64 guaranteed): (1) salt
  replaced with a different 16-byte value → fails with the AEAD-class string; (2) nonce
  replaced with a different 24-byte value → same class; (3) version `0` → version-class
  string; (4) version `2` → version-class string. Class asserted per row via substring,
  so a regression that leaks "wrong passphrase" vs "tampered cipher" fails here and in
  R2b.
- `TestOpen_ErrorClassOracleStable` — four rows: wrong passphrase (`NewFromString("wrong")`),
  tampered cipher (`cipher[0] ^= 0xFF`), swapped salt (R2a row 1), swapped nonce (R2a row
  2). Assert each `err.Error()` equals the exact literal
  `"snapshot/passphrase: open: chacha20poly1305: message authentication failed"` (D3).
  An attacker learns nothing from the error text; the version/salt/nonce classes are
  structural validation, not key-oracles, and are deliberately *not* part of this
  byte-identity set.

### 3.4 R3 — mutation scan + fuzz

- `TestOpen_AnySingleByteMutationFails` — seal `[]byte("x")` with the low-cost sealer;
  loop `i` over every byte of the params JSON and of the ciphertext (on copies, so
  mutations never accumulate); flip `b[i] ^= 0x01`; assert `Open` fails (D4). Covers
  JSON-structure flips → `"unmarshal params"`, version-digit flips → version class,
  digit-to-zero flips → zero-KDF class, base64-value flips → AEAD class, cipher flips →
  AEAD class. The only theoretical escape is an XChaCha20-Poly1305 tag forgery
  (2^-128), the standard bound every AEAD negative test in the tree assumes.
- `FuzzSealOpenRoundtrip` — `f.Add` seeds: `[]byte{}`, `[]byte("the quick brown fox")`,
  `[]byte{0x00, 0x01, 0x02, 0xFF}`, 4 KiB deterministic pattern, 64 KiB payload. Body:
  `cipher, params, err := s.Seal(in)`; assert `err == nil`; `got, err := s.Open(...)`;
  assert roundtrip equality (D5). Seeds execute in CI under plain `go test`; no
  `-fuzz` requirement. No `t.Parallel` (D5).

### 3.5 R4 — aesgcm sibling consistency

- `TestSealer_OpenRejectsBadNonceLength` — nonce `0`, `11`, `13`, `100` via the aesgcm
  mirror → error contains `"bad nonce length"` (AES-GCM nonce size is 12; production
  error also carries the want-length, asserted too). Cheap: no KDF (D6).
- `TestSealer_OpenErrorClassOracleStable` — wrong key, tampered cipher, swapped nonce
  (12 bytes, via mirror) → all equal the exact literal
  `"snapshot/aesgcm: open: cipher: message authentication failed"` (D3). The version
  branch is *not* duplicated — `TestSealer_PluggableInPipeline` already covers it (E4).

## 4. API changes

None. This is a test-only change:

- No exported or unexported production symbol changes in `passphrase.go`, `aesgcm.go`,
  or `pipeline.go`; the `snapshot.Sealer` interface and `SealedEnvelope` wire format
  stay byte-identical.
- No new `Err*` constants, no `docs/error-codes.md`/OpenAPI/config/feature-matrix
  updates (every asserted error string is pre-existing and shipped).
- Test surface only: 9 new named tests + 1 fuzz target in `passphrase_test.go`,
  2 new named tests in `aesgcm_test.go`.

## 5. Compatibility constraints

1. Tests must pass at HEAD with zero production changes — this is the definition of a
   regression lock; if any new test fails at HEAD, the design is wrong and must be
   corrected before proceeding (none should: all assertions match verified HEAD
   behavior, E1–E8).
2. No test may assert a memory/time KDF cap or any behavior not present at HEAD (E6) —
   that is direction 1 of the analysis and a separate change.
3. External `package passphrase_test` / `package aesgcm_test` style preserved; no new
   packages; stdlib-only imports; `t.Parallel` retained everywhere except the fuzz
   target.
4. Fuzz seeds must run under plain `go test` (CI has no `-fuzz`); the fuzz target must
   be fast enough to also run under `-race` without blowing the suite budget (~1 ms
   derivations, D1).
5. File budgets: `passphrase_test.go` ~310 lines, `aesgcm_test.go` ~235 — both under
   the 500-line/file gate; test files are exempt from the 10-files/directory fan-out
   gate; `interfaces/snapshot` stays at its file count (no new files).
6. The byte-identity assertions (D3) are intentionally sensitive to x/crypto/stdlib
   error-string rewrites: the sensitivity is the property under test, not a flake
   source, and is documented in a comment on each assertion.

## 6. Failure modes

| # | Failure mode | Detection | Mitigation |
|---|---|---|---|
| FM-1 | Future edit drops/reorders/loosens a check in `Open` (e.g., removes salt-length check) | R1b row for that field stops failing | R1 matrix is the regression lock; fix must restore the check |
| FM-2 | Future edit leaks the AEAD cause ("wrong passphrase" vs "tampered ciphertext") | R2b/R4b exact-string equality breaks | Byte-identity assertion; any split of the class fails loudly |
| FM-3 | aesgcm sibling diverges (nonce check removed, error class changed) | R4a/R4b fail | Sibling consistency lock |
| FM-4 | `kdfVersion`/`saltLen`/nonce-size wire bump without updating the matrix | R1a row `2` (or R1b/R1d rows) fails — the "valid" row becomes the rejected one | Intentional: wire-format changes must re-pin the matrix (D7); the failing test names the row to update |
| FM-5 | x/crypto or stdlib rewrites the AEAD error string | R2b/R4b fail at exactly one literal | Deliberate tripwire (D3); both cause-rows fail together, confirming the class is still unified; update both literals in one review |
| FM-6 | Mirror-struct JSON tag drift | Mutated rows stop affecting production behavior → row succeeds → assertion fails | Self-detecting by construction (D2); comment on the mirror explains |
| FM-7 | Test-suite time blow-up from 64 MiB KDFs in nonce rows / scan positions | CI wall-clock regression | D1: single low-cost envelope everywhere (~1 ms/derivation, ~0.2 s scan) |
| FM-8 | R3a false negative (a mutated position opens successfully) | Test reports the violating byte positions in one `t.Errorf` | Theoretical only via AEAD tag forgery (2^-128); identical to the assumption of every AEAD negative test in the tree |
| FM-9 | Non-determinism (fresh salt/nonce per seal) breaking row derivation | — | Rows derive from their own sealed envelope; no hard-coded salt/nonce bytes anywhere |
| FM-10 | Race detector noise from parallel tests sharing state | `go test -race` | Every test seals its own envelope with its own sealer; no package-level mutable state |

## 7. Migration steps

This is a pure test addition — "migration" is the ordered implementation sequence:

1. `passphrase_test.go`: add `lowCostSealer()`, `sealWith()`, mirror structs
   (`testEnv`, `testKDF`) with the drift comment (D2).
2. Add R1a–R1e (table tests, subtests, `t.Parallel`).
3. Add R2a (tampered params, class-asserted) and R2b (oracle-stable byte identity).
4. Add R3a (mutation scan) and R3b (`FuzzSealOpenRoundtrip` with the 5 seeds).
5. `aesgcm_test.go`: add the aesgcm mirror, R4a, R4b.
6. Run the mandatory gates (below). The suite must be green at HEAD with no production
   change; if any row fails, re-verify the branch it targets before adjusting anything.
7. Commit as a conventional, imperative change (e.g., `test(snapshot): lock negative-validation matrix for passphrase Open`) with a body explaining the oracle-pinning rationale and an AI co-author trailer when applicable. No binaries.

## 8. Testable acceptance mapping

Every direction acceptance bullet maps to a named test and a concrete assertion:

| Direction acceptance | Test | Concrete assertion |
|---|---|---|
| Version 0/2 rejected | `TestOpen_RejectsUnsupportedVersion` | `err.Error()` contains `"unsupported KDF version 0"` / `"... 2"` / `"... 4294967295"` |
| Salt len 15/17 rejected | `TestOpen_RejectsBadSaltLength` | contains `"bad salt length 15"` / `"17"` / `"100"` / `"0"` |
| Zero Time/Memory/Threads rejected | `TestOpen_RejectsZeroKDFParam` | 4 rows, each `err.Error() == "snapshot/passphrase: zero KDF param"` |
| Nonce len 23/25 rejected | `TestOpen_RejectsBadNonceLength` | contains `"bad nonce length 23"` / `"25"` / `"100"` / `"0"` (post-KDF rows, low-cost envelope) |
| Tampered params JSON fails Open; oracle-stable error class | `TestOpen_TamperedParams` + `TestOpen_ErrorClassOracleStable` | swapped salt/nonce fail with the AEAD class; version 0/2 fail with the version class; the 4 AEAD-class causes are byte-identical to the exact literal |
| Oversized params rejected fast | R1a (version `MaxUint32`), R1b (salt 100), R1d (nonce 100), R1e (1 MiB blob → `"unmarshal params"`; 1 MiB salt → `"bad salt length"`) | rejection before/with the low-cost KDF; exact substrings |
| Any single-byte mutation of params or cipher fails | `TestOpen_AnySingleByteMutationFails` | every byte position of params JSON and ciphertext, flipped `^= 0x01`, fails `Open`; violating positions reported in one error |
| Seal→Open roundtrip fuzz with CI-run seeds | `FuzzSealOpenRoundtrip` | 5 seeds run under plain `go test`; property: `Seal` no-error + byte-exact roundtrip |
| Sibling consistency (aesgcm nonce + error class) | `TestSealer_OpenRejectsBadNonceLength` + `TestSealer_OpenErrorClassOracleStable` | nonce 0/11/13/100 → `"bad nonce length"`; wrong key/tampered cipher/swapped nonce → byte-identical `"snapshot/aesgcm: open: cipher: message authentication failed"`; version branch not duplicated (already covered) |
| T-8(b)/T-8(e) hardening verification | — | Campaign attribution only ([PROPOSED] per audit pack); no gate outside this module |

## 9. Verification plan

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./interfaces/snapshot/encryptionpassphrase/ ./interfaces/snapshot/encryptionaesgcm/ -run 'TestOpen_|TestSealer_|Fuzz' -v
go test ./interfaces/snapshot/encryptionpassphrase/ -run FuzzSealOpenRoundtrip -count=10   # seeds as CI tests
go test ./... -race
make ci
```

`make ci` is the handoff gate. Because the change is test-only and the assertions pin
verified HEAD behavior, the suite must be green before any future direction-1 (KDF-cap)
change — that is the point of landing it as a pure regression lock.
