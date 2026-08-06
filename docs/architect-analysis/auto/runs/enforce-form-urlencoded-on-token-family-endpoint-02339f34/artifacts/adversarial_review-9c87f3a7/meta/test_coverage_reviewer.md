Verification complete. I checked every finding's anchor against the tree and the design's current AC-1..AC-5 mapping; the gate report is at `docs/architect-analysis/auto/runs/enforce-form-urlencoded-on-token-family-endpoint-02339f34/artifacts/design_gate-6a76b0dd/task-1-design-gate.md`.

## Results per finding

**1. Form-encoded RFC 9396 PAR test — MISSING (blocking).** Verified real: `parRequestForm.AuthorizationDetails`/`Claims` are `json.RawMessage` (`handle_par.go:100,105`), `setFormField` (`oauthwire/bind.go:112-134`) has no RawMessage case → silent drop, and `issuePARRequest` stores them via `CloneRawJSON` (`:246,255`). `parThenLogin` (`handle_par_test.go:349-353`) posts JSON RAR and asserts the claim at `:403-405`; zero form+RAR tests exist. The design never mentions this — not in F1–F8, not in section 2.1, not in the AC table. Needs: RawMessage case in `setFormField` + unit test in `protocols/oauth/bind_extra_test.go`, and migrating `parThenLogin` to form while keeping `:403-405`.

**2. TestGeneratePython\* — PARTIAL (blocking).** Verified: `emit_test.go` has zero `TestGeneratePython*` (only two `TestGenerateTS_*`); `GeneratePython` exists (`gen_py.go:22`); all negative-set ops exist in openapi (`postLogin`:528, `putRegistration`:1769, `postDeviceCode`:1539, `postDeviceVerify`:1845, `postMFAComplete`:639, `postBackchannelAuthentication`:1600). AC-2 asserts the outcome generically but names no test and pins no negative set — needs a concrete `TestGeneratePython_FormBody` in `cmd/gensdk/emit_test.go`.

**3. TS emit_test.go:231 flip — PRESENT.** Line 231 is exactly `` `{ body, clientAuth: true });` `` in `TestGenerateTS_ConfidentialAuthAndStrictOptionalTransport` (:207); M5 names it verbatim. No change needed.

**4. Nullish skipping (G3) — MISSING (blocking).** Precedents verified: Python query filter (`gen_py.go:99`), TS `v !== undefined` (`gen_ts_runtime.go:146`); the designed form paths would emit `"None"`/`"undefined"`. Zero mentions in the design. Needs nullish filters in both form encoders plus emission assertions in the two emit tests.

**5. /par 400 no-store — PRESENT.** `token_no_store_test.go` has 7 tests, none for `/par`; `TokenNoStoreHeaders` pre-bind (`handle_par.go:55`). AC-3a maps it concretely.

**Gates:** all five test homes are existing files — no new files, so architecture budgets (interfaces/sso 60-file ceiling, cmd/gensdk ≤10) are untouched; each `.go` edit runs `go build ./... && go vet ./...` + `go test -run 'TestMaintainability_|TestArchitecture_' .`, and M9 sequences `make ci`.

**VERDICT: FAIL** — the committed mapping resolves 2 of 5 findings; findings 1, 2 (as a named test with pinned negative set), and 4 need concrete test entries added to AC-1/AC-2 and the corresponding binder/runtime changes before implementation.
