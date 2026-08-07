All claims verified against HEAD. Here is the verification result.

## Verdict: the AC-1..AC-11 mapping is sound — all five T-2 checks covered, relay check explicitly justified, not dropped

### Five T-2 checks → AC rows (design.md §8)

| T-2 check (pipeline.yaml) | AC | Run(args) invocation | Pinned exit | Pinned tokens | Wrong-reason barrier |
|---|---|---|---|---|---|
| #1 mid-chain + `--anchor-hash` → 0 | AC-1 | `Run(["--from-file", w.json, "--anchor-hash", anchor])` | 0 | `segment verified:`, `anchored=<anchor>` | If the impl ignored the anchor and ran `VerifyChain`, index-0 breaks (chainer seeds `""`) → exit 1, so exit 0 is only reachable via real `VerifyChainSegment(events, anchor)` |
| #2 same segment, no anchor → 1 | AC-2 | `Run(["--from-file", w.json])` | 1 | `chain BROKEN:`, `chain break at index 0` | Tokens pin the specific fail-closed mode; a wrong-reason exit 1 (load error, tamper elsewhere) fails the token match |
| #3 first-PrevHash ≠ anchor → 1 | AC-3 | `Run(["--from-file", w.json, "--anchor-hash", "deadbeef..."])` | 1 | `chain BROKEN:`, `expected "deadbeef..."` | `expected %q` (chainer.go:207) only appears if the anchor reaches the chainer; an anchor-dropping impl emits `expected ""` and fails |
| #4 `--limit`-truncated honest head | AC-7 | window + `--limit < len` + anchor; and without anchor | 1 | `prefix verified:`, `not the full chain` | False-tip print (`chain verified: … head=`) fails tokens; any exit-0 prefix path fails the exit pin. The unanchored-truncated row is the direction-mandated behavior change, documented in §3.3/§5/§7.4 |
| #5 relay-shaped batch vs boundary anchor | AC-6 | batch = mid-chain slice; with anchor → 0, without → 1 | 0 / 1 | `segment verified:` / `chain break at index 0` | Same barriers as AC-1/AC-2 on the relay-shaped fixture |

### Harness reuse — all confirmed in repo
- `chainedEvents(t, n)` (main_test.go:174) builds real hash-chained events via `audit.New(sink, audit.WithHashChain())`; slicing yields a mid-chain window whose `events[0].PrevHash` is the excluded predecessor's Hash — so the planned `midChainWindow` fixture is constructible.
- `runVerify(t, args...)` (checkpoint_test.go:133) invokes `Run` in-process capturing stdout+stderr, returns (code, stdout, stderr); `captureStdout`/`captureStderr` (coverage_test.go:156/197); `urlServer` httptest newest-first paging (checkpoint_test.go) for AC-5; `writeEventsFile` for fixtures.
- AC-8's two new misuse rules route through `checkMisuse`'s return-code path (same pattern as the existing `--notary-key` rule at main.go:172-177), keeping them in-process testable — verified `runVerify` cannot exercise the legacy `usageErr` `os.Exit` paths.

### Relay-shaped check (AC-6): genuinely covered, explicitly justified as batch-shape-only
Independently confirmed the design's evidence: `commerce.OutboxEvent` (domains/tenant/commerce/store.go:74-93) has no `PrevHash`/`Hash` fields (outbox fact with `PayloadDigest`); `Relay` (infrastructure/auditgovernance/relay.go:167+) drains `commerce.OutboxStore`; `audit-contract-batch-snaplink.md:16` marks `auth.token.issue` mapping `[PROPOSED]`. Design §1 documents this correction, decision 8 explicitly rejects literal ManagedRelay integration, and §7.3 pins the contract so B4-5-wired batches verify unchanged. AC-6 exists as a distinct row with pinned outcomes — not silently dropped.

### Nuances to note (non-blocking)
1. **AC-11 is not a Run(args) invocation** — it's the build/vet/maintainability gate pin. The "each AC is an in-process Run(args) invocation" claim holds for AC-1..AC-10 (all five T-2 checks); AC-11 is a deliberate extra.
2. **AC-6 is execution-equivalent to AC-1+AC-2** — the relay specificity is fixture intent plus the documented justification; that is the honest maximum given literal integration is impossible today.
3. **Requirements artifact drift** — `requirements.md` is 21 lines, not the claimed 132; the design flags this and re-derives from `pipeline.yaml` (the authoritative source). The AC table is the design's own mapping and is internally consistent with it.
4. **Minor evidence nit** — design says auto-reverse now at main.go:321-323 (the call site in `readFromFile`); `reverseEvents` itself is at 436. Semantics confirmed either way.
5. **Budget claims verified** — chainer.go exactly 500 lines, platform/audit exactly 16 non-test files (41 total incl. 25 tests), cmd/sso-ctl exactly 16 subdirectories (20 entries = 16 dirs + 4 files), main.go 453 lines. AC-11's gate pins are realistic.

**Conclusion**: AC-1/2/3/6/7 cover T-2 checks #1-#5 one-to-one, each with a pinned exit code and exact output tokens that cannot be satisfied by an anchor-ignoring, false-tip-printing, or fail-open implementation; the relay-shaped check is covered at batch-shape level with explicit, code-verified justification rather than being dropped.
