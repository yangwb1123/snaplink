All three verification targets confirmed by direct measurement against HEAD. Report follows.

# Verification: SDK-refresh backward-compat, dist/-excluded sweep, and R1/R3 remediation coherence

## 1. TypedDict total=False + TS `?`-optional fields — truly non-breaking ✅

**Measured**: regenerated to temp with `go run ./cmd/gensdk --lang=all` and diffed. The drift vs committed files is *exactly* the three declared fields, all in the `AdminClient` interface (both languages), additions only — no removals, no requiredness flips, no reordering:

- **TS** `client.ts`: 2 hunks, 6 added lines (`diff | wc -l` = 8) — `client_secret_expires_at?: number`, `grant_types?: string[]`, `tenant_id?: string`, each `?`-suffixed in `interface AdminClient` (all of whose members are `?`-optional). The only other `client_secret_expires_at` in the file (line 611, required, in a different interface) is untouched by regeneration.
- **PY** `client.py`: 2 hunks, 3 added lines (`diff | wc -l` = 5) — `client_secret_expires_at: int`, `grant_types: List[str]`, `tenant_id: str` inside `class AdminClient(TypedDict, total=False)`.

Why non-breaking, verified end-to-end:

1. **Type-level only, zero runtime impact.** Both clients are JSON passthrough: PY `_request` is `json.dumps`/`_parse_body` with no schema validation; TS `request<T>` is `JSON.stringify`/parse with no validation. Interface/TypedDict additions are erased at runtime; emitted JS behavior is unchanged.
2. **Optional in both directions.** TS: adding optional props to an interface used both as request body (`adminClientCreate(body: AdminClient)`) and response type is the canonical additive change — consumers that omit the keys remain assignable; nothing that compiled before stops compiling. PY: `total=False` keys are optional on write and read; `AdminClient` is `total=False` for *all* keys.
3. **Types catch up to the wire, not ahead of it.** The server already emits these fields: `shared/core/types.go:47` `TenantID json:"tenant_id,omitempty"`, `:304` `GrantTypes json:"grant_types,omitempty"`, `:358` `SecretExpiresAt json:"client_secret_expires_at,omitempty"`; the gRPC admin response sets `ClientSecretExpiresAt` (`interfaces/grpcserver/grpcadmin/admin_clients.go:407`). Consumers receiving admin responses already see these keys at runtime; the refresh only declares them.
4. **No in-repo consumer is affected.** `AdminClient` is referenced only inside `client.ts` itself; `hosted-login.ts`, `client.test.mjs`, `index.ts` have zero references; the only other repo mention is a doc link in `interfaces/apidocs/template.go:116`.

⚠️ **Precision note (P4)**: the design's changed-surfaces table says "`ClientMetadata` is `TypedDict(total=False)` — new keys are optional". The keys actually land in **`AdminClient`** (`client.py:64`); `ClientMetadata` (`:299`) *already* carries all three fields in both committed and regenerated files. The compatibility conclusion is unaffected (both classes are `total=False`), but the citation names the wrong class.

## 2. dist/-excluded sweep — no false-fail, no masked drift ✅

**Premise verified**: `docs/sdks/typescript/dist/` is committed (8 files, `git ls-files`), built by `tsc -p tsconfig.json` (`outDir: dist`, package.json `build`/`prepack`). Critically, committed `dist/client.d.ts`'s `AdminClient` **lacks** the three fields — dist was built from the *stale* client.ts. So after R3 refreshes client.ts, any local `npm run build` dirties tracked dist; without the exclusion the R1 cleanliness scan false-fails. The P2 exclusion is therefore *necessary*, not defensive.

**Empirically tested** in a scratch clone (dirtied `dist/client.js` + new untracked `dist/newfile.js` + modified `client.ts` + stray `docs/sdks/python/stray.txt`):

- Blanket `git status --porcelain -- docs/sdks/` → 4 entries (incl. both dist entries) — would false-fail.
- D3's exact command `git status --porcelain -- docs/sdks/ ':(exclude)docs/sdks/typescript/dist'` → only `client.ts` and the python stray — dist dirt invisible, **all non-dist drift still reported**.

Masking analysis: the exclusion covers exactly the declared non-goal subtree (`docs/sdks/typescript/dist`); every other tracked path under `docs/sdks` (READMEs, `hosted-login.ts`, `index.ts`, `package.json`, `tsconfig.json`, `.mjs` tests, python/) remains visible. The regeneration leg byte-compares generator output directly (not git status), so generator drift can never be masked by the exclusion. The deploy leg itself involves only the three byte-identity pairs (`openapi.yaml`, `client.ts`, `client.py`) — dist is not a sweep target in either leg.

**One residual to state explicitly**: after R3, committed `dist/` is stale w.r.t. `client.ts` (its `AdminClient` lacks the new optional fields) until a maintainer runs `npm run build` and commits. The gate deliberately ignores this (declared non-goal) and the npm-published `@snaplink/sso-client` (`main: ./dist/index.js`) will ship without the three optional type declarations until then — additive-optional only, so no consumer break, but it is a real, intended gap.

## 3. docs/sdks/* staleness remediation coherent with R1/R3 corrections ✅

- **Correction 2 (committed SDKs stale at HEAD) → R3**: measured staleness is exactly the 3 fields/2 hunks per file (+8/+5 diff lines — matching the design's E9 and the requirement's "4 hunks"). Regeneration is deterministic (two independent runs → `cmp` byte-identical), so the in-place refresh makes committed == generator output and the regen leg goes green by construction. The committed `docs/sdks/` tree is currently clean (`git status --porcelain -- docs/sdks/` → 0 entries), so the cleanliness leg won't trip on pre-existing dirt when the gate lands.
- **Correction 1 (deploy tree untracked) → R2/R3**: the working tree has `static/` present-but-untracked with **all three sweep pairs currently stale** (`diff -q` nonzero for openapi.yaml; the sdks copies differ per the E1/E3 measurements); `conf.d/gateway.conf` tracked (P1 scope holds). R3's `cp` refresh makes the pairs byte-identical, and the skip-when-absent semantics cover fresh checkouts. No in-tree script, Make target, or nginx conf references `fullstack/static`, so nothing else can re-stale it silently — the sweep is the only guard.
- **P2 (dist exclusion)**: coherent as shown in §2 — it reconciles R1's literal "any modified/new file" with the declared "no dist/ staleness check" non-goal.
- **Wiring anchors cited by the design all match HEAD**: Makefile `.PHONY` :16, `sdk-surface-check` :125-126, `ci:` :268 (ends at `sdk-surface-check`, no drift/deploy target); cli.py `cmd_sdk_surface` :275-278, `"sdk-surface"` :356, passthrough tuple :388, `check-test` :345; CHECKS_REGISTRY.md rows :31/:45. Baseline `python cli.py sdk-surface check` → `OK (13 groups, 316 operations, 2 languages)`, exit 0 (acceptance 9 holds).
- **D6 sibling interaction**: confirmed nil — `grep servers cmd/gensdk/*.go` → 0 hits; regeneration embeds the working-tree spec (`docs/openapi_embed.go`), so the drift leg always reflects the current spec regardless of the sibling direction's landing order.

**Verdict**: all three constraints hold as designed. Two precision notes to carry into implementation: (a) the design's "ClientMetadata" citation should read "AdminClient" (compat conclusion unchanged); (b) post-R3, committed `dist/` is stale-by-design and the npm package won't expose the new optional fields until a manual rebuild — worth a sentence in the commit message so a future maintainer doesn't "fix" the gate by re-enabling dist checks.
