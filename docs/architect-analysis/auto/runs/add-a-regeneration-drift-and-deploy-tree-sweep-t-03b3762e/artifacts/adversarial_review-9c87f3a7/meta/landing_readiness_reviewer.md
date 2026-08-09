All evidence gathered. Here is the independent executable-sequencing review.

---

# Review: T-9 design — 9 migration steps, rollback path, first-run-green

**Scope walked**: every step executed or simulated against the real repo and a clean scratch clone (`git clone --local` of HEAD 038e1765). Baselines re-measured independently: regen determinism (2 runs byte-identical, 157904B), committed drift (+8 TS/+5 PY, exactly the 3 AdminClient fields), deploy pairs (all 3 stale), `sdk-surface check` exit 0, `check-test` 203 passed, `docs/sdks/` clean.

## Verdict: one blocking sequencing defect — the design's R3 premise is misattributed, and step 9 as written makes the first CI run red

### Finding 1 (blocking): "committed SDKs stale at HEAD" is false; the drift is vs an uncommitted spec edit

- In a **clean clone of HEAD**, `go run ./cmd/gensdk --lang=all` reproduces the committed SDKs **byte-for-byte** (git: "nothing to commit, working tree clean"; 157596B committed == 157596B regenerated). HEAD is self-consistent.
- The +8/+5 "drift" exists only because the working tree carries an **uncommitted `docs/openapi.yaml` edit** (`M`, 19 insertions/2 deletions): the `servers:` purge (sibling b4-3, 2 deletions) **plus** `client_secret_expires_at`/`tenant_id`/`grant_types` on the `AdminClient` schema (19 insertions, owned by in-flight direction `surface-the-client-s-tenant-binding-tenant-id-gr-02c2fc57`, whose R5 commits the spec "in the same change" but never regenerates SDKs).
- **Consequence**: the design's step 3 regenerates SDKs to the *working-tree* spec (157904B) and step 9 commits them **without** the spec edit ("Do not modify `docs/openapi.yaml`"). I simulated exactly that commit in the clone: the first CI run's regen leg **FAILS** — committed 157904B vs regenerated-from-committed-spec 157596B (TS and PY). `make ci` is red on first run after landing.
- **Second, independent failure in the same commit**: the working tree's `ci:` also carries uncommitted parity-direction wiring (`proto-openapi-parity` target + ci token, `cmd_check_proto_openapi_parity` in cli.py). At clean HEAD the committed proto already has the 3 fields (`clients.proto` :80/:88/:89) but the committed spec lacks them → `proto-openapi-parity` fails on the first CI run unless the spec edit lands in the same commit.
- **Fix (either)**: (a) land the tenant-binding direction (proto + spec edit + parity wiring) first; T-9's R3 then becomes the correct, necessary SDK refresh and its commit is self-consistent; or (b) include the AdminClient spec edit in T-9's own commit (amend the "Do not modify" list accordingly). Add a **scratch-clone verification to step 8** — the current step-8 local run executes against the modified working-tree spec and *masks* exactly this CI failure.

### Finding 2 (minor): step-2/step-5-6 ordering leaves `check-test` red in a window

The tests created at step 2 include `test_cli_wiring`/`test_makefile_ci_includes_sdk_drift_check`, which assert on wiring from steps 5–6. Between steps 2 and 6, `python cli.py check-test` fails. Step 8 runs it green after wiring; nothing in `make ci` runs it. Either move the wiring tests after step 6 or state the intermediate red explicitly.

### Finding 3 (commit scoping caution): the working tree has 157 modified tracked files

`git status --porcelain | grep '^ M'` = 157 — the workspace carries many in-flight directions. HEAD's Makefile differs from the working tree (HEAD `ci:` at :265 lacks `proto-openapi-parity`; the design's :268 anchor is the working tree). The design never discloses that cli.py/Makefile/CHECKS_REGISTRY.md are already modified. Step 9's commit must be scoped to this change's hunks, or the revert story (below) breaks.

## Confirmed items

**R3 ordered before the gate becomes blocking** — structurally yes (steps 3–4 precede wiring 5–7; I verified the working-tree state after step 4's `cp`s makes all 3 deploy pairs byte-identical, and the deploy-leg SKIP condition holds in a fresh checkout). The defect is the *content* of R3 (Finding 1), not its position.

**dist/ exclusion does not mask** — verified with real git: tracked-modified `dist/client.js` + untracked `dist/newfile.js` are invisible to `git status --porcelain -- docs/sdks/ ':(exclude)docs/sdks/typescript/dist'` (F6 PASS), while a stray under `docs/sdks/python/` is reported (F7 PASS). The exclusion covers exactly the declared non-goal subtree; the regen leg byte-compares generator output directly (gensdk writes only client.ts/client.py, never dist/), so generator drift cannot hide. Post-R3, committed `dist/client.d.ts`'s `AdminClient` genuinely lacks the 3 fields (stale-by-design; npm ships without the optional declarations until a manual rebuild) — intended, and worth the commit-message sentence.

**Rollback complete** — simulated in the clone: reverting the landing commit(s) restores the tracked tree **byte-exactly** to pre-landing (`git diff --quiet` empty), both SDKs revert to their pre-landing bytes, the post-rollback state is self-consistent (regen reproduces committed SDKs), and untracked deploy copies + dist dirt survive untouched. No revert conflict with the sibling or tenant-binding directions (disjoint file sets). Two caveats: (a) if the spec edit lands as a separate prior commit, rolling back T-9 alone leaves SDKs stale vs the committed spec — harmless (gate gone) but re-landing needs R3 again; (b) if step 9 sweeps in the 157-file workspace, the revert removes them all — the design's "rollback = revert this commit" assumes a scoped commit.

**D6 determinism safe** — `grep servers cmd/gensdk/*.go` → 0 hits; the spec enters via `go:embed` (build-time, content-addressed cache, main.go:63); two independent runs byte-identical; the sibling adds only a gensdk *test* and sso-minimal tests and its own R4 asserts regeneration-stability. Regen output is a pure function of tree state — landing order cannot break determinism (the Finding-1 hazard is consistency/ordering, not determinism).

**Registry nit (N2 confirmed, sharpened)**: the table at CHECKS_REGISTRY.md:21-38 groups `checks/*` rows (:22-30, ending `self_test.py`) before `ops/scripts/*` rows (:31-35, ending `sdk_surface.py`). "After `sdk_surface.py`" drops the new row into the ops block; place it after `self_test.py`. The "Specific checks" group (:46) is the right command group. N1 (argparse `SystemExit(2)`) and N3 (`##` help comment) stand as previously noted.

**Bottom line**: steps 1–2, 5–8 and the rollback path are executable as written (with Findings 2–3 applied); step 3/9's sequencing is broken until the AdminClient spec edit is committed in the same landing — without it, the gate's first CI run fails on both `sdk-drift-check` (regen leg) and `proto-openapi-parity`. The design's step 8 must gain a fresh-checkout (scratch clone) verification, since its working-tree verification cannot see this failure.
