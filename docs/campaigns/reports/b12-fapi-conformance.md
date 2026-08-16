# B12-2 FAPI conformance run — fallback outcome (blocked, B12-1 not merged)

Status: **FALLBACK EXECUTED** — the FAPI 2.0 run was NOT attempted because
its dependency (B12-1 per-client `id_token_signed_response_alg`) is **not
merged at HEAD**. Per the task contract ("若该功能未在 HEAD 出现，按本提示的
fallback 执行"), this batch executed the fallback instead: verify the harness
variant is intact, rerun the basic plan to prove zero regression, and record
the B12-1 absence as the blocker honestly. No FAPI result is claimed or
fabricated.

## 1. Step 1 — dependency check at HEAD

| Check | Result |
|---|---|
| HEAD commit | `78bb614f` (`docs(campaigns): B11 batch definitions and completion reports`) |
| `git log --all --grep id_token_signed_response_alg` (committed) | empty — no per-client alg commit exists |
| `git grep -l IDTokenSignedResponseAlg HEAD -- '*.go'` | empty — the field does not exist at HEAD |
| B12-1 report `docs/campaigns/reports/b12-per-client-id-token-alg.md` | **absent** — B12-1 timed out before producing it |

B12-1's implementation exists **only in the uncommitted worktree** (the
previous B12-1 session timed out; 29 modified/untracked files covering
`shared/core/types.go` Client field, DCR validation, config keys, sqlite
migration v7 / postgres schema v5, issuer selection, discovery union — see
`docs/design/per-client-id-token-alg.md`, present in the worktree). It
compiles cleanly (`go build ./...` and `go vet ./...` both exit 0 with the
worktree state) but is not merged, so HEAD's server cannot serve an RS256
login ID token to the OIDF suite — the B11 blocker (B11-2 / BLOCKER.md)
stands. Per contract, this absence is the blocker and the FAPI module was
not run.

## 2. Step 3 — fallback: harness variant intact

`config-fapi.yaml` + `--fapi` variant versus the default topology, verified
by parsing both compose graphs (the same command the harness itself uses):

```bash
docker compose --env-file config.env config > /tmp/compose-default.txt
CONFORMANCE_CONFIG=config-fapi.yaml docker compose --env-file config.env config > /tmp/compose-fapi.txt
diff /tmp/compose-default.txt /tmp/compose-fapi.txt
```

**Result**: the ONLY difference is the sso-server config mount source
(`config.yaml` vs `config-fapi.yaml`); every other service field (ports,
env, networks, healthchecks, image pins) is byte-identical. The harness
files themselves are unmodified relative to HEAD (`git diff HEAD --`
`test/oidc-conformance/{docker-compose.yml,drive_test.py,run-headless.sh,`
`config.yaml,config-fapi.yaml}` is empty). Variant intact.

## 3. Step 3 — fallback: basic plan rerun (zero regression)

Reran the committed basic plan at HEAD state (with the uncommitted B12-1
worktree present, so the result also covers those additive changes — their
default path is byte-identical by design):

```bash
cd test/oidc-conformance && ./run-headless.sh --timeout 900
```

| Stage | Outcome |
|---|---|
| config validate (`--validate-only`, default config.yaml) | PASS — `config valid`, exit 0 |
| harness up (`docker compose up -d --build`) | PASS — sso-server built from worktree, healthy |
| DCR register suite login client | PASS |
| admin signup user | PASS (idempotent) |
| suite login (OIDC via server under test) | PASS (1 transient retry during suite boot, then admin session confirmed) |
| plan creation (`oidcc-basic-certification-test-plan`, discovery + dynamic_client) | PASS — plan `Oswbl812yuDe7`, 38 modules |
| `oidcc-server` module | FINISHED |

Final per-step statistics (`results/78bb614f/oidcc-server.log.json`, 115
events): **59 SUCCESS + 1 FAILURE + 3 WARNING** (+ 5 INFO + FINISHED) —
**identical to the archived baseline `7400ba0c`** (59 SUCCESS + 1 FAILURE +
3 WARNING). The sole FAILURE is the known, expected
`VerifyClientManagementCredentials` step (`URL for client management point
does not use https scheme`, requirement OIDCR-3.2): an HTTP-only local
issuer cannot provide the https client-management URL — the same expected
failure in every archived HTTP run. The 3 WARNINGs are the non-fatal
`EnsureIdTokenDoesNotContainNonRequestedClaims` notices (`ext` + `scope`
claims). The pinned config is byte-identical to the baseline (md5
`932b860b53ecb023b143e686c8a67179`), and the 38-module plan list matches the
baseline module-for-module. **Zero regression confirmed.**

Evidence archived at `test/oidc-conformance/results/78bb614f/`:
`plan.json`, `oidcc-server.log.json`, `oidcc-server.info.json`,
`config.yaml`, `commit.txt` (`78bb614fb9739a44e5cf08755bf963208f879e70`),
`worktree.txt` (records the uncommitted B12-1 worktree — see the B12-1
evidence note in §5). `docker-compose.yml` was restored to the committed
bytes after the run (the sed credential injection is runtime-only and is
reverted; verified `git status` clean for the harness directory).

## 4. Why FAPI remains blocked (B12-1 missing)

The B11 root cause is unchanged and is re-confirmed by inspection, not
speculation: the pinned OIDF suite (`release-v5.2.1`) protects its own admin
UI with Spring Security's `OidcIdTokenDecoderFactory`, whose
`jwsAlgorithmResolver` is hard-coded to **RS256**, while the FAPI 2.0 SP
forbids RS256 for ID tokens (its own
`FAPI2CheckDiscEndpointIdTokenSigningAlgValuesSupported` demands
PS256/ES256/EdDSA/Ed25519). The FAPI variant signs ES256, so the suite login
would reject the login ID token (`invalid_id_token: Signed JWT rejected:
Another algorithm expected`) and no plan/module could run — exactly the
evidence archived at `results/39ecdf7a-fapi/BLOCKER.md`.

The product-level unblock (per-client `id_token_signed_response_alg` so the
suite's RS256-only login client coexists with ES256/PS256 FAPI clients on
one issuer) is **implemented in the B12-1 worktree but not merged at HEAD**;
this batch therefore cannot execute the FAPI run per contract. The B12-1
worktree must be landed (with its own report and full gates), after which
the FAPI conformance run becomes the next step: add
`id_token_signed_response_alg: RS256` to the suite login client's DCR
registration in `run-headless.sh` (the login client is a plain OIDC client,
so RS256 does not violate FAPI — the FAPI constraints apply only to FAPI
clients; the design's acceptance assertions cover this), then
`./run-headless.sh --fapi --timeout 1200` and archive
`results/<commit>-fapi/`.

## 5. Verification commands (actually run, real output)

| Command | Output |
|---|---|
| `cd test/oidc-conformance && ./run-headless.sh --timeout 900` | see §3; archived `results/78bb614f/` |
| `cd /home/u1/workspace/demo/snaplink && go build ./...` | exit 0 (no output) |
| `go vet ./...` | exit 0 (no output) |
| `go test -count=1 -run 'TestMaintainability_|TestArchitecture_|TestDirectory' .` | `ok github.com/yangwb1123/snaplink 0.325s` |
| `docker compose --env-file config.env config` (default vs fapi) | identical except the sso-server config mount source |
| `git status --porcelain` | B12-1 worktree (uncommitted, pre-existing) + this report/docs sync; harness dir clean after compose restore |

Note: the basic rerun's docker image was built from the worktree state
(which includes the uncommitted B12-1 changes). Because B12-1's default path
is byte-identical by design (no client sets the field, no per-alg issuer is
wired in the harness config), the basic result is the valid zero-regression
baseline; the B12-1 evidence note in the archive's `worktree.txt` documents
the exact build state.

## 6. Commit scope

Docs-only (`docs` prefix): this report, the evidence-table addendum in
`docs/sso/oidc-conformance.md`, and the README FAPI status line. No harness
change in this batch (the harness variant was already landed in `b3074cd1`
and verified intact); CHANGELOG gets no entry here because there is no
shipped behavior change in this commit — the B12-1 CHANGELOG entry belongs
to the B12-1 commit when it lands.
