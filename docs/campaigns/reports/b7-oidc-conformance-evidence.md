Done. Summary of the work:

## Commits
- **`af3bc485`** `fix(conformance): disable gRPC listener in the headless harness` — harness fix
- **`1cd438e3`** `docs(conformance): record headless rerun at HEAD af3bc485` — docs + README sync

(both pushed by the repo's post-commit hook; AI co-author trailer on both)

## 1. Harness fix (test-only, no production code)
- `docker-compose.yml`: sso-server `command` → `["--config", "/etc/sso/conformance.yaml", "-grpc-listen", ""]` (empty listen = listener-disabled branch of the f585545e decision), plus comments; pinned tag `release-v5.2.1`, healthcheck, ports, config.yaml untouched
- `run-headless.sh`: `--validate-only` invocation now passes `-grpc-listen ""`
- `README.md`: the two documented validate commands synced to match

## 2. Run report (honest, two attempts)
- **Attempt 1** (exact `./run-headless.sh --timeout 900`): gRPC preflight **passed** — server built, booted healthy, DCR registration and admin signup succeeded. But suite login failed all 8 attempts: this box has an ambient `HTTP_PROXY=http://127.0.0.1:7897/` and `sso-issuer` is not in `no_proxy`; curl's `--resolve` login POST went through the proxy, which can't resolve the name → `502` → empty body → JSONDecodeError. Environment property, not a harness/server defect.
- **Attempt 2** (same script, proxy env vars unset — all harness traffic is localhost/container-network): completed, `SCRIPT_EXIT=0`. One suite-login retry (Spring warm-up), plan id `L5AkCP0Psgujp` (Basic plan, discovery + dynamic-client, 38 modules), test id `dQBMFqJgPmT9HzE` driven through headless Chrome with one CDP-fulfilled login.

## 3. Final statistics (archived `results/af3bc485/`)
plan.json / oidcc-server.log.json / oidcc-server.info.json / config.yaml / commit.txt / worktree.txt all present (gitignored, local only):
- **59 SUCCESS + 1 FAILURE** — identical to the 34ea1d3d baseline (60 steps both runs)
- Failure: expected `VerifyClientManagementCredentials` — "URL for client management point does not use https scheme" (HTTP-only topology)

## 4. Docs
`docs/sso/oidc-conformance.md`: "Latest run attempt (blocked)" → "Latest run (2026-08-15, HEAD `af3bc485`)" with date, commit, stats, baseline comparison, and the proxy environment note; the HTTPS-external-topology / OIDF-listing boundary statements are untouched. Header date updated to 2026-08-15.

## 5. Verification
- `go build ./... && go vet ./...` → **OK**
- `git status --porcelain` → only pre-existing unrelated dirty files remain (state.jsonl, campaign yamls, `.pi-batch.lock`, tasks yamls) — **no production code changes**, harness tree clean
