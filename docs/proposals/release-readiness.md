# Release readiness implementation

## Goal and boundary

Deliver a reproducible stock SSO container and a gated multi-platform Docker Hub
release, then validate the first business integration and production state
boundaries. This is an implementation tracker, not release or certification
proof. Browser applications, Billing and Stripe remain separate deployments.

## Ordered work

| Wave | Scope | Completion evidence |
|---|---|---|
| 1 | Explicit deploy-artifact refresh; retain the read-only drift gate | Targeted sync tests and complete `make ci` |
| 2 | Bounded idempotency responses without bypassing grant/session validation | Negative, expiration and backend tests; race repetition |
| 3 | Reproducible development container/Compose startup | Clean bootstrap, nonroot writable state, probes and restart tests |
| 4 | Opt-in Docker Hub version publication | Protected dispatch/tag, gates, both architectures, digest/SBOM/signature checks |
| 5 | Reference application, shared-state and recovery acceptance | Tenant/client isolation, refresh/logout, key rotation, recovery and load evidence |

## Product decisions and external dependencies

- Docker Hub namespace, repository visibility and minimum-privilege registry
  credentials must be provisioned by the operator. Do not publish implicitly.
- ARM CI and a real Apple Silicon machine must execute runtime acceptance;
  cross-compilation/ELF inspection alone are not native runtime evidence.
- Capacity, P99, revocation latency and RPO/RTO need a named deployment target.
- Persistent Webhook delivery, optional resource-server event revocation,
  incremental session scans and primary Passkey recovery each need their own
  bounded specification and security review. They are not prerequisites for a
  small single-process evaluation deployment, nor silently promised features.
- Official OIDC/FAPI certification requires an externally reachable trusted
  HTTPS issuer, a chosen certification profile and an OIDF account/result.

## Owners and files

- Deploy sync: `checks/sdk_drift.py`, `checks/test_sdk_drift.py`, `Makefile`.
- Idempotency: existing SSO/middleware adapters, OAuth grant handlers and real
  memory/Redis stores; keep production Go budgets and the 60-file SSO ceiling.
- Containers: `ops/deploy/compose`, existing Dockerfile/CI/deployment contracts.
- Publication: a dedicated opt-in workflow and its contract tests; do not
  reinterpret the existing GoReleaser/GHCR flow as a Docker Hub release.
- Integration: `test/` (`package ssotest`); frontend implementation stays external.

## Acceptance and non-goals

- Apply `AGENTS.md`, U1-U9, O1-O11 and S1-S7 as relevant; preserve each existing
  oracle-safe response and fail-open/fail-closed policy.
- Never bypass hooks, weaken gates, add exemptions or mutate root Go modules.
- Artifact sync is explicit, validates canonical generation first, overwrites
  only the three declared derived copies and rejects paths escaping the tree.
- Generic token replay is limited to built-in client credentials, retained for
  at most one minute and revalidated against current authorization/revocation.
  Stateful grants use their own stores; local coordination is not cluster-wide
  first-miss ownership or exactly-once issuance.
- Refresh grace never extends the original grant/access deadline. Replays need
  reuse evidence, a live same-family successor, current session/user/client,
  scopes and sender bindings. Apply deadlines to all four store backends.
- Persist Redis family-reuse evidence before atomic GETDEL, refusing consume
  on marker-write error; its TTL must cover the remaining original grant.
  Grace keys must not contain raw credentials. DSN-owned grace databases must
  close after their cleanup workers drain; panic recovery must release local
  client-credentials locks without caching an unfinished response.
- Development credentials/ephemeral state are not production configuration.
- No new protocol family, general plugin platform or universal queue framework.

## Compatibility and rollout

Keep feature-off behavior unchanged. Changes to optional replay semantics must
be documented and tested. Use additive optional storage capabilities rather
than breaking existing storage implementations. Production deployments stage
configuration and persistent state before switching traffic. Deadline-less
legacy grace responses and Redis's former plaintext grace keys are not
replayed; old entries expire on their existing TTL. Rolling upgrades may need
fresh authorization. Registry pushes are opt-in; no pull request can publish,
and credentials are never build args.

## Verification

After every Go edit: build, vet and committed architecture/maintainability gates.
Each wave adds adjacent targeted tests and an independent diff/contract review.
Before handoff: root race tests, E2E tests and `make ci`; module/profile changes
also validate module metadata and final binary inventory. Native ARM, registry
publication and certification stay incomplete until their external evidence
exists.

## Execution status

- Wave 1 implemented: explicit deploy-copy refresh, scanner regression tests
  and backchannel-logout test scheduling fix. Complete `make ci` passed at that
  wave; this does not certify subsequent worktree changes.
- Wave 2 implemented with token/session negative tests and repeated race runs;
  independent review identified Redis reuse-marker failure handling, raw grace
  keys, PostgreSQL retention, SQLite lifecycle and panic-safe lock release.
  Remediation and final whole-tree verification are in progress.
- Waves 3/4 have development config, runtime acceptance scripts, publication
  workflow and contract tests. The latest amd64/arm64 SSO OCI index, linked
  attestations, static ELF/Go metadata and amd64 restart/revocation checks
  passed. Loopback-only registry transfer/index promotion/digest validation
  passed; this is not Docker Hub publication, content-level SBOM review or
  native ARM evidence.
- Additional concurrent Browser SSO/schema changes are preserved, not claimed
  as this task's implementation. Their SDK-generation drift currently blocks
  the final combined-tree gate; regenerate derived clients before sync/check.
- Wave 5 and the separately scoped extension projects remain incomplete.
  External publication, Apple Silicon, production HA/recovery/load targets and
  certification have no completed acceptance evidence.
