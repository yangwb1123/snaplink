# B12-3 FAPI 2.0 conformance run — completed up to the module's static-client gate

Status: **RUN EXECUTED.** The B12-1 dependency is merged at HEAD (`07832dda`),
so the contract's primary path ran: the harness registers the suite login
client with `id_token_signed_response_alg: RS256` (backed by a dedicated
RS256 id_token signing key wired via the new `keys.id_token_algs` config
knob), the suite login — the historical B11/B12-2 blocker — now SUCCEEDS, the
FAPI 2.0 SP final plan is created (56 modules), and the
`fapi2-security-profile-final-happy-flow` module runs for the first time
ever against this harness. It ends INTERRUPTED with **12 SUCCESS + 1 FAILURE**:
the suite's FAPI2 SP FINAL server tests hardcode a static client whose
per-test callback redirect cannot be registered against snaplink's
exact-match redirect-URI allowlist. That gate and its next step are
documented honestly below; no pass is claimed.

## 1. Dependency check at HEAD (contract step 1)

| Check | Result |
|---|---|
| HEAD commit | `07832dda` (`feat(sso): per-client id_token signing algorithm (id_token_signed_response_alg)`) — B12-1 landed |
| `git grep -n IDTokenSignedResponseAlg HEAD -- '*.go'` | present (57 hits across core/types.go, DCR, config, sqlite/postgres, discovery, issuance) |
| B12-1 report | `docs/campaigns/reports/b12-per-client-id-token-alg.md` (this batch's B12-R2-A output) |

Dependency present → primary path (contract step 2) executed.

## 2. Product enabler discovered during the run: `keys.id_token_algs`

The SDK per-client alg (`sso.WithIDTokenIssuerAlg`) exists since B12-1, but
the `sso-server` binary wires exactly one signing issuer from
`keys.signing.alg`, and DCR validation only accepts algs in the wired set —
so an RS256 login client would have been rejected with 400
`invalid_client_metadata` against the FAPI config's ES256 primary. The run
therefore needed the config-facing form of the SDK option. Added in this
batch (commit 1, `feat(sso)`):

- `keys.id_token_algs[]` (each: `alg` required eddsa/es256/rs256/ps256,
  optional `key_file`/`external`): wires a DEDICATED per-client id_token
  signing issuer, registered via `sso.WithTokenIssuer` (aggregated JWKS +
  hint validation) AND `sso.WithIDTokenIssuerAlg`.
- Boot gate (`config.validateIDTokenAlgs`): alg must be supported, must
  differ from the primary `keys.signing.alg`, no duplicates.
- Discovery advertises the union (`id_token_signing_alg_values_supported`
  = `["ES256","RS256"]` in the FAPI variant) — the same set DCR validates
  against.
- Empty (default) = byte-identical behavior; unit + cmd wiring tests cover
  both paths.

The FAPI variant (`config-fapi.yaml`) wires `id_token_algs: [{alg: rs256}]`,
and the harness registers the suite login client via DCR with
`id_token_signed_response_alg: RS256` (a plain OIDC client — RS256 does not
violate FAPI, whose constraints apply only to FAPI clients).

## 3. The run (`./run-headless.sh --fapi --timeout 1200`)

| Stage | Outcome |
|---|---|
| config validate (FAPI variant) | PASS — `config valid` |
| harness up (`docker compose up -d --build`) | PASS — sso-server rebuilt with the per-client-alg wiring, healthy |
| DCR register suite login client (RS256) | PASS — accepted and persisted |
| admin signup user | PASS (idempotent) |
| suite restart with login-client creds | PASS |
| suite login (OIDC via server under test) | PASS on attempt 2 — the hard-coded-RS256 Spring `OidcIdTokenDecoderFactory` now decodes the login ID token |
| plan creation | PASS — plan `9M7YF5n4cHjHB`, **56 modules** (vs the basic plan's 38), variant plain_fapi / private_key_jwt / DPoP / unsigned-PAR / plain-response |
| `fapi2-security-profile-final-happy-flow` module | FINISHED — **12 SUCCESS + 1 FAILURE**, INTERRUPTED (see §4) |

### Harness fixes discovered by the run (contract step 2a, in commit 2)

- The FAPI plan's `fapi_request_method`/`fapi_response_mode` are plan-
  intrinsic: the planinfo already bakes `unsigned` + `plain_response` into
  every module, so repeating them in the plan-creation `variant` query param
  makes the suite reject the plan with `400 Variant 'fapi_request_method'
  has been set by user...`. The `--fapi` PLAN_VARIANT now omits those two
  keys (documented in run-headless.sh). Plan creation previously always
  failed at this stage; it now succeeds.

## 4. Module result and the remaining gate (honest)

`results/07832dda-fapi/fapi2-security-profile-final-happy-flow.log.json`
(22 events):

- **12 SUCCESS**: GetDynamicServerConfiguration, CheckServerConfiguration,
  FetchServerKeys, CheckServerKeysIsValid, MapJwksToValidationLocation,
  ValidateJwksStructure, ParseUsableJwksKeys, WarnOnUnusableJwksKeys,
  EnsureJwksHasNoPrivateOrSymmetricKeyMaterial, CheckForKeyIdInServerJWKs,
  FAPI2FinalEnsureMinimumServerKeyLength, CreateRedirectUri. The suite saw
  `id_token_signing_alg_values_supported: ["ES256","RS256"]` and an
  aggregated JWKS carrying BOTH the ES256 primary and the RS256 per-client
  key — the B12-1 feature is exercised end to end and satisfies the suite's
  discovery alg check + FAPI2 SP key-length check.
- **1 FAILURE** → INTERRUPTED: `GetStaticClientConfiguration: As static
  client was selected, the test configuration must contain a client
  configuration`.

Root cause (proven from the pinned suite jar, `release-v5.2.1`):
`AbstractFAPI2SPFinalServerTestModule.configureClient()` (decompiled) calls
`GetStaticClientConfiguration` unconditionally — the FAPI2 SP FINAL
server-side tests hardcode a STATIC client and the plan exposes no
`client_registration` variant (its selectable variants are fapi_profile /
client_auth_type / sender_constrain / openid / authorization_request_type;
only fapi_request_method/fapi_response_mode are plan-level, both intrinsic).
A static client additionally cannot be pre-registered at snaplink because the
suite's callback redirect is per-test-instance
(`https://localhost:8443/test/{testId}/callback`), and snaplink's
`Client.IsRedirectURIValid` is an exact-match allowlist. So the module cannot
proceed past its client step without either (a) a suite/harness path to a
pre-registered static client with a stable redirect, or (b) product-level
wildcard redirect-URI registration support (opt-in per client, exact-match
default preserved) — a security-sensitive surface that must be designed
separately, not rushed into this conformance task. Both are recorded in
`results/07832dda-fapi/BLOCKER.md`.

## 5. Archive (contract step 2c)

`test/oidc-conformance/results/07832dda-fapi/` (gitignored, local):
`plan.json` (56 modules + variant), `fapi2-security-profile-final-happy-flow.log.json`,
`.info.json`, `config.yaml` (FAPI variant with `keys.id_token_algs`),
`commit.txt` (`07832dda`), `worktree.txt` (run-time worktree: my in-progress
changes + the preserved B12-3 OTel worktree), `BLOCKER.md` (this module-gate
record). Compare with the basic plan archive `results/78bb614f/`: 38 modules,
`oidcc-server` 59 SUCCESS + 1 FAILURE (the expected https client-management
check) — the FAPI plan is 56 modules and the happy-flow module's only
failure is the static-client gate, with the same expected discovery/JWKS
path exercised successfully.

## 6. Verification commands (actually run)

| Command | Output |
|---|---|
| `cd test/oidc-conformance && ./run-headless.sh --fapi --timeout 1200` | see §3; archived `results/07832dda-fapi/` |
| `/tmp/sso-server-test --validate-only -grpc-listen "" --config config-fapi.yaml` (locally built binary) | `config valid`, exit 0 |
| `cd /home/u1/workspace/demo/snaplink && go build ./...` | exit 0 |
| `go vet ./...` | exit 0 |
| `go test -count=1 -run 'TestMaintainability_|TestArchitecture_|TestDirectory' .` | PASS |
| `go test ./config/ ./cmd/sso-server/ ./cmd/sso-server/serverbuildsign/ ./interfaces/sso/... ./protocols/oauth/... ./protocols/oidc/... ./test/ -count=1` | PASS |
| `git status --porcelain` | B12-3 OTel worktree (pre-existing, preserved, uncommitted) + this batch's files |

Note: the docker image was built from the run-time worktree (which includes
the preserved B12-3 OTel changes — additive middleware/tracing work, no
protocol-surface impact on the surfaces the FAPI module exercises; recorded
in the archive's `worktree.txt`). The validate stage ran against the
pre-existing image and warned (warn-only) about the then-unknown
`keys.id_token_algs` key; the freshly built image loads it.

## 7. Commits (this batch)

1. `feat(sso): wire additional per-client id_token signing keys via keys.id_token_algs` —
   config schema + boot gate + cmd wiring (serverbuildsign.BuildIDTokenAlgOptions),
   unit/cmd tests, config-reference, CHANGELOG.
2. `test(conformance): run FAPI 2.0 SP through the module's static-client gate` —
   harness (DCR RS256 login client + `keys.id_token_algs` in config-fapi.yaml +
   FAPI plan-variant fix), README fapi row, evidence-table addendum, this
   report, CHANGELOG.

Both conventional + imperative, with the `Co-authored-by: pi` trailer. The
B12-3 OTel worktree stays uncommitted and untouched (mixed files staged via
`git apply --cached` so only this batch's hunks enter the commits).
