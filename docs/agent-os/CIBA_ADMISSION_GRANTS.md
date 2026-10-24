# CIBA request admission: explicit client grant restrictions

## Goal and observable outcome

An authenticated client whose nonempty `grant_types` omits exact
`urn:openid:params:grant-type:ciba` must not start a new backchannel request.
It must receive `400 unauthorized_client` before hint resolution, user-code
verification, pending-request persistence, challenge delivery or success audit.
This prevents unauthorized challenge side effects and closes the initiation
route around the existing token endpoint's CIBA grant restriction.

The existing nil/empty grant-list compatibility remains unrestricted. This is
not a new CIBA `offline_access` requirement and does not alter Step36's separate
initial-refresh grant restriction.

## Boundary and owner

- OAuth/protocol flow and authorization policy; owner:
  `protocols/oauth/handle_ciba.go::HandleBackchannelAuth`.
- Embeddable Server and existing opt-in stock CIBA composition; feature gates,
  default wiring and all store interfaces remain unchanged.
- Use the existing `GrantCIBA` and `ErrUnauthorizedClient` constants and local
  protocol error shape. No new SPI, public option, dependency, schema structure,
  YAML/env key, transport or import-layer exemption.
- `shared/core/types.go` only clarifies the existing `GrantTypes` field comment;
  its declaration and serialization remain unchanged.

## Ordering, compatibility and fail-closed criteria

1. Preserve no-store, missing-store, bind, Basic-over-body, assertion, client
   lookup/active/tenant, secret and resource validation before the new gate.
   A bad credential still receives the existing authentication error, not an
   authorization result. Invalid resources still return `invalid_target` first.
2. Exact membership is required for nonempty lists. Other grants, blank entries,
   CIBA prefixes/suffixes/case aliases or unsplit combined values do not qualify.
   Allowed scopes (including `offline_access`) never authorize a grant type.
3. Nil/empty lists, exact CIBA, duplicate exact CIBA and CIBA alongside other
   grants preserve existing request validation, identity, scope order/defaults,
   requested-expiry/interval, notification credential and stored context.
4. Public-client compatibility and assertion authentication remain unchanged;
   proving identity does not override an explicit grant restriction. Assertion
   verifier seams in unit tests are not real cryptographic-verification proof.
5. Denial has no `auth_req_id` or credential field and no pending request,
   challenge transport call, success audit or token-store write. No fallback,
   retry, default-grant inference or client configuration mutation is introduced.
6. Approved authorized flows retain atomic claim/replay and existing refresh
   behavior for poll, ping collection and push. Ping is tested through the SDK
   callback seam; push uses a real owned loopback TLS receiver, not a remote
   notification service.

Applicable evaluation: U1/U2/U3/U5/U8/U9, O4/O8/O10 and S2/S3/S4 as exercised by
existing/new flow tests. Frontchannel authorization `iss` shaping is not added
to this backchannel endpoint. Committed Go gates and full `make ci` remain
required; Python checks/acceptance are supplementary.

## Implementation and verification plan

New tests: `protocols/oauth/handle_ciba_grant_admission_test.go` and
`test/backchannel_grant_admission_test.go`. Update OpenAPI, frontend contract,
error-code registry, checks registry and the client field comment together.
Regenerate SDKs and cached TypeScript declarations: the AdminClient grant-list
first-line documentation now includes CIBA initiation, so derived documentation
changes are genuine, not forced SDK drift. No generator or dependency change.
Capture the new-test source before the first build, expected pre-fix failures,
the exact final source, all normal exits and all failed attempts privately.

```sh
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test -count=1 ./protocols/oauth -run TestBackchannelGrantAdmission -v
go test -count=1 ./test/ -run TestE2E_BackchannelGrantAdmission -v
go test -race -count=10 -timeout=120s ./protocols/oauth ./test/ -run 'Test(BackchannelGrantAdmission|E2E_BackchannelGrantAdmission)'
go test -race -count=10 -timeout=120s ./internal/handler/tokengrant ./test/ ./protocols/oauth ./interfaces/sso -run 'CIBA|Ciba'
make ci
```

Both repeat commands retain the 120s per-test-binary bound and 180s whole-command
capture window. The legacy name selection is unchanged, not renamed or reduced;
new request-admission tests have their own endpoint-specific names/selection.
Full CI still runs every package together with race enabled. Preserve any timeout
or failure; do not increase bounds, relax assertions or drop selected cases.

## Rollout and explicit non-goals

Existing clients that deliberately restrict grants but rely on CIBA initiation
now fail closed. Review/update real client registrations only through separate
explicit authority; these changes never reconfigure them. No automatic rollback
or migration of existing request/token state occurs.

Not certified here: stock runtime or historical identities; Redis/PostgreSQL
CIBA storage; HA, external notifications or production; actual-time expiry or
crash/recovery; grant admission for other protocols; revalidation after approval
or client-policy mutation; revocation/reconciliation of already-pending requests;
new offline-scope policy; Step32 original idempotency cause. Independent security,
integration and release review remain required before any merge/deployment.
