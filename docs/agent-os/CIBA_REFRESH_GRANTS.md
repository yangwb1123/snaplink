# CIBA initial refresh: explicit client grant restrictions

## Goal and product boundary

An operator-provisioned client with a nonempty `GrantTypes` that excludes exact
`refresh_token` must not receive an initial CIBA refresh credential or create its
managed store/audit side effects. CIBA poll, ping collection and push share the
existing builder, so the restriction belongs in
`internal/handler/tokengrant/token_ciba.go::cibaIssueRefresh` (interface layer),
not in an HTTP-only adapter or notifier. Empty grant lists preserve unrestricted
legacy behavior. This is a bounded client-policy hardening, not a claim that
CIBA Core requires an `offline_access` scope.

Surface: embeddable Server and existing opt-in stock CIBA composition. No new
endpoint, default, feature flag, option, package, SPI, schema or dependency.
Existing downward dependencies and the `slices` import suffice. Production Go
file/function/complexity/nesting and directory ceilings remain unchanged.

## Acceptance

- Nonempty client grant lists must contain exact `refresh_token`. CIBA alone,
  unrelated grants, case aliases, substrings, whitespace and unsplit entries do
  not authorize it. An `offline_access` scope cannot override this restriction.
- Denied grants return before the refresh-store accessor, issue operation or
  issuance event. Responses omit the refresh key, not an empty credential.
- Nil/empty grant lists and explicitly permitted refresh grants retain current
  CIBA scope semantics, including existing no-offline refresh issuance. Choosing
  a new CIBA offline-scope policy remains a separate product/security decision.
- A wired store remains required. Never forward an issuer-provided refresh value,
  even when storage is unwired or authorized managed issuance fails. Preserve
  the exact failure log and log-and-omit behavior without undoing the consumed
  CIBA request or substituting another credential.
- Access and explicitly requested OpenID ID issuance remain independent. Preserve
  approved subject/client/provider, scopes/resources, ACR/authentication time,
  sender constraint, client TTL, empty initial family/SID/details/attributes and
  initial issuance events (`rotation=false`). Never use the RP nonce as a family.
- Poll and push must enforce the same refresh policy. Preserve single-use claim,
  client binding, pending/denied/slow-down/expired responses, push bearer semantics,
  cache headers, notification credentials and existing-family rotation. No new
  offline-scope gate on existing-family redemption.
- Real-memory HTTP flows and owned disposable SQLite flows must exercise the
  restriction without widening client policies or weakening existing assertions.
  They do not certify Redis/PostgreSQL CIBA storage, multi-process/HA, production
  callbacks, remote notification delivery or historical credentials.

Applicable evaluation: O8/O10 and S2/S3/S4; retain the existing CIBA-specific
`expired_token` replay contract rather than misreporting it as O1 `invalid_grant`.
Universal build/vet/committed architecture/maintainability gates and full `make ci`
remain authoritative. Run targeted tests, race repetitions, product E2E, all
engineering checks and supplementary acceptance with the required owned PG test
fixture; no missing-engine skip or budget/threshold changes.

## Files and compatibility

Create `token_ciba_refresh_grant_test.go` beside the handler and
`test/ciba_refresh_grant_test.go`; modify only the initial refresh guard and its
comments in production. Synchronize this document, checks registry, frontend and
OpenAPI descriptions; regenerate SDK-derived contracts if affected. Preserve all
predecessor source paths and use an independent worktree.

Clients that explicitly deny the refresh grant stop receiving that unusable
credential; add `refresh_token` only through a separately authorized client-policy
change if offline CIBA refresh is desired. Existing refresh families are not
revoked. No production clients are reconfigured by this implementation.

## Non-goals and evidence limits

No new CIBA offline-access requirement, broader CIBA grant admission policy,
WebAuthn/token-exchange policy change, device/code/direct-login policy change,
browser anchoring, SVERP 30-day-session change, import/replay, historical-runtime
recertification, migration, production operation, integration, release or cutover.
Step32's original idempotency failure remains unexplained; later passing tests
are not its diagnosis or repair. The finite migration Python complexity list is
empty, not whole-repository maintainability certification. Synthetic fixtures and
self-verification are not independent security/integration approval.
