# Feature Request: OIDC Front-Channel Logout

## Background

Snaplink is an API-only OIDC SSO server. RP-Initiated Logout
(`protocols/oidc/handle_end_session.go`) terminates the OP session and
notifies relying parties via back-channel logout. Several existing
deployments use simple HTML front-ends that cannot hold a back-channel
endpoint, so sessions at those RPs stay alive after the OP session ends.

## Goal

Support OIDC Front-Channel Logout 1.0: after end_session, the user agent
loads a hidden iframe per registered RP that polls a logout status
endpoint; the RP clears its local session when the frame reports the OP
session ended. The feature must not regress the existing back-channel
path or the session management spec compliance.

## Non-goals (for this iteration)

- No hosted login UI (frontends are separate projects).
- No automatic RP registration; RPs declare front-channel URIs in their
  client config.
- No session management spec (opbs/iframe) work in this change.

## Acceptance criteria

1. `end_session` response includes the front-channel logout URIs for the
   session's RPs when configured.
2. New logout-status endpoint answers `{ "sid": "..." }` with `Cache-Control:
   no-store`; unknown/expired sessions return the same payload shape (no
   oracle).
3. Existing back-channel logout and OIDC conformance suites stay green.
4. New endpoint and config keys are documented in OpenAPI and
   config-reference.

## Out of scope

Protocol-level review, threat model, implementation plan, and test strategy
are produced by the downstream SDLC stages (see
`ai-dev/examples/sdlc-mini-pipeline.yaml`).
