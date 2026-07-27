# ADR-0003 — Protocol packages are physically grouped

## Status

Accepted; supersedes the former “keep protocol packages flat” decision.

## Context

OAuth, OIDC, SCIM, FAPI, CAEP/SSF, self-service, compliance, lifecycle
reactions, and outbound SCIM provisioning are use-case/protocol orchestration.
The project originally kept these packages flat to preserve import paths, then
executed the layered-topology migration summarized in
[`docs/HISTORY.md`](../HISTORY.md).

## Decision

Root-module protocol packages live under `protocols/`:

```text
protocols/
  oauth  oidc  scim  fapi  caep  selfservice
  compliance  lifecyclereactions  scimprovision
```

Optional adapters that carry heavy third-party dependencies remain nested
modules under `infrastructure/` (`saml`, `ldap`, `kerberos`, `radius`,
`extauthz`, and others). Their responsibility is concrete integration, not
root-module protocol orchestration.

`protocols/oauth` and `protocols/oidc` remain mutually independent; shared wire
types and interfaces move downward instead of crossing between them.

## Consequences

- Protocol code is navigable by responsibility and automatically classified
  by its first path segment.
- Existing consumers of former flat paths had to update imports.
- Adding a root-level `oauth`, `oidc`, `scim`, or similar compatibility package
  would reverse the migration and is not allowed without a public API decision.

## Enforcement

- `architecture_gate_test.go`
- `architecture_layer_test.go`
- [directory map](../architecture/DIRECTORY_MAP.md)
