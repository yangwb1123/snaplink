# ADR-0003 — Protocol packages stay flat (no `protocols/` grouping)

## Status

Accepted.

## Context

A "cognitive complexity" guideline suggested grouping the protocol
implementations under a `protocols/` (and `platform/`, `domains/`) parent to
reduce the apparent number of root modules:

```
protocols/oauth  protocols/oidc  protocols/saml  protocols/scim
```

Today these live flat: `oauth/` and `oidc/` in the main module, `saml/` and
`scim/` (`saml/` is its own nested `go.mod`). They are individually cohesive,
gate-clean, and correctly separated (`oauth ↮ oidc`, ADR-0002).

The 2026-06-19 audit found grouping to be net-negative here:

- `oauth/` is imported by ~106 files, `oidc/` by ~42. Re-pathing them to
  `protocols/...` is a breaking API change for every embedder.
- The architecture gate keys on **literal** path prefixes (`"oauth/"`,
  `"oidc/"`) and on relative-path exemption keys. A rename that doesn't update
  the gate test atomically either reds CI or **silently disables the
  `oauth↔oidc` cycle guard**.
- `oauth/handle_register.go` sits at exactly 500 lines; any incidental reformat
  during a mass rename trips the file-size gate mid-migration.

The "too many root modules" concern is also miscounted for a library: distinct
import paths are a feature (consumers import exactly the protocol they need),
not cognitive overhead to be hidden.

## Decision

Keep `oauth/`, `oidc/`, `saml/`, `scim/` **flat at their current import paths**.
Do not introduce a `protocols/` grouping directory. The same applies to the
nested protocol/auth modules (`ldap/`, `kerberos/`, `radius/`, `extauthz/`):
their `go.mod` boundary already provides isolation, and their module path
encodes their location.

## Consequences

**Pros** — zero consumer breakage; the path-keyed gates stay valid; no atomic
gate-rename hazard.

**Cons** — the root keeps four protocol directories visible; accepted as a
library, not hidden.

**Risks** — none introduced. If grouping is ever desired it is a v2-major
concern executed with deprecation aliases and a same-commit gate update.

## Enforcement

Indirect: ADR-0002's `architecture_gate_test.go` would break loudly on a
careless protocol rename, which is precisely why this decision is recorded.
Manifest: [`.arch/rules.yaml`](../../.arch/rules.yaml) `protocols:`.
