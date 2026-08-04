# Profile physical isolation and edition evidence (P0-5)

The public edition hierarchy is `prototype → minimal → full`. The two
smaller editions share one binary (`cmd/sso-minimal`, selected by
`--edition`); `full` is the complete stock composition (`cmd/sso-server`).
This document records what physical isolation means, how it is proven, and
what the full profile proves against durable state, security controls,
observability and topology.

## The isolation boundary

`go list -deps` is the ground truth. Measured at the time of writing:

| Binary | Snaplink packages | Symbols | Size |
|---|---:|---:|---:|
| `sso-minimal` (prototype + minimal) | 95 | ~35.1k | ~34.2 MB |
| `sso-server` (full) | 180 | ~73.5k | ~68.1 MB |
| `snaplink-billing` (billing) | 109 | ~38.0k | ~34.7 MB |

The small binary links the protocol SDK (`interfaces/sso`), the identity
and OAuth memory stores (`infrastructure/defaultimpl`), password
authentication (`domains/authenticators`), the Ed25519 JWT issuer
(`defaultimpl.NewEd25519JWTIssuer`) and the OIDC protocol
(`protocols/oidc`). It does NOT link:

- durable stores: `infrastructure/{redis,postgres,sqlite,sms,emailsmtp}`,
  `identitylinkpostgres`, the `*/sqlite` and `*/memory` store variants that
  only the full composition wires;
- the admin plane: `interfaces/grpcserver`, `gen/proto/*`,
  `interfaces/snapshot`, `platform/bootstrap`, `platform/registry`,
  `platform/releases`;
- heavy protocol surfaces: `protocols/scim`, `platform/netpolicy/*`;
- configuration: `config/*` (the small editions have their own flags/env);
- the extension host API: `interfaces/ssoext` (only `cmd/sso-server`
  consumes registered SAML/signer factories).

The protocol SDK itself is deliberately shared: `interfaces/sso` is the
product's SDK surface, and the editions are compositions of the same SDK
with fewer options wired. Physical isolation therefore targets the
infrastructure/admin/durable graph, not the SDK. The boundary is declared
in `ops/build/profile-isolation.json` and enforced by
`python cli.py profiles evidence` — an accidental import that drags
postgres or the admin gateway into the small binary fails the check.

The independent `billing` profile has a narrower, different assertion. It
must link the tenant-commerce and usage-ledger domains, their PostgreSQL
stores, the billing HTTP interfaces and Audit Governance relay, while it must
also link the typed entitlement-to-SSO quota projection client. It must not
link either SSO command composition, admin gRPC, snapshots, bootstrap,
releases or SCIM. Shared SDK packages reached through its Snaplink token
client are not claimed to be physically absent. This proves an independently
buildable process boundary; it does not classify billing as hot or include it
in the `full` SSO edition. An empty quota base URL keeps the compiled worker
inactive; endpoint/audience/credentials are cold configuration, not an
installable plugin.

## Reproducing the evidence

```bash
python cli.py profiles evidence            # build + assert + archive
python cli.py profiles evidence --skip-build  # re-verify the last bundle
make profiles-evidence
```

Every run archives, under `dist/profiles/<binary>/`:

- `packages.txt` — the snaplink package inventory (`go list -deps`);
- `module-sbom.txt` — the binary's actual module versions (`go version -m`);
- `symbols.txt` / `size.txt` — `go tool nm` count and binary size;
- `evidence.json` — machine-readable bundle (sizes, counts, violations).

The assertion gate is the manifest's `must_link` / `must_not_link` prefix
lists per profile. Both directions are checked: a required package missing
from the small build is as much a violation as a forbidden one present.

## Full-profile evidence

The `full` profile's claims are proven as follows:

- **Durable state**: the full binary links `infrastructure/postgres`,
  `infrastructure/redis`, `infrastructure/defaultimpl/sqlite` and the
  per-store sqlite/redis/postgres variants (proven by `profiles evidence`
  `must_link`). Behavior against those backends is exercised by the
  package suites (`infrastructure/postgres`, `infrastructure/redis`,
  `domains/tenant/sqlite`, ...) and the cross-server E2E suite
  (`go test ./test/ -run TestE2E`).
- **Security controls**: FIPS policy (`shared/security/fipspolicy` is
  full-only and linked), admin RBAC (`gen/proto/authz`), key rotation and
  the signing-key registry (`platform/signingkeys/*`), snapshot encryption
  (`interfaces/snapshot/encryption*`) — all linked only in the full
  binary, all with dedicated suites in their packages.
- **Observability**: audit sinks (`platform/audit/*` incl. sqlite + the
  Kafka cold module), metrics, tracing, cluster bus
  (`platform/cluster/{memory,etcd}`), config audit (`platform/configaudit`).
- **Supported topology**: the full HA/OpenResty Kubernetes stack is
  committed under `deploy/` and rendered/validated by
  `make k8s-render` / `make k8s-diff`; leaderless replica coordination
  (`platform/cluster/memory`, `platform/signingkeys/memory`,
  `platform/registry/memory`) is exercised by the invalidation-bus and
  signing-key adoption tests.

## Extension and hot-capability rules

- `oauth-client-credentials` remains an independent optional
  machine-to-machine module: `kind: cold`, `state: planned`,
  `conflicts: stock-server`, `removable: true`, requiring only base SPIs
  (`access-token.issuer.v1`, `client.store.v1`, `oauth.token-host.v1`,
  `security.policy.v1`) — it is not a profile foundation.
- SAML, LDAP/Kerberos/RADIUS, KMS/HSM and the other nested modules are
  separate Go modules by construction; the standard host API for
  operator-registered factories is `interfaces/ssoext` (typed registrars on
  `platform/registrar`) and the module catalog (`ops/build/modules.json`).
  Migrating the remaining nested modules onto that host API proceeds once
  the boundary is stable.
- No in-process capability is classified as hot: activation is
  `restart`-only, generation leases and static route slots are required
  before any hot classification, and installable third-party code must run
  out of process over the typed authenticated protocol (see
  `docs/plugin-system.md`).
- Release artifacts: `python cli.py configure` produces profile locks and
  cold-build overlays under `dist/`; per-profile binary SBOMs and size
  deltas are archived by `profiles evidence`; signing and provenance of
  release binaries is the release pipeline's job (see `docs/RELEASE.md`).
