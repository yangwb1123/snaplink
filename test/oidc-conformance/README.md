# OIDC Conformance Test Suite

This directory is a **manual scaffold** for running the
[OpenID Foundation's Conformance Test Suite](https://gitlab.com/openid/conformance-suite)
against the SSO server.

> **No conformance claim:** this harness is not part of `make ci`, requires
> browser interaction, and has no committed pass report or certification
> artifact. “Implemented in the server” is not equivalent to “passed the OIDF
> suite,” and snaplink must not be described as OIDF-certified on the basis of
> this directory.

## Current scaffold status

The checked-in Compose file is **not runnable as-is**:

- it references a repository-root `Dockerfile.test` that is not present;
- `config.env` is not interpolated by `docker-compose.yml`, so editing it does
  not currently change the services; and
- several `SSO_*` names in the Compose environment predate the current nested
  configuration mapping.

Before using the scaffold, update it to build the root `Dockerfile`, mount a
validated current server configuration, and explicitly wire every test
parameter. Validate that configuration with:

```bash
sso-ctl config validate --file <conformance-config.yaml>
```

The authoritative configuration keys are documented in
[`docs/config-reference.md`](../../docs/config-reference.md). The broader
manual certification procedure and current certification status are in
[`docs/sso/oidc-conformance.md`](../../docs/sso/oidc-conformance.md).

## Manual execution after scaffold repair

Once the Compose wiring has been repaired and reviewed:

```bash
docker compose up -d --build
docker compose logs -f conformance-suite
```

Open `http://localhost:8080` and:

1. Create a new test plan
2. Select only the modules enabled in the server-under-test configuration
3. Point the suite at `http://sso-server:8080` on the internal Docker network
4. Enter the RP's test client credentials (created automatically by the suite)
5. Run the tests
6. Export and archive the exact plan, server commit/configuration, and results

For certification-quality evidence, use an externally reachable HTTPS issuer
and the OIDF-required redirect/browser setup rather than treating this
HTTP-only local topology as the final environment.

## Troubleshooting

- Server startup: `docker compose logs sso-server`
- Redirect/network failure: verify the issuer and server URL are reachable from
  the conformance container.
- Database failure: `docker compose logs conformance-db`

Profile support and certification status belong only in
[`docs/sso/oidc-conformance.md`](../../docs/sso/oidc-conformance.md).
