# ADR-0008 — Proto API versioning strategy

## Status

Accepted (2026-06-29). Partially implemented: all current proto packages are
stable `v1`; HTTP version negotiation, deprecation headers, and one opt-in
`v2alpha` proof route exist. No `v2alpha`/`v2beta` proto service has shipped.

## Context

All admin, audit, authz, and discovery protos are published as `v1`:

```
proto/admin/v1/{clients,keys,permissions,releases,snapshots,tenants,tokens,users}.proto
proto/audit/v1/audit.proto
proto/authz/v1/authz.proto
proto/discovery/v1/discovery.proto
proto/netpolicy/v1/netpolicy.proto
```

Every current proto carries a stable-package header. There are no deprecated
fields/messages and no preview proto directories because no breaking successor
has been introduced. The HTTP Server already supports opt-in `Accept-Version`
negotiation, `Deprecation`/`Sunset` headers, and
`GET /api/v2alpha/version` as a proof of the preview-path mechanism.

A `proto-breaking` Make target can run
[`buf breaking`](https://buf.build/docs/breaking/overview) against `main`. It
is not part of default `make ci`:

```makefile
proto-breaking: ## Check proto wire-breaking vs main.
	cd proto && $(GO) run github.com/bufbuild/buf/cmd/buf@latest breaking \
		--against "../.git#branch=main,subdir=proto"
```

The detection exists, but there is no documented policy for what constitutes a breaking change, how to handle one when it is detected, or how consumers should prepare for a future major version.

## Decision

Adopt Google's API versioning conventions for gRPC (as documented in the [Google API Improvement Proposals](https://aip.dev/)) with four tiered stability levels:

| Version | Stability | Guarantees | Lifespan |
|---------|-----------|------------|----------|
| **v1** | Stable | Fully backward-compatible. Fields may be added but never removed or change type. | Indefinite |
| **v2alpha** | Preview | Breaking changes allowed freely. Clients must opt in explicitly. No compatibility guarantees. | Until v2beta cut |
| **v2beta** | Nearly stable | Wire-compatible with v2alpha (same wire format). Not wire-compatible with v1. | ≤ 2 releases, then v2 |
| **v2** | Stable | Same guarantees as v1. v1 deprecated but continues to work for ≥ 6 months. | Indefinite (replaces v1) |

### Version progression lifecycle

1. **Prototyping** — work happens in `v2alpha` protos. Everything is provisional.
2. **Stabilisation** — a `v2beta` branch is cut from `v2alpha`. Wire format is frozen; only additive changes are permitted. Bug fixes are cherry-picked from the `v2alpha` line. The `v2beta` phase lasts at most two releases.
3. **Release** — `v2beta` graduates to `v2`. The `v1` package enters a 6-month deprecation window.
4. **Cleanup** — after the deprecation window expires, `v1` protos and their serving paths may be removed in a coordinated release.

## Rules

1. **Adding a field to v1** — always allowed. This is backward-compatible per proto3 semantics. New fields must use field numbers outside the `reserved` range.

2. **Removing a field from v1** — the field must first be annotated `reserved` for one full release cycle (to prevent accidental reuse of the field number), then removed in the NEXT major version. Both the field name and the field number must be reserved.

    ```protobuf
    // Before removal (v1):
    reserved 9, 10;
    reserved "old_field", "obsolete_flag";
    ```

3. **Changing a field type** — MUST use a new field number. The old field is deprecated with `deprecated = true` and listed in `reserved` in the next major version.

    ```protobuf
    // v1 — old string field, deprecated:
    string user_id = 5 [deprecated = true];
    // v1 — new int64 field, replaces user_id:
    int64 user_id_int = 12;
    ```

4. **Deprecation annotations** — every deprecated field, message, enum value, or RPC must carry `deprecated = true`:

    ```protobuf
    message OldConfig {
      option deprecated = true;
      // ...
    }
    rpc LegacyLookup(LegacyRequest) returns (LegacyResponse) {
      option deprecated = true;
    }
    ```

5. **Preview paths** — `v2alpha` protos live under `proto/*/v2alpha/` and are served at a `/api/v2alpha/*` prefix. `v2beta` protos live under `proto/*/v2beta/` and are served at `/api/v2beta/*`.

    ```
    proto/admin/v2alpha/
    proto/admin/v2beta/
    ```

6. **Breaking changes** MUST NOT be introduced without a documented migration path in the proto file header comment and, for user-facing APIs, in a companion migration guide under `docs/migrations/`.

7. **Version policy header** — every `.proto` file MUST carry a header comment documenting the version's stability level per this ADR:

    ```protobuf
    // Package admin/v1 — STABLE.
    // See docs/adr/ADR-0008-proto-versioning.md for the versioning policy.
    // Breaking changes are not permitted in this package without a minimum 6-month deprecation window.
    ```

8. **buf configuration** — `proto/buf.yaml` / `proto/buf.gen.yaml` and CI must
   keep stable `v1` packages under breaking-change protection. Add
   preview-specific rules when the first preview proto package is created.

## Consequences

### Positive

- **Clear contract** for API consumers. Every proto file header states its stability level, and the ADR defines exactly what each level means.
- **Safe iteration** on admin, audit, and authz APIs. `v2alpha` gives us a sandbox to experiment without breaking production consumers.
- **buf CI integration** with an explicit policy. The existing `proto-breaking` Make target becomes more useful because we can configure different rules for stable vs preview packages.
- **Gradual deprecation**. Consumers get a minimum 6-month migration window when a major version ships.

### Negative

- **More proto files to maintain** during transition periods. Two or three active versions of the same service may coexist for several releases.
- **v2alpha/v2beta routing complexity**. The gateway or gRPC mux must dispatch requests to different implementations based on the URL path prefix. This is routine but still needs explicit plumbing.
- **Documentation overhead**. Migration guides and changelogs must be maintained per-version.

## Compliance

This ADR is enforced by code review and protocol tooling. There is no custom
lint rule that validates every lifecycle statement, so compliance depends on:

- **Code reviews** verifying that new proto additions follow the rules above.
- **The `proto-breaking` Make target** (buf breaking against `main`) when run
  for a proto change; default `make ci` performs proto linting but not this
  comparison.
- **Server integration tests** for `Accept-Version`, deprecation headers, and
  the opt-in `v2alpha` proof route.
- **Manual audit** before each release to confirm deprecation windows are honoured and reservation annotations are in place.

If a future gate (e.g. a `buf lint` rule or a committed check script) can enforce parts of this policy automatically, it should be added and this section updated.

---

*See [ADR-0003](ADR-0003-protocol-grouping.md) for the protocol grouping conventions this versioning scheme extends.*
