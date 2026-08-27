# Read-only audit export from the latest durable checkpoint

## Current-state evidence

The audit exporter already supports a file checkpoint through `--anchor`: it
reads the JSON once, verifies the embedded Ed25519 signature, builds a bundle
from the selected source, and rejects a head mismatch before writing the
bundle. The shared `cmd/auditstore.OpenReadOnly` opener already selects the
SQLite or PostgreSQL read-only, non-migrating constructor. Both durable sinks
already implement `Latest(context.Context)` and persist `SignedCheckpoint`
rows in the existing `audit_checkpoints` table. `sso-server` producer wiring
already writes those rows; this seam only makes the existing durable evidence
reachable from the CLI.

## Flag and mode semantics

`--anchor-latest` is a boolean export modifier, not a new source. It is valid
only with `--dsn`; it is invalid with `--from-url`, `--verify`, or an explicit
`--anchor` file. Misuse returns the existing CLI usage exit code 2. With
`--dsn --anchor-latest`, the command opens the selected read-only store, reads
one latest checkpoint, verifies its signature, builds the normal export, and
embeds that exact checkpoint only if the bundle head equals the attested head.
No checkpoint is silently treated as an unanchored export: `Latest == nil`, a
store error, a signature error, or a head mismatch is a runtime failure (exit
1), before bundle output.

Without `--anchor-latest`, parsing, source access, export ordering, output, and
exit behavior remain the existing behavior. `--anchor <file>` retains its
read-once-before-open and signature-check ordering. `--verify` remains offline
and unchanged; it does not infer or fetch a checkpoint.

## Read-only and dialect boundary

The CLI continues to call exactly `auditstore.OpenReadOnly(dsn)`. SQLite is
opened with the existing `auditsqlite.OpenReadOnly`; PostgreSQL uses the
existing non-migrating `postgres.OpenAuditReadOnly`. After opening, the CLI
uses only this narrow structural reader:

```go
type latestCheckpointReader interface {
    Latest(context.Context) (*audit.SignedCheckpoint, error)
}
```

A type assertion on the already-opened concrete durable sink supplies this
reader. The CLI does not assert `audit.CheckpointStore`, import or expose its
`Append` operation, issue raw SQL, run migrations, or add a store opener. The
normal `Query` path remains the sole event-reading path, and `--from-url` has
no checkpoint operation or endpoint.

## Signature, head race, and export completeness

The stored checkpoint is verified against its embedded signer key before
bundle construction. The bundle's `HeadHash` must then equal
`SignedCheckpoint.Checkpoint.HeadHash` byte-for-byte, using the same
`enforceAnchorHead` relation as `--anchor`. This closes the last-event blind
spot without treating a checkpoint as a signer pin: the signer key is the key
carried by the checkpoint, as in the existing file-anchor path.

`Latest` and the subsequent event `Query` are separate read operations. If the
store grows, changes, or is filtered between them, the resulting bundle ends
at a different head and fails closed. A `since`, `until`, attribute filter, or
`limit` that does not produce the attested head likewise fails before output.
A limit is never relaxed, moved, or ignored to satisfy the checkpoint; an
attribute-filtered bundle retains the existing per-event verification rules.
The seam does not claim a database snapshot or distributed producer lease.

## Security and PII boundary

Checkpoint failures expose only operation-level diagnostics (open/read,
missing checkpoint, signature failure, or head mismatch); they do not print
checkpoint/event bodies, bearer tokens, or SQL row contents. The existing
summary remains stderr-only and contains bounded metadata. Bundle output keeps
its existing owner-only file mode and may contain audit PII. The feature adds
no HTTP route, raw query surface, token handling, signer-key pin registry, or
network call.

## Compatibility and rollback

The default unanchored path and explicit file-anchor path are additive and
wire-compatible. Existing bundles and offline verification remain valid.
Enabling the flag requires no migration because it reads the already-present
checkpoint table. Rollback is simply to stop passing `--anchor-latest` (or use
the existing file/unanchored modes); no rows or schema objects are changed by
the CLI. A live PostgreSQL round trip remains environment-gated by the
repository's existing DSN tests.

This seam makes no server, API, schema, or event changes. It adds no endpoint,
configuration key, error code, feature-registry entry, generated ID, or key
change.
