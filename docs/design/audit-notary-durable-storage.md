# Durable audit-notary checkpoints

## Scope and baseline evidence

This batch adds durable storage and restart continuity only. The statements in
this section describe the pre-change baseline (HEAD^), not the post-change
implementation. At that baseline, `platform/audit/chainer.go` contained the
`CheckpointStore` interface, `MemoryCheckpointStore`, signed checkpoint wire
types, and `NewNotary`; `grep` showed no production caller of `NewNotary` or
`StartNotary`, and no durable `CheckpointStore` implementation.
The requested `docs/design/audit-chain.md` is absent in this checkout, so this
design relies on the executable code and the direction-one evidence in the
requested scan document rather than treating that missing document as a
contract. Existing chain recording and checkpoint JSON/signing remain
unchanged.

## Storage shape and migrations

Both durable sinks add an independent table; checkpoints are never inserted
into `audit_events`.

- SQLite audit migration v4, `add_audit_checkpoints`, creates
  `audit_checkpoints(sequence INTEGER PRIMARY KEY, ts_unix_ns INTEGER NOT NULL,
  head_hash TEXT NOT NULL, prev_hash TEXT NOT NULL, signature BLOB NOT NULL,
  signer_key BLOB NOT NULL)`.
- Postgres audit migration v3, `add_audit_checkpoints`, creates the equivalent
  table with `sequence BIGINT PRIMARY KEY`, `ts_unix_ns BIGINT`, text hash
  columns, and `BYTEA` signature/key columns. The existing Postgres migration
  runner still splits and executes the parameter-free DDL using its dialect
  and advisory-lock/serialization retry rules.

The sequence primary key is the durable uniqueness boundary. `Append(nil)` is
rejected with an explicit error. A repeated sequence is rejected by the
primary-key conflict and returned as a store error; it is not an upsert and
never overwrites an attestation. A non-nil checkpoint's signature and signer
key are stored as opaque byte values and read back as independent byte slices.
The store does not re-sign, normalize JSON, or silently validate a checkpoint;
`Notary` validates the latest record before using it for recovery.

Existing audit migration rows and event columns are untouched. Forward
migration is transactional in SQLite and in the Postgres runner. A rollback
is restore-from-snapshot, not a down migration; an older binary that does not
know the new migration must not be used against a schema ahead of it through
its read-only schema-checked path.

## Read and ordering contract

`Latest` orders by `sequence DESC` and returns `(nil, nil)` when the table has
no rows. `List(ctx, since, limit)` applies an inclusive timestamp predicate
(`ts_unix_ns >= since.UnixNano()` when `since` is non-zero), returns
`sequence ASC`, and applies `LIMIT` only when `limit > 0`; a non-positive limit
means unlimited. An empty result is a non-nil empty slice where the backend
can provide one, with no synthetic genesis checkpoint. All variable values
use SQL parameters; only fixed SQL identifiers and the integer limit are
constructed by the implementation.

A nil or closed sink returns an explicit closed-store error for Append,
Latest, and List. Context cancellation and database errors are returned rather
than converted to an empty result. A malformed or bad-signature row remains
observable through storage/List; it is not repaired or deleted by a read.

## Restart recovery

`NewNotary` performs one best-effort `Latest` read from the supplied store
before returning. If no row exists, it retains `lastSigned == GenesisHash`
and `lastSeq == 0`. If a row exists and
`VerifyCheckpointSignature` succeeds, it sets `lastSigned` to the stored
`HeadHash` and `lastSeq` to the stored `Sequence`. If the read fails or the
signature is invalid, it logs an error when a logger is supplied and keeps
those genesis values. Bad data therefore cannot advance the next sequence or
become the next checkpoint's `PrevHash`; construction remains fail-open.

The first later `CheckpointNow` still reads the live `ChainTip`, preserves the
unchanged-head rule, signs the existing checkpoint JSON with the existing
algorithm, and only advances in-memory state after durable `Append` succeeds.
A durable restart with a valid latest checkpoint consequently emits
`latest.Sequence + 1` and points `PrevHash` at `latest.HeadHash`. Checkpoint
success is not recorded back through the hash-chain `Recorder`, because that
would change the head just attested. Storage failures remain notary failures
(and failure audit/logging follows the existing path) but never block the
primary audit Recorder.

## Concurrency and HA boundary

The Notary mutex serializes `CheckpointNow` calls within one Notary. The
checkpoint table's primary key prevents silent overwrite across replicas,
but this batch does not introduce a distributed lease or compare-and-swap
protocol: two HA notaries can both recover the same latest row, race to sign
sequence `latest+1`, and one append can fail with a duplicate sequence. That
failure is fail-open and must be audited/logged; operators need one active
producer until a later producer-wiring batch defines HA ownership. SQLite keeps
its existing single-writer/lock behavior. Postgres transactions and the
migration runner provide database serialization, not Notary leader election.

Checkpoint signature verification is deliberately at the trust boundary
(`NewNotary` recovery and existing verification APIs), not a storage-side
wire rewrite. A valid signature on semantically nonsensical but otherwise
well-formed data is still treated according to the existing signature
primitive; storage does not invent new checkpoint fields or protocol rules.

## Compatibility and explicit non-goals

This is additive: the `CheckpointStore` interface, Memory implementation,
checkpoint JSON, Ed25519 algorithm, `CheckpointNow` unchanged-head behavior,
`audit_events` schema/queries, CLI verification behavior, and event registry
are unchanged. No server, `sso-server` producer wiring, configuration key,
route, OpenAPI surface, event type, external object store, notary network
channel, or checkpoint write-back to the hash-chain Recorder is included.
The future producer batch can construct a durable SQLite or Postgres store and
call the existing Notary API without another wire migration.
