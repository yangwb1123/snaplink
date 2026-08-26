# Signed audit checkpoint producer wiring

## Evidence baseline

At the current HEAD, `platform/audit/chainer.go` is exactly 500 lines and already
contains `ChainTip`, `CheckpointStore`, the signed-checkpoint wire types, and the
`Notary`/`StartNotary` loop. The SQLite audit sink (migration v4) and the
PostgreSQL audit sink (schema migration v3) already persist the independent
`audit_checkpoints` table. `grep` of production Go files shows no existing
`sso-server` caller of `StartNotary` or `NewNotary`; existing references are
implementations and tests. The preceding durable-storage batch is therefore a
storage dependency of this change, not a migration to repeat.

## Configuration and key format

`audit.notary` is default-off and has `enabled`, `interval`, and `key_file`.
When enabled, `audit.enabled` and `audit.hash_chain` must both be true, the
primary `audit.backend` must be `sqlite` or `postgres`, and `key_file` must be a
non-empty absolute path. A non-positive interval keeps the existing Notary
five-minute default.

The operator provisions `key_file` out of band as a PEM `PRIVATE KEY` block
whose bytes are an x509 PKCS#8 Ed25519 private key. The loader rejects an empty
file, missing/extra PEM data, another PEM type, malformed PKCS#8, and every
non-Ed25519 algorithm. It never generates, writes, or places the private key in
YAML. This key is held by a small server-composition signer and is independent
of the token signing issuer/registry. Logs may identify the backend, path, and
public key, but never private material.

## Startup and storage selection

The wiring validates the same prerequisites again at the build seam, then
constructs the recorder and raw primary sink. Only that raw primary is eligible
for notarization: it must implement both `audit.ChainTip` and
`audit.CheckpointStore`. The raw SQLite/PostgreSQL sink is passed to
`StartNotary`; a memory sink, a fan-out, or any unsupported composition fails
boot clearly rather than silently selecting `MemoryCheckpointStore`.

The Notary uses the existing durable `Latest` recovery and `Append` behavior.
It signs the existing checkpoint JSON, writes only to `audit_checkpoints`, and
advances its in-memory sequence/head only after append succeeds. The Recorder's
hash-chain head is never updated by checkpoint success.

## Lifecycle and shutdown order

The producer starts only after the recorder and raw primary have been built.
Its cancel-and-done pair is composed into the existing audit cleanup closure,
which is also used for build-failure cleanup. This preserves an already-wired
external audit worker close instead of overwriting it. A build failure cancels
and waits for the producer before the primary is released.

Normal shutdown keeps the existing order: stop/drain the async Recorder sink,
then close exporters and the Notary, then close the raw primary database. The
Notary cancel is waited on under the shared shutdown deadline. The first Notary
attempt remains immediate; an unchanged head remains a no-op.

## Failure, concurrency, and HA semantics

Key loading, invalid configuration, and an unsupported raw sink are boot
failures. Runtime `ChainTip`, signing, and checkpoint-store errors retain the
existing Notary fail-open behavior: they are logged and produce the existing
failure audit event through `EventAuditChainCheckpoint`; the primary Recorder
is not blocked. A successful checkpoint produces no success audit event because
writing one through the chained Recorder would change the head it just attested.

One Notary serializes its checkpoint attempts. Across replicas, the existing
checkpoint sequence primary key exposes same-sequence races as append errors;
there is no new lease, CAS protocol, or leader election. Operators must run one
active producer for a shared audit database. SQLite keeps its existing
single-writer behavior, while PostgreSQL transaction/migration behavior does
not imply producer ownership.

## Compatibility, migration, and rollback

With `audit.notary.enabled` absent or false, no key is read, no signer is built,
no goroutine is started, and the existing audit Recorder/sink composition is
unchanged. Enabling it is additive and uses the already-applied checkpoint
schema; no schema version is added in this batch. Rollout requires provisioning
the stable key first, applying the configuration, and then restarting. Rollback
is disabling the flag and restarting; existing checkpoint rows remain harmless
and can be retained for later verification. Schema rollback remains the
previous batch's restore-from-snapshot procedure, not a down migration.

## Explicitly not done

This batch adds no new `EventType`, no success-event/hash-chain Recorder
write-back, no metrics, no checkpoint HTTP endpoint, no external exporter or
network channel, no object storage, no key download/refresh, and no leader
(election) mechanism. It also adds no CLI flag and does not alter the existing
PostgreSQL environment-gated test posture.
