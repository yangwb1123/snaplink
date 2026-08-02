Evidence gathering complete. All claims verified against the code. Here is the requirements specification.

# Requirements Specification: interfaces/snapshot — 方向 2（凭据感知的恢复）

Scope: `interfaces/snapshot` expansion toward credential-aware recovery per `docs/auto/interfaces-snapshot-analysis.md` 方向 2. All three improvements are confined to the snapshot module's own boundaries (snapshotter/restorer/codec/redactor + optional store SPI seams); no credential material is added to the plaintext snapshot body.

## 1. Fresh-node client secret regeneration (客户端密钥再生)

**Name**: `Restorer` auto-rotates secrets for secret-less confidential clients after a fresh-node restore, and reports the regenerated credentials.

**Problem**: A snapshot never carries client credentials — `shared/core/types.go:24` marks `Client.Secret` (and `RegistrationAccessToken`) as `json:"-"`, so serialization strips them. On a fresh destination node there is no live record to backfill from: `interfaces/snapshot/restorer_clients.go:124` `preserveClientSecrets` returns `cl` untouched (Secret stays `""`) when `ClientStore.Get` fails with `sso.ErrNoSuchClient`. Result: after DR Level 3/4 recovery, every confidential client's `client_secret` grant is silently broken, the `Report` (`restorer.go:89`) has no field to flag it, and the restore path never invokes `ClientStore.RotateSecret` (`shared/core/spi.go:81`) even though the SPI and a gRPC wrapper (`interfaces/grpcserver/grpcadmin/admin_clients.go:271` `RotateSecret`) already exist. Operators must manually enumerate and rotate each client — an un-billed, error-prone step in the RTO budget.

**Evidence**:
- `shared/core/types.go:22-24` — `type Client struct { Secret string \`json:"-"\` }`
- `interfaces/snapshot/restorer_clients.go:124-155` — `preserveClientSecrets`; the `ErrNoSuchClient → return cl, nil` branch leaves an empty secret on fresh nodes
- `shared/core/spi.go:78-81` — `ClientStore.RotateSecret(ctx, clientID) (string, error)` exists, unreferenced by `interfaces/snapshot/`
- `interfaces/snapshot/restorer.go:89-109` — `Report` has no credential-recovery fields

**Proposed behavior**:
- Add an optional `SecretRotator` capability interface (type-asserted, mirroring the `TenantScopedClientStore` pattern in `spi.go`) that wraps `RotateSecret`; the restorer uses it only when the destination store implements it, so existing stores stay untouched.
- After a non-dry-run upsert, when the resulting client is `Active` and `Secret == ""` (i.e. preserve backfill found nothing), call `RotateSecret` for that client, evict cache entries, and record the `client_id` + new secret in the `Report` (new `CredentialRecovery` field listing rotated client IDs; secrets surfaced only through the RPC response, never in audit logs — consistent with `admin_clients.go:37` "secrets are never echoed").
- Dry-run counts these clients as `RequiresRotation` in `CategoryCounts` (new counter) without mutating the store.
- Rotation runs per-client, fail-closed per client but non-fatal to other categories: a rotation error is reported in `Report.Errors` and the client is left in the "needs rotation" state rather than aborting the whole restore.

**Acceptance check**: `interfaces/snapshot/restore_preserve_secret_test.go` gains a fresh-node case: seed a `MemoryClientStore` with a confidential client (secret never in snapshot), run `ModeReplace` non-dry-run restore → `ValidateSecret` succeeds with the rotated value, `Report` lists the client ID, dry-run reports the same client as `RequiresRotation` with zero store mutations; a store without the rotator capability restores unchanged (empty secret preserved, no panic).

## 2. WebAuthn credential portability (passkey 注册数据随快照迁移)

**Name**: New `webauthn_credentials` snapshot category — export/restore of public-key passkey records per user.

**Problem**: WebAuthn credential records (credential ID, COSE public key, sign counter, AAGUID) contain no secret material, yet they are entirely outside snapshot scope: `docs/dr-framework.md:46` explicitly lists "MFA enrollments" among resources the snapshot omits, and the `ResourceCategory` enum (`interfaces/snapshot/snapshot.go:119-128`) has no MFA category. After a Level 4 recovery, every passkey-enrolled user is locked out of passwordless/MFA login and must re-enroll manually — hours of human work that is easy to miss (missed = production incident). This is the asymmetry the analysis doc calls out: user password hashes travel through `CategoryUsers` (`restorer_users.go` `upsertUser` → `CreateOrUpdate`), but authenticator registrations do not.

**Evidence**:
- `domains/authenticators/webauthn/webauthn_types.go:52-66` — `UserStore` SPI: `GetByName`, `CreateUser`, `AddCredential`, `UpdateCredential`, `RemoveCredential`; the persisted `gw.Credential` is public-key material only
- `interfaces/snapshot/snapshot.go:119-128` — category enum lacks any MFA/webauthn entry
- `docs/dr-framework.md:46` — "MFA enrollments" listed among snapshot omissions
- `interfaces/snapshot/snapshotter.go:247-273` — exporter iterates only `Clients`/`Users`/etc.; no credential hook
- `domains/authenticators/webauthn/webauthn_memory_store.go` — `MemoryUserStore` demonstrates a complete per-user credential model already exists

**Proposed behavior**:
- New category `webauthn_credentials` (string-typed `ResourceCategory` per `snapshot.go` — additive, no schema bump needed for readers, but bump `SchemaVersion` to "3" for the new category set and keep v1/v2 readable per the documented v1/v2 compat rule).
- Snapshotter gains an optional `WebAuthnExporter` interface (type-asserted from the wired store, per AGENTS.md "implementation interface guards live with implementations"): `ListCredentials(ctx) ([]UserCredentialRecord, error)` where `UserCredentialRecord` = username/handle + credential ID + COSE public key + sign counter + extension metadata (`webauthn.CredentialExtensions`). Store implementations (memory, `webauthnpostgres`, `webauthnredis`, `webauthnsqlite`) add the exporter; absent exporter = category skipped, mirroring the existing "optional store ⇒ category omitted" pattern in `snapshotter.go`.
- Restorer replays records via `UserStore.GetByName` + `AddCredential` (insert-only for unknown credential IDs); fail-closed on counter regression: an existing credential whose stored counter is higher than the snapshot's is skipped and counted, never overwritten backwards (matches the "production clocks slew" discipline in AGENTS.md §3).
- `Report.Items[CategoryWebAuthn]` gets normal `inserted/updated/deleted/skipped` counts; `snapshot.go` `CategoryOrder` list gains the new category; redactor treats credential records as non-secret (no redaction), consistent with public-key material.
- Exclusion/`Exclude` handling and dry-run work like every other category.

**Acceptance check**: round-trip test: enroll a passkey via `webauthn.MemoryUserStore` (reuse `assertion_regression_test.go`'s `softwareAuthenticator`), export → restore into a fresh `MemoryUserStore` → `GetByName` returns the user with the credential and a successful assertion completes; restoring a snapshot with an older counter leaves the newer live counter intact (skipped count +1); a store without the exporter produces a snapshot with no webauthn category and a clean restore.

## 3. Encrypted, opt-in TOTP seed portability (TOTP 种子加密导出与恢复标记)

**Name**: Gated `totp_seeds` export under a dedicated encryption key + post-restore re-enrollment marker.

**Problem**: TOTP seeds are secret, MUST-encrypt material, and are completely absent from snapshots: `domains/authenticators/totp.go:58` `TOTPStore.GetSecret` returns raw secret bytes, and the memory backend's own comment says "TOTP secrets are MUST-encrypt material" (`MemoryTOTPStore` doc). The redactor's `secretUserAttrKeys` (`interfaces/snapshot/redactor.go:128`) covers only `password_hash`/`password_hash_format`/`seeded_password` — so user password verifiers ride along in `CategoryUsers` while TOTP seeds do not, and DR recovery leaves every TOTP-enrolled user locked out with no remediation step in the §6 runbook. Unlike WebAuthn (public keys), seeds cannot ride in the plaintext snapshot; they need the existing envelope-sealing machinery with a distinct key and an explicit operator gate.

**Evidence**:
- `domains/authenticators/totp.go:58-60` — `TOTPStore` interface; `MemoryTOTPStore` doc comment: "TOTP secrets are MUST-encrypt material"
- `interfaces/snapshot/redactor.go:123-128` — `secretUserAttrKeys` covers only password attributes; no TOTP/seed handling (and no category for it)
- `interfaces/snapshot/encryptionaesgcm/aesgcm.go` — existing envelope encryption (sealed envelope with checksum) that a second, purpose-separated key can reuse
- `docs/dr-framework.md:46` — "MFA enrollments" omitted from tier-1 snapshot
- `interfaces/snapshot/snapshotter.go` — exporter has no seed hook; `ResourceCategory` enum (`snapshot.go:119-128`) has no TOTP category

**Proposed behavior**:
- New category `totp_seeds`, exported **only** when (a) the wired `TOTPStore` implements an optional `SeedExporter` (`ExportSeeds(ctx) ([]SeedRecord, error)` — userID + raw bytes), (b) export options carry an explicit `IncludeCredentialSecrets` flag, and (c) the pipeline was configured with a sealer. Without all three, the category is silently absent (fail-safe default: seeds never leak into a plaintext or redacted snapshot).
- Seeds serialize as an encrypted payload inside the sealed envelope with a dedicated key purpose/context distinct from the snapshot body key (AES-GCM with a separate nonce/AD domain, reusing `encryptionaesgcm` primitives), so decrypting the body does not decrypt seeds.
- Redactor hard-refuses redacted exports containing seed material: `Compose`d redaction + seeds present → error, not silent scrubbing (redactor.go's own "MUST NOT redact" CRITICAL note at `redactor.go:25` for verifier-critical fields applies symmetrically here).
- Restore requires an explicit `RestoreOptions.RestoreCredentialSeeds` opt-in; when omitted, restore succeeds but the `Report` marks every user present in `totp_seeds` as `MFAReenrollmentRequired` (new `Report` field) so operators see the remediation backlog instead of discovering it via lockouts.
- When opted in, seeds restore via a new optional `SeedImporter` capability on the TOTP store (fail-closed: an import error aborts that category and is reported, never silently half-applied); the restored state is byte-identical so existing TOTP verification succeeds.
- `docs/dr-framework.md` §1 and the §6 runbook gain the remediation step (re-enroll or re-issue seeds for flagged users).

**Acceptance check**: export with `IncludeCredentialSecrets` + AES-GCM sealer → envelope contains no plaintext seed bytes (scan the sealed payload), restore into a fresh `MemoryTOTPStore` with opt-in → `GetSecret` returns the original bytes and a TOTP verification passes; restore without opt-in → `Report` flags re-enrollment-required users and the store stays empty; `IncludeCredentialSecrets` without a sealer, or redaction requested with seeds present, fails closed with an explicit error; default export (no flag) yields a snapshot byte-identical in scope to today.

---

All three decisions stay within `interfaces/snapshot` plus optional SPI seams on existing stores (type-asserted capabilities, no interface churn), keep credential material out of the default snapshot body, and each carries a `Report`-level marker so recovery outcomes are observable rather than discovered by outage. Per AGENTS.md §5, contract updates (error codes, `docs/dr-framework.md`, `proto/admin/v1/snapshots.proto` `RestoreReport`) belong in the same change as the implementation.
