# Identity-Protocol Review: Credential-Aware Recovery for `interfaces/snapshot`

**Review target:** `docs/design/interfaces-snapshot-credential-aware-recovery.md` (design only — no code modified by this review). **Role:** advisory identity-protocol reviewer per `ai-dev/prompts/README.md` and `ai-dev/prompts/protocol_expert.md`. **Revision:** working tree at `b531de63` with 284 pre-existing uncommitted modified files; the design is a proposal for that WIP tree.

**Checks actually run for this revision:**
- `go build ./...` — **passed** (all claims read against a compiling tree).
- `go test ./interfaces/snapshot/...` — **failed to build** (pre-existing WIP state, unrelated to this design: `interfaces/snapshot/restore_safety_test.go:105` `cannot use &failFirstPermissions as *permissions.MemoryProvider`; the snapshot package is mid-refactor in the worktree). Reported separately; no claim below rests on that test run.
- Scratch probe (compiled + executed, then removed): `MemoryClientStore.ValidateSecret` with a stored-empty-secret client accepts an empty presented secret — see F1.
- Static verification (read/grep/sed) of every design citation listed in the matrix, plus the go-webauthn v0.17.3 and v0.17.4 module sources in `GOMODCACHE`.

Statuses: **Verified** (code read this revision), **Proposed** (design), **Gap** (design misses or is wrong), **Partial** (claim verified with caveats).

---

## 1. Protocol / profile scope and authoritative references

The design touches no authorization/authentication endpoint behavior; it changes what a snapshot artifact may carry and what a restore may write. The identity protocols actually in scope are the credential surfaces those artifacts touch.

| Reference | Relevance |
|---|---|
| RFC 6749 §2.3.1 (client authentication; confidential vs. public clients), §4.4 (`client_credentials`), §6 (refresh-token client auth) | Decision 1 — client-secret regeneration; empty-secret client-auth semantics (F1); the `denyPublicClientCredentials` guard |
| RFC 7592 §2.2 (registration access token for dynamic client management) | Decision 1 — the `RegistrationAccessToken` is a second credential lost on fresh-node restore and **not** covered (F3) |
| RFC 9126 §2 (PAR: confidential clients MUST authenticate before push) | F1 — `authenticatePARClient` calls `ValidateSecret` with no non-empty guard, making the empty-secret acceptance reachable today |
| RFC 7662 §2.1 / RFC 7009 §2.1 (introspect/revoke client auth) | F1 — both require a non-empty presented secret (verified), so the bypass does not reach them |
| W3C WebAuthn Level 2/3: §5.1 credential record, §5.4.3 user handle, §5.10 authenticator data (BE/BS flags, sign counter), §6.3.2 login ceremony steps 4–17 (clone detection) | Decision 2 — credential projection, counter-regression skip, handle preservation |
| RFC 6238 §4 (shared-secret handling) + RFC 4226 §4 | Decision 3 — TOTP seed portability; byte-identical import preserves verification |
| Repo invariants: AGENTS.md §3 (oracle-safe errors; credentials never in snapshots), `admin_clients.go:37` ("secrets are never echoed… RotateSecret is the only RPC that returns one"), `codec_json.go` `DisallowUnknownFields`, `docs/dr-framework.md` §1/§6 | Decisions 1/3/4/5 |
| go-webauthn v0.17.3 (pinned; v0.17.4 `login.go` byte-identical) | Decision 2 verification-field claim (F4) |

Design-citation audit (all **Verified** this revision unless noted): `preserveClientSecrets`/`ErrNoSuchClient` (`interfaces/snapshot/restorer_clients.go:111-145`, with the fresh-node mechanism nuance in F9); `ClientStore.RotateSecret` in the base SPI (`shared/core/spi.go:78-82`) and on `MemoryClientStore` (`infrastructure/defaultimpl/memorystoreidentity/memory_clients.go:211-213`, which applies `clientrotation.DefaultLifetime` via `RotateSecretWithLifecycle` — the design's "destination-store default lifecycle" note is accurate); `TenantScopedClientStore` type-assert pattern (`shared/core/spi.go`); `sso.Client.Active` (`shared/core/types.go:48`); `codec_json.go` `DisallowUnknownFields` + decode-before-version-check ordering (F5); `Report`/`CategoryCounts`/`runPlan` abort contract (`interfaces/snapshot/restorer.go`, `restorer_stage.go:22-40`); `stagePlan` ordering clients→users (`restorer_stage.go:50-72`); `InvalidateRestoredControlPlane` after both phases (`restorer.go:131-137`, `interfaces/sso/server_invalidation.go:47-56`); webauthn `UserStore` SPI + `credentialExtensionSetter` + `CredentialExtensions` (`domains/authenticators/webauthn/webauthn_types.go`); `MemoryUserStore` methods + `GetByHandle` (`webauthn_memory_store.go`); `webauthnpostgres`/`webauthnsqlite` stores; `TOTPStore`/`MemoryTOTPStore` (`domains/authenticators/totp.go`), sqlite `TOTPEnrollmentStore.GetSecret` keyed by `user_id` (`infrastructure/defaultimpl/sqlite/totp_enrollment.go:114-117`), login-time lookup keyed by subject ID (`domains/authenticators/totp_mfa.go:57-71` — matches `SeedRecord.UserID`); `Sealer` shape (`pipeline.go:41-50`), aesgcm 32-byte key, passphrase argon2id; `Redactor.Redact` returns nothing (`redactor.go`); `SnapshotRedactSecrets` wired at `cmd/sso-server/build_stores.go:150`, config default **false** (F7); proto field numbers 3/5/9/9 all free (`proto/admin/v1/snapshots.proto`); `reportToProto` (`admin_snapshots.go:532-558`); operations ledger persists `json.Marshal(rep)` (`admin_snapshots.go:327-328`) — the design's audit-stripping guard is required and correctly identified; `mapSnapshotError` maps capability sentinels to `codes.FailedPrecondition` (`admin_snapshots.go`); `softwareAuthenticator` harness (`domains/authenticators/webauthn/assertion_regression_test.go:29`); `docs/dr-framework.md` §1 lists "MFA enrollments" as omitted; §6 runbook has no credential-remediation step; openapi snapshot endpoints at `docs/openapi.yaml:6218-6355`; `docs/feature-matrix.md` has **no** snapshot rows today.

---

## 2. Compliance matrix

| Section / requirement | Level | Implementation evidence | Status | Deviation / notes | Test to run |
|---|---|---|---|---|---|
| **Decision 1 — client secret regeneration** | | | | | |
| RFC 6749 §2.3.1 — confidential clients authenticate with a secret; a restored client must have a usable secret | MUST | Fresh-node restore inserts `Secret == ""` (`json:"-"`); `ValidateSecret` with stored-empty accepts empty presented value (probe) but `/token` grants are masked by `denyPublicClientCredentials` (`server_token.go:377-392`) → `invalid_client`; design rotates via `ClientStore.RotateSecret` | **Proposed** | Failure mode mischaracterized: token minting "breaks" as the design says, but PAR client auth does **not** break — it bypasses (F1). Rotation design itself is sound and correctly ordered before `InvalidateRestoredControlPlane()` | F1 probe; rotation e2e in `test/` |
| RFC 6749 §2.3.1 / §4.4 — only secret-bearing confidential clients get a secret | MUST | Eligibility `Active && Secret == ""` has no auth-method check; `TokenEndpointAuthMethod` supports `"none"` (public) and `Federation` clients never use secrets (`shared/core/types.go:306-314`, `Federation` field) | **Proposed** | Over-match: public + federation clients would be rotated (F2) | Rotation-classification unit test |
| RFC 6749 §6 — refresh grant client auth | MUST | Empty-secret auth would pass `ValidateSecret`, but `denyPublicClientCredentials` blocks all grants for `Secret == ""` live records | **Verified** | Masked today; do not rely on the mask (F1) | F1 regression |
| RFC 7592 §2.2 — registration access token for client management | MUST | `authorizeRegistrationMgmt` requires `bearer != "" && RAT != ""` (`handle_register.go:372-377`) — fail-closed | **Verified** | Fresh-node restore also empties the RAT; no regeneration path in the design (F3) | RAT-loss DR test |
| RFC 9126 §2 — confidential clients MUST authenticate at PAR | MUST | `authenticatePARClient` → `ValidateSecret` with **no** non-empty guard (`handle_par.go:141-142`) | **Gap** | Empty stored secret authenticates at `/par` after fresh-node restore (F1) | PAR empty-secret probe |
| RFC 7662 §2.1 / RFC 7009 §2.1 — client auth at introspect/revoke | MUST | Both require `secret != ""` (`handle_introspect.go:371-374`, `handlers.go:45-47`) | **Verified** | Not affected by F1 | n/a |
| Audit/operations: rotated secrets are RPC-response-only | Repo invariant (`admin_clients.go:37`) | `result, _ := json.Marshal(rep)` persists the full Report into the operations ledger (`admin_snapshots.go:327-328`); audit meta via `restoreAuditMeta` | **Proposed** | Design requires a strip guard + test — correct and necessary; `admin_clients.go:37` comment becomes stale (F10) | Ledger-row no-secret test |
| **Decision 2 — WebAuthn portability** | | | | | |
| WebAuthn §5.1 — credential record fields | MUST | `gw.Credential` carries ID, PublicKey, AttestationType, AttestationFormat, Transport, Flags, Authenticator{AAGUID,SignCount}, Attestation (`credential.go:65-95`); projection zeroes only `Attestation` | **Verified** | Attestation blob is never read post-registration in-repo; MDS login path passes `nil` statement (`login.go:349`) — zeroing is safe; library comment "must be persisted" caveat should be documented | Round-trip test with `softwareAuthenticator` |
| WebAuthn §6.3.2 steps 4–17 — verify with stored public key; update sign counter; clone detection | MUST | go-webauthn `VerifyLogin` reads `PublicKey`, `AttestationFormat` (GetAppID), `Flags` (BE consistency), `Authenticator.AAGUID`+`AttestationType` (MDS path), `ID` (lookup); Snaplink fails on `CloneWarning` (`webauthn.go` `ErrClonedAuthenticator`) | **Verified / Partial** | Design's field list omits ID + MDS-path fields (F4a); the counter-regression skip (live newer ⇒ skip) matches the never-write-backwards discipline and the library's clone semantics | Counter-regression test |
| WebAuthn §5.10 — BE/BS flags preserved | MUST | Flags travel in the projection; `VerifyLogin` rejects BE-change and BE=0+BS=1 (`login.go:371-378`) | **Verified** | None | Round-trip + flags test |
| WebAuthn §5.4.3 — user handle binding | SHOULD | `CreateUserWithHandle` preserves the handle; fallback re-mints; conditional login resolves users **by handle** (`conditional_login.go:109-110` `GetByHandle`) | **Gap** | "Cosmetic" fallback breaks discoverable/conditional login (F4b) | Conditional-login round-trip |
| Restore replay — insert/converge, no prune | Repo convention | Replay via `GetByName`/`CreateUser`/`AddCredential`/`UpdateCredential`/`SetCredentialExtensions` — all exist | **Proposed** | Deliberate no-prune deviation documented; acceptable (F2-design) | `snapshot_v3_test.go` |
| **Decision 3 — TOTP seeds** | | | | | |
| RFC 6238 §4 / RFC 4226 §4 — shared secrets protected; never plaintext in artifacts | MUST | Purpose-separated sealed envelope (`DeriveSealer("snapshot:totp_seeds:v1")`); `encryptionnone` cannot derive (no key material — fail-closed); redaction refusal lives in `Export` (verified insertion point between `exportResources` and `applyRedaction`, `snapshotter.go:55-65`) | **Proposed** | `Redactor` cannot error (verified `redactor.go`) — refusal-in-`Export` is the only workable placement | Envelope substring scan |
| RFC 6238 — byte-identical secret ⇒ verification passes | MUST | `ImportSeed` byte-copy; `hotp` is a pure function of (secret, step) (`totp.go:230-260`); store key space = subject ID (`totp_mfa.go:57-71`) matches `SeedRecord.UserID` | **Verified** | None | TOTP round-trip |
| Opt-in gates fail closed | Repo discipline | Flag+missing sealer/exporter/PurposeSealer ⇒ hard error; flag-unset ⇒ category absent | **Proposed** | Acceptance-check quote not traceable in-repo (F6); default-flag reading is the stricter, correct one | Gate-matrix table test |
| Redaction XOR seeds | Repo discipline | Hard error when effective redactor + seeds | **Proposed** | Parenthetical about `snapshot.redact_secrets` default is backwards (F7) | Redaction-conflict test |
| Undecryptable envelope ⇒ conservative flag-all | Availability | Category error + flag all users | **Proposed** | Over-flagging is deliberate and documented | Wrong-key test |
| **Decision 4 — schema v3** | | | | | |
| v3 refused by ≤v2 binaries | Wire compat | `DisallowUnknownFields` decode precedes the version check (`codec_json.go:43-55`) | **Partial** | Field-carrying v3 artifacts fail as JSON unknown-field errors, not `ErrUnknownSchemaVersion` (F5) | v2-codec refusal test (both shapes) |
| v1/v2 readable by v3; `legacyCategories` unchanged | Wire compat | `IsValidSchemaVersion` must accept `"1"|"2"|"3"`; `IncludesCategory` v1 = legacy only, nil manifest = include-all (`snapshot.go`) | **Proposed** | Implementation must add `"2"` to the acceptance set | v1/v2 decode tests |
| **Decision 5 — contracts** | | | | | |
| Proto field numbers | Wire compat | `include_credential_seeds=3`, `restore_credential_seeds=9`, `credential_recovery=9`, `requires_rotation=5` — all free (verified) | **Proposed** | None | bufconn proto test |
| Error codes → `failed_precondition` | Repo contract | `mapSnapshotError` precedent for capability sentinels | **Proposed** | `docs/error-codes.md` has no snapshot section today; add both sentinels | REST error-mapping test |
| OpenAPI / feature-matrix | Repo contract | Endpoints exist (`openapi.yaml:6218-6355`); feature-matrix has no snapshot rows | **Proposed** | Net-new rows, not edits | docscheck |
| OIDF certification | — | Repo explicitly disclaims ("Implemented does not mean OpenID Certified", `docs/feature-matrix.md:85`); no published result in-tree | **Missing** | Do not claim | n/a |

---

## 3. Findings

### F1 — High — Empty stored client secret authenticates an empty presented secret; PAR is the reachable bypass after fresh-node restore

- **Requirement level:** RFC 6749 §2.3.1 / RFC 9126 §2 MUST (client authentication); repo invariant "a secret-less confidential client must not authenticate".
- **Location:** `shared/security/client_secret.go:19-26` (`CompareClientSecret` returns true for `("","")`); `infrastructure/defaultimpl/memorystoreidentity/memory_clients.go:62-90` and `infrastructure/defaultimpl/sqlite/clients.go:176-190` (`ValidateSecret`); reachable at `protocols/oauth/handle_par.go:141-142` (`authenticatePARClient` has no non-empty guard).
- **Evidence:** executed probe this revision — a client added with `Secret == ""` (the exact fresh-node-restore state) passes `ValidateSecret(ctx, "web", "")` with nil error; a non-empty wrong secret is rejected. Token minting is *not* exploitable: `denyPublicClientCredentials` (`interfaces/sso/server_token.go:377-392`) rejects all grants when the live record's `Secret == ""`. Introspect/revoke/DCR require non-empty input (`handle_introspect.go:371-374`, `handlers.go:45-47`, `handle_register.go:372-377`). **`/par` is the bypass surface**: an attacker who knows a client_id can push authorization requests as a restored confidential client.
- **Impact:** the design (and its source, `docs/auto/interfaces-snapshot-analysis.md`) frames the fresh-node failure as "the `client_secret` grant silently breaks" — true for token issuance, but false for PAR, which silently *accepts* the empty secret. Interoperability/security: client-authentication bypass on RFC 9126; and the design's failure table treats "store lacks `SecretRotator` ⇒ restored with empty secrets exactly as today" as an availability matter, when it is a live auth-bypass state on one credential endpoint. Any future endpoint calling `ValidateSecret` without a non-empty guard inherits the bypass.
- **Corrective behavior:** (a) root fix — `ValidateSecret` implementations (and `CompareClientSecret` callers) must reject an **empty stored secret** (a client with no secret must never authenticate, even against an empty presented value); this makes the design's premise literally true and closes the PAR path; (b) the design should rate missing-rotator/rotation-failure outcomes as security-relevant in the failure table and consider failing the restore closed (or refusing to mark `Committed`) when confidential clients would be left secret-less on a store without `SecretRotator`; (c) add a non-empty-presented check to `authenticatePARClient` regardless.
- **Validation step:** probe test (stored-empty + presented-empty must fail) + PAR empty-secret e2e against a restored-node fixture.

### F2 — Medium — Decision 1 eligibility over-matches public and federation clients

- **Requirement level:** RFC 6749 §2.3.1 (public vs. confidential distinction); least-privilege.
- **Location:** design Decision 1 eligibility rule (`Active && Secret == ""`); `shared/core/types.go:306-314` (`TokenEndpointAuthMethod` incl. `"none"`) and `Federation` field (`types.go:50-54`).
- **Evidence:** public clients (`token_endpoint_auth_method="none"`) and federation-derived clients are written secret-less **by design**; the rule would rotate them: spurious secrets minted, spurious plaintext secrets returned in the RPC response, spurious `client_secret_expires_at` lifecycle on clients that must never hold a secret.
- **Impact:** correctness and exposure hygiene — `CredentialRecovery` entries carry unnecessary plaintext credentials; report noise undermines the "observable recovery" goal.
- **Corrective behavior:** predicate rotation on secret-based auth methods (`TokenEndpointAuthMethod ∈ {"", "client_secret_basic", "client_secret_post"}`) **and** `!Federation`; add a third classification the report carries: rotate / flag-on-enable (disabled secret-auth clients) / skip (public, federation).
- **Validation step:** classification unit test over all six auth-method values + federation flag.

### F3 — Medium — RFC 7592 `RegistrationAccessToken` is lost on fresh-node restore and unaddressed

- **Requirement level:** RFC 7592 §2.2; AGENTS.md §3 oracle table (identical `401 invalid_token`).
- **Location:** design Decision 1 scope (secret only); `shared/core/types.go:46-48` (`RegistrationAccessToken` `json:"-"`); `handle_register.go:372-377` (fail-closed when empty — verified, so no bypass, but a hard break).
- **Evidence:** after fresh-node restore the RAT is empty; dynamic client management (GET/PUT/DELETE `/register/:client_id`) fails for every DCR-provisioned client; no regeneration SPI exists and the design adds none, no report marker names the condition.
- **Impact:** availability — DCR-based client lifecycle breaks silently after DR; operators discover it only when management calls 401.
- **Corrective behavior:** either add a RAT regeneration capability + report field, or explicitly declare DCR out of scope for this feature and (a) document it in `docs/dr-framework.md` §6 and (b) surface a `RequiresRotation`-style marker for RAT-less clients. The design's "What could break" list should name this.
- **Validation step:** restore fixture with a DCR client; assert the DCR-management 401 and the documented marker.

### F4 — Low — Decision 2 accuracy: version/field claims and the "cosmetic" handle fallback

- **Requirement level:** documentation accuracy; WebAuthn §5.4.3/§6.3.2 behavior claims.
- **Location:** design Decision 2 ("go-webauthn v0.17.4", "only PublicKey/AttestationFormat/Flags/SignCount", "cosmetic" handle re-mint); `go.mod:12` pins **v0.17.3** (v0.17.4 `login.go` byte-identical — diffed); `login.go:320-385` also reads `ID` (lookup) and, when `Config.MDS != nil`, `Authenticator.AAGUID` + `AttestationType` (`login.go:343-352`); Snaplink can wire MDS (`webauthn.go:166-181`); `conditional_login.go:109-110` resolves users by `GetByHandle`.
- **Impact:** the projection decision is safe (only the `Attestation` blob is zeroed, so the extra fields survive), so this is a claim-accuracy issue — except the handle point: with the fallback path (store lacks `HandlePreservingUserCreator`), restored credentials **fail passwordless/conditional login** because the authenticator presents the old handle and `GetByHandle` misses; the design's "cosmetic, assertions still verify" understates a functional break for discoverable credentials.
- **Corrective behavior:** correct the version/field citations; treat handle preservation as effectively required — make the fallback skip the credential with a counted outcome (fail-closed) rather than silently re-minting, or keep the fallback but document the conditional-login break in the runbook.
- **Validation step:** conditional-login round-trip with handle re-mint (expect documented failure); MDS-wired login round-trip.

### F5 — Low — Decision 4 wording: where v3 refusal actually happens in ≤v2 binaries

- **Requirement level:** wire-compat documentation accuracy.
- **Location:** `codec_json.go:43-55` — `DisallowUnknownFields` decode **precedes** the version check.
- **Evidence:** a v3 artifact carrying `webauthn_credentials`/`totp_seeds` fails in an old binary as a JSON unknown-field error before `IsValidSchemaVersion` runs; only new-field-free v3 artifacts reach the version sentinel. The design's "refused at the version check" and "protects the codec from choking" are inverted — the codec *does* choke, safely.
- **Impact:** operators troubleshooting "v3 into old binary" see `json: unknown field` instead of the documented `unknown_schema_version`; the refusal property itself holds (no silent misparse).
- **Corrective behavior:** fix the wording; optionally peek `schema_version` before full decode for a clean sentinel error.
- **Validation step:** two codec tests — v3 artifact with new fields (expect unknown-field error) and without (expect `ErrUnknownSchemaVersion`).

### F6 — Info — Requirement provenance for the "Active gate" and the TOTP acceptance-check quotes

- **Location:** design Decisions 1 and 3 cite "the requirement" and "the acceptance check" ("silently absent without all three", "fails closed with an explicit error").
- **Evidence:** the only in-repo requirement source, `docs/auto/interfaces-snapshot-analysis.md` (29 lines), contains none of these phrases and no `Active` gate. The strict readings adopted (hard error once the flag is set; conservative gates) are the right ones under AGENTS.md ("satisfy the stricter contract"), so no design change is required — but provenance should be cited or marked unknown so reviewers don't hunt for a nonexistent text.
- **Validation step:** n/a.

### F7 — Info — "snapshot.redact_secrets default makes seed exports fail loudly" is backwards

- **Location:** design Decision 3 failure table; `config/config_snapshot.go:60-65` (`RedactSecrets` default **false**).
- **Evidence:** with defaults, seed exports succeed (flag + sealer + exporter present); the redaction-vs-seeds conflict arises only when the operator *enables* `redact_secrets`. The design's behavior table is correct; the parenthetical misstates the default's effect.
- **Validation step:** n/a.

### F8 — Info — Passphrase `DeriveSealer` rationale and salt handling should be specified

- **Location:** design Decision 3 (`PurposeSealer` on `encryptionpassphrase`).
- **Evidence:** purpose separation via HKDF over the raw passphrase would not be "illusory" (deterministic per purpose; different passphrases still yield different keys) — deriving from the argon2id output is a *strength* improvement (KDF hardening), which is the better rationale. Also specify that the derived sealer carries its own salt in the envelope `Params` (as the base sealer does) so two nodes with the same passphrase derive the same key; otherwise cross-node restore breaks.
- **Validation step:** two-node passphrase round-trip test.

### F9 — Info — Fresh-node mechanism in Decision 1 is a race path, not the main path

- **Location:** design Decision 1 opening ("`preserveClientSecrets` hits `ErrNoSuchClient`").
- **Evidence:** on a fresh node `Add` succeeds (no `ErrClientExists`), so `preserveClientSecrets` is never invoked; the client is inserted secret-less directly. `ErrNoSuchClient` occurs only in the probe-then-update race (`restorer_clients.go:123-130`). Outcome claim is unaffected. Related: `MemoryClientStore.Add/Update` mutate the passed client in place (hashing) and `Get` returns live pointers — the design's "written by this restore" bookkeeping should key on client ID, not pointer identity.
- **Validation step:** n/a.

### F10 — Info — Contract touchpoints the design should also update

- **Location:** `interfaces/snapshot/restorer.go` (`Report.Errors` doc: "non-nil Errors means at least one category bailed" — per-client rotation errors extend that meaning); `interfaces/grpcserver/grpcadmin/admin_clients.go:37` ("RotateSecret is the only RPC that returns one" — the restore RPC becomes a second exception); `admin_snapshots.go:327-328` (ledger strip guard, already required by the design).
- **Validation step:** ledger-row no-secret test (design already plans it).

---

## 4. Priority conformance tests, declared unsupported features, certification evidence

### Priority conformance tests (new, in order)

1. **F1 regression (blocks merge):** stored-empty + presented-empty `ValidateSecret` must fail (memory + sqlite); PAR empty-secret request must 401; token grants still `invalid_client` via `denyPublicClientCredentials`.
2. **Rotation classification:** confidential-active → rotate; confidential-disabled → flag-on-enable (report field); public/federation → skip; dry-run predicts the identical set with zero mutations.
3. **Ledger/audit strip:** operations row + audit event for a restore contain client IDs but no rotated secret bytes.
4. **WebAuthn round-trip** (`snapshot_v3_test.go` as designed): export → restore → login with `softwareAuthenticator`; counter-regression skip (live newer); exporter-less store ⇒ category absent; conditional-login with preserved handle.
5. **TOTP round-trip:** sealed-envelope substring scan for a known seed; wrong-key restore ⇒ category error + conservative all-users flag; opt-out restore ⇒ `MFAReenrollmentRequired` without mutation.
6. **Schema v3 wire tests:** v3-with-new-fields and v3-without-new-fields against a v2-shaped codec (assert the actual error, per F5); v1/v2 artifacts decode under v3.
7. **Redaction XOR seeds / missing-gate hard errors** matrix.
8. **Two-node passphrase seed round-trip** (F8).

### Declared unsupported features (as designed)

- WebAuthn/totp Phase-B prune ("replace wipes the category" deliberately deviates for credentials; destination is authority on newer credentials) — acceptable, must stay documented.
- TOTP seeds under `encryptionnone` (fail-closed by missing `PurposeSealer`).
- RegistrationAccessToken regeneration (F3 — currently *undeclared*; must be declared).
- Rotation of disabled clients (F2 — must at least be reported, not silently skipped).

### Certification evidence

- **OIDF:** no OpenID certification claimed or present in-tree; `docs/feature-matrix.md:85` explicitly disclaims. The review makes no certification claim.
- **FIDO/WebAuthn:** no FIDO certification claimed. The design changes record *portability*, not ceremony behavior; no conformance-impact beyond the handle/counter points in F4, which are covered by the tests above.
- **Remaining evidence gaps:** the snapshot package tests do not currently build in this worktree (pre-existing WIP refactor, `restore_safety_test.go:105`); F1's e2e confirmation at `/par` and the rotation lifecycle behavior (`client_secret_expires_at` defaults) still need executable tests against the finished refactor.
