Spec written and evidence verified. Summary of the work:

**Deliverable**: `docs/architect-analysis/auto/interfaces-snapshot-storagefile-sanitize-injective-spec.md`

**Evidence verification** (all direction citations checked against the repo):

| Citation | Result |
|---|---|
| `file.go:130-152` `sanitize` | ✅ Verified — function is at 130-153; non-injective `_`-collapse confirmed (`"a/b"` and `"a_b"` both → `a_b`) |
| `file.go:50-86` Put/Get sanitized-name overwrite | ✅ Verified — Put 50-86 (`os.Rename` silent overwrite); Get 88-105 and Delete 107-120 also route through `sanitize` |
| `file_test.go:83-103` `TestSanitisesNames` | ⚠️ Symbol verified, **line number corrected to 68-88** (83-103 is `TestPutAtomic`'s region); content check confirms no collision case |
| `pipeline.go:15-18` Storage contract | ✅ Verified — "Overwrites are allowed (older copy is replaced)" at 16-18; contract also permits rejecting unsafe names (alternative considered and rejected since it fails the supplied acceptance) |
| `issue_payload.go:26` `buildAccessPayload` | ✅ Verified — func at 27, header 21-26; `TenantID: subject.TenantID` unconditional literal; roles from `Subject.Roles` (`ed25519_types.go:53`) |
| `spi.go:171` `Subject.TenantID` | ✅ Verified — exact line |

**Trust-chain corroboration**: `Client.TenantID` (`shared/core/types.go:47`) → stamped into `Subject` at login (`server_login_client.go:329`) → `tenant_id`/`roles` claims; restore re-seeds clients/roles (`restorer_permissions.go:37-74`); T-8(a) gate at `implementation-gate.md:11`; production name flows (`snapshotcmd` list/inspect/verify, `retention.go`) all address storage by original name.

**Spec content**:
- **Decision**: byte-level percent-encoding sanitize (`%` → `%25` first, then `%XX` per byte) — provably injective (prefix code); `List` decodes back to original names so `Get(List-name)` round-trips; clean names (production default `snap_*`) are fixed points → zero compat impact. Rejection-based alternative documented and rejected because the supplied acceptance requires `Put("a/b")` to succeed.
- **Acceptance preserved and made testable**: A1 = the exact `Put("a/b", v1)`/`Put("a_b", v2)` both-retrievable/List-both-names/delete-isolation check; A2 = injectivity table over previously-colliding pairs; A3 = List↔Get round-trip; A4 = restore-level test with two hand-built snapshots (per `snapshot_v2_test.go` precedent) carrying distinct `TenantID`+roles under the colliding names, asserting no cross-read into fresh destinations — the restore-side precondition for T-8(a).
- Scope kept tight: only `file.go` + `file_test.go`; no new errors/config/docs; loader `?name=` interaction documented as an explicit out-of-scope follow-up.
