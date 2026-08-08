Review complete and written to `docs/architect-analysis/auto/runs/input-harden-entity-id-interpolation-and-add-the-077a1671/artifacts/adversarial_review-9c87f3a7/task-2-hazard-set-review.md` (temp probe files removed; no repo changes). Findings:

## 1. Hazard set — empirically bypassable; `%` and `#` must be added

I ran the repo's actual `apiclient.Client` against a grpc-gateway v2.28.0 mux with the **exact production patterns** (`gen/proto/admin/v1/tenants.pb.gw.go:911,915`), observing wire RequestURI and the `{id}` binding:

| typed id | wire | `{id}` binding |
|---|---|---|
| `acme%3Ax` | `/tenants/acme%3Ax` | **`acme:x`** |
| `acme%3Fx` | `/tenants/acme%3Fx` | **`acme?x`** |
| `acme%23x` | `/tenants/acme%23x` | **`acme#x`** |
| `acme%2Fx` | `/tenants/acme%2Fx` | 404 (decoded `/` splits the component; all tenant routes are `{id}`-terminal) |
| `acme#x` | **`/tenants/acme`** | **`acme`** — fragment stripped client-side |
| `acme%3Aset-status` | `…:set-status` verb suffix intact | **`acme:set-status`** |

Mechanism: `apiclient.Do` splices the raw id (apiclient.go:88); net/http decodes escapes into `URL.Path`; the gateway matches on the decoded path (mux.go:396) and binds the component via `UnescapingModeAllCharacters` (pattern.go:338-341) — so the unescaping is net/http-first, gateway-backstop, but the conclusion is identical.

- **"Hazard ids never leave the process" is FALSE as designed.** `%3A`/`%3F`/`%23` leave the process and hit the binding unescaped; the server addresses the decoded entity. Even a benign escape silently remaps today (`acme%41` → `acmeA`).
- **`%` must be added** — it kills the whole encoding class with zero addressability regression (valid escapes are *already* silently remapped; invalid ones already fail).
- **`#` must be added** — same mechanism as the `?` the design already rejects, but worse: `delete acme#x --yes` deletes `acme` (silent wrong-target destructive mutation). The typed id never leaves the process, but a different one does.
- Resulting set: `% # : / ?`; A1/A2 grow to 20/15 cases plus encoded-form regression rows.

## 2. Probe (b) — one real side-effect-bound gap: the restore unwinds a pre-existing suspension

Verified: cc mint has **no** suspension gate (token_client_credentials.go — `checkTenantNotSuspended` lives only in validation, server_token_clientauth.go:400); same-status set-status is a **200 no-op with no revocation** (admin_tenants.go:338-343). So if the tenant is already suspended: mint succeeds → suspend is a no-op → introspect `active:false` → **unconditional restore flips it to ACTIVE, undoing a deliberate suspension the probe never created**. Race-free fix: restore only when the suspend response carries `credentialRevocation` (present on real transitions, absent on the no-op path); otherwise SKIP + INCOMPLETE. Also: add the lockout window to the warning, and correct "the only tenant the bearer is authorized to flip" — the admin bearer is not tenant-scoped; the self-bound via the minted token's `tenant_id` is sound but should be worded as such. Revocation scope (all tenant refresh tokens + sessions, irreversible) is correctly documented.

## 3. stderr `%q` — design's echo safe; two raw-echo holes in scope

`%q` renders ESC as `\x1b` text (verified), and the `http.NewRequest` error path is safe too (`url.Error` quotes with `%q` — verified for `%zz`, ESC, NUL, CR/LF). But the claim "echoed with %q on stderr only" is already false in the two files the design modifies: the delete-refusal hint echoes the id **raw** via `%s` (tenants.go:212, users.go:219) — ESC ids pass the proposed guard and inject into the terminal today. Fix `%s`→`%q` there in the same commit, and specify `%q` for probe (b)'s tenant warning (server-controlled claim).
