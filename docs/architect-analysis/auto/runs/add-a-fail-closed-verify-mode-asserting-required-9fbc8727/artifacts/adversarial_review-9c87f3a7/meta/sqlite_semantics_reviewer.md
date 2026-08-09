All probes complete and the docs corrected. Summary of the adversarial probe and the row corrections:

## Empirical results (modernc.org/sqlite **v1.50.1**, the pinned version; lock holder in a second process; reader ran open → Ping → probe → `CurrentVersion`)

| Scenario | Result at each stage | Bucket |
|---|---|---|
| **SQLITE_BUSY, locked DB** (`BEGIN EXCLUSIVE`, 9/9 runs: plain, `?mode=ro`, `busy_timeout(1500)`) | Ping: `database is locked (5) (SQLITE_BUSY)` — **never** `unable to open database file`. `?mode=ro` does **not** bypass it; busy_timeout just delays the same error | generic `open:` (exit 1, fail-closed) |
| **Mid-migration** (`BEGIN IMMEDIATE`/RESERVED — migrate.Run's real shape, 2/2) | Ping/probe/floors all pass — readers see a consistent pre-migration snapshot; only writers are blocked | report (exit per floors) |
| Directory as DSN (plain + `file:` URI) | Ping: `unable to open database file (14)` | `open:` |
| Permission-denied (`chmod 000/0200`, rw and `?mode=ro`) | Ping: `unable to open database file (14)`; a readable `0400` file falls back to a read-only open (was already known in the pins doc) | `open:` |
| Read-only filesystem (real tmpfs, remounted `ro`) | **No failure** — rw DSN reads work; only writes would fail (`attempt to write a readonly database (8)`, unreachable) | report (exit per floors) |
| WAL readers during an active uncommitted write (plain, `?mode=ro`, even missing `-shm`) | fine — consistent pre-write snapshot | report |
| Missing file, `?mode=ro` | Ping: `unable to open database file (14)` (re-confirmed with proper isolation — an earlier harness had silently created the file with a plain-rw case first) | `open:` |
| Missing file, plain rw DSN | **no error — sqlite creates the file**; all floors 0 → exit 1 with report (the one mutation verify can cause) | report |

## Corrections written into `docs/architect-analysis/cmd-sso-ctl-migratecmd-verify-design.md`

- **§3.3 step 2**: busy DB now documented to surface `database is locked (5) (SQLITE_BUSY)` at Ping (not `unable to open`), `0400`-vs-`0200/000` nuance, `?mode=ro` non-bypass.
- **§3.3 step 3**: probe errors reuse the same two-bucket classification as Ping — a busy but valid DB must never be mislabeled `not a SQLite database` (the old text turned any probe error into a NOTADB claim).
- **§3.3 table**: replaced `write-permission failure` row with 6 empirically grounded rows (EXCLUSIVE-locked, mid-migration-RESERVED, missing-file-rw-creates, directory-as-DSN, read-only filesystem, `0400` file), plus the empirical-basis note.
- **§3.4/§3.5**: qualified the "never mutates" claim (plain rw DSN materializes a file) and the pure-read claim (busy window → `open: database is locked …`).
- **§4 "Live server is mid-migration" row — the explicitly named row — rewritten**: two phases; the commit-window EXCLUSIVE phase yields `database is locked (5) (SQLITE_BUSY)` at Ping, exit 1, never an open failure; snapshot reads are the normal during-migration case, not a fallback.
- **§7**: new pin `TestVerify_LockedDB_BusyIsNotNotSQLite`; **§9**: the probe trail.

The companion `...-verify-failure-pins.md` got a §9 addendum reconciling its N-E1…N-E7 pins (all still valid: the exact busy string now pinned with the `(SQLITE_BUSY)` suffix, the mid-migration two-phase split, and the new input rows).

No Go code touched; the only worktree changes are the two docs in the untracked analysis area, and the probe harness lived in `/tmp` (cleaned up, tmpfs unmounted).
