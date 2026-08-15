# B5-1: SMTP implicit TLS (port 465) — completion report

Commit: `65c60ef3` — `feat(emailsmtp): add implicit TLS transport for SMTP port 465`
(9 files changed, 494 insertions(+), 29 deletions(-); conventional imperative
message + `Co-authored-by: pi <pi@earendil-works.local>` trailer).

## What was implemented

Adjudicated scope: v1 adds implicit TLS only (port 465 auto-selection +
`crypto/tls.Dial`-first transport); STARTTLS (587) / plaintext (25) behavior is
byte-identical to before.

### Transport (`infrastructure/defaultimpl/emailsmtp/transport.go`)
- `implicitTLSSendFunc`: establishes the TLS connection FIRST via
  `crypto/tls.Dial` (through the injectable `tlsDialFunc` seam, default
  `defaultTLSDial` = `tls.Dial`), then runs the SMTP session with
  `net/smtp.NewClient` (greeting + EHLO), optional AUTH, MAIL, RCPT, DATA
  write, QUIT — mirroring `SendMail`'s steps. Errors are wrapped without
  echoing credentials or message contents.
- `implicitTLSConfig(host)`: `ServerName` pinned to the relay host (SNI +
  verification name), `MinVersion` TLS 1.2, **`InsecureSkipVerify` never set**
  — verification failure is fail-closed.
- `Sender.useImplicitTLS()`: `cfg.Port == 465 || cfg.TLSMode == "implicit"`;
  anything else (including unknown `tls_mode` values) keeps the plaintext
  `net/smtp.SendMail` path. Selection happens inside the existing timeout
  goroutine, so `cfg.Timeout` still bounds implicit-TLS sends.
- `smtp.PlainAuth` works over implicit TLS because `net/smtp.NewClient` marks a
  `*tls.Conn` as TLS (`c.tls = true`); verified against Go 1.26.5 stdlib.

### Config
- `config/config_self.go` `SMTPConfig.TLSMode string` (`yaml:"tls_mode"`):
  `auto`/empty (default; unknown values behave as `auto`) or `implicit`.
  Existing keys (`starttls`, port, etc.) untouched; `smtp.enabled=false` /
  empty host → nil sender, byte-identical (existing tests assert this).
- `cmd/sso-server/serverbuildplatform/email_sender.go`: translates `TLSMode`
  through (`BuildEmailSender`), which also serves the email-OTP and
  magic-link authenticators via `buildEmailOTPSender`.
- `emailsmtp.Config.TLSMode` mirror + updated doc comments (config.go).

### Tests (`transport_test.go`, all real, none skipped, `-count=10 -race` clean)
1. `TestSender_UseImplicitTLS_Selection` — table-pins the predicate: 465
   auto-enables (incl. explicit `auto`), 587/25 unchanged, 587+`implicit`
   selects TLS, unknown mode = auto.
2. `TestTransport_ImplicitTLS_Port465` — end-to-end over an in-process
   TLS-wrapped SMTP listener with a real handshake (throwaway ECDSA cert with
   127.0.0.1 IP SAN; `WithTLSDial` adds the test CA to the sender's own
   config). Asserts the transport derived `host:465`, `ServerName` = relay
   host, `MinVersion` = TLS 1.2, `InsecureSkipVerify` never set.
3. `TestTransport_ImplicitTLS_ExplicitMode` — `tls_mode: implicit` on a
   non-465 port (non-standard implicit-TLS relays).
4. `TestTransport_Non465_PlaintextUnchanged` — no-regression: plaintext
   `SendMail` path for non-465/auto, TLS dial never invoked.
5. `TestTransport_ImplicitTLS_HandshakeFailure_FailClosed` — default
   `tls.Dial` against a plaintext listener: handshake fails, error surfaces
   (`tls:`), and no SMTP byte reaches DATA — no plaintext fallback.
6. Existing `serveFakeSMTP` refactored into `serveSMTP(conn)` so the same
   RFC 5321 loop serves plain and TLS listeners; existing tests untouched in
   behavior.

### Contract sync (same commit)
- `docs/config-reference.md` — `smtp.port` (465 = implicit TLS), `smtp.starttls`
  (unchanged 587/25 wording), new `smtp.tls_mode` row.
- `docs/deferred-backlog.md` — "SMTP transport" limitation closed per baseline
  maintenance rule (Implicit TLS now supported; fail-closed verification).
- `CHANGELOG.md` — Added entry.
- No `feature-matrix.md` change needed (no SMTP transport row exists there);
  no OpenAPI/error-code surface affected (outbound transport only).

## Verification (actually run)

| Command | Result |
|---|---|
| `go build ./... && go vet ./...` | PASS |
| `go test ./infrastructure/defaultimpl/emailsmtp/... -count=1` | PASS (ok, 0.006s) |
| `go test ./infrastructure/defaultimpl/emailsmtp/... -count=10 -race` | PASS (ok, 1.1s) |
| `go test ./test/ -run 'SendCode\|Email' -count=1` | PASS (ok, 0.538s) |
| `go test ./cmd/sso-server/serverbuildplatform/... -count=1` | PASS |
| `go test ./config/ -count=1` | PASS |
| `go test -count=1 -run 'TestMaintainability_\|TestArchitecture_\|TestDirectory' .` | FAIL — **pre-existing, unrelated** (see below) |
| `gofmt -l` on changed packages | clean |

Pre-existing failure (present on `origin/main` HEAD `f30b1f6f`, files untouched
by this change — `git diff` shows no `cmd/gensdk` edits):
- `cmd/gensdk/gen_py.go` — 526 lines (budget 500) and `pyEmitMethod` 51 lines
  (budget 50), from commit `981a89a3` (2026-07-30). Architecture and Directory
  gates PASS; only these two maintainability checks fail.

## Push status

Committed locally. The post-commit hook's auto-push to `origin/main` was
blocked by the repository's pre-push hook (`python3 cli.py harness`), which
fails on the same pre-existing `cmd/gensdk/gen_py.go` budget violation. Per
AGENTS.md, hooks are not bypassed (`--no-verify` forbidden) and unrelated
cleanup is not performed without authorization; the violation must be resolved
(e.g., splitting `gen_py.go`) before `main` can accept any push.
