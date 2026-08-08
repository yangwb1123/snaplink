Verification complete. Artifact: `docs/architect-analysis/auto/runs/opt-entitiescmd-into-the-no-redirect-credential--5001a419/artifacts/verification-3692645e/task-2-expanded-surface.md`

## Findings

**1. Enumeration — 11 credential-bearing, redirect-following sites, 2 construction paths**

- **Path A (10 sites, shared construction):** zero-option `apiclient.New()` at tui/run.go:38 (single construction; all 4 verbs — fetchItems GET, createItem POST, updateItem PUT via `client.Do`, deleteItem DELETE — route through it, api.go constructs nothing), tokenscmd:74/:133, sessionscmd:132/:158, clientscmd:132/:158, entitiescmd tenants.go:254/275/298. Each is a literal one-line `New(apiclient.WithNoRedirect())`.
- **Path B (reviewer's #11, confirmed):** auditverify/main.go:414 — bare `&http.Client{Timeout: timeout}`, no CheckRedirect, bearer set at :459; imports no apiclient, so a default flip in `New` would never touch it.
- **Third paths: none.** No retry clients, no custom RoundTripper, no other bare `http.Client` in cmd/sso-ctl (only already-pinned check.go:325 and token.go:417). Adjacent out-of-scope note: sso-operator's `defaultHTTPClient` (bearer, no pin).

**2. Pin fits every site; no legitimate redirect dependency**

- auditverify wrinkle: `rejectRedirect` is **unexported** and auditverify deliberately doesn't import apiclient — the pin is still one line (inline `CheckRedirect: func(...) error { return http.ErrUseLastResponse }`), but the review's "CheckRedirect: rejectRedirect" wording needs the inline form or an exported policy.
- No dependency: docs/deployment.md:411's same-origin edge needs no following; apiclient design §2.4 already documents "point --addr at the final origin" as the remediation; oauth2-proxy-style login gates can never authenticate an admin bearer (not a session cookie) — following only leaks it. `SSO_ADMIN_ADDR` is the only knob on Path A (no `--addr` flags — verified), `--from-url` for auditverify.

**3. Tests: no follow-assertions on any pinned surface.** tui has zero test files; the three subcommands' tests use plain httptest servers (pin-safe); the only default-follow assertion (`TestNew_NoRedirect`'s second half) is compatible with per-site pins and **breaks under a default flip** — the design's opt-in choice is the only one the suite supports.

**4. Error branch: applicable consistently, but it's new work, not part of the pins**

- The recommended branch (redacted Location + hint + truncated body) exists **nowhere** today — all surfaces print status + raw body. `redactURL`/`sanitizeBody` already live in package apiclient, so one shared helper covers all 10 Path-A sites + tui's `apiErrorMessage` with byte-identical diagnostics.
- auditverify diverges on four axes: needs a `--from-url` hint (not `SSO_ADMIN_ADDR`), its body echo is the only **unbounded** one (`io.ReadAll`, no 1MB cap, no 200-byte sanitize), its transport-error path wraps `url.Error` embedding the URL (userinfo never rejected at parse), and the helper is unreachable without a new dependency.

**Net:** fold-in is confirmed feasible and correct — 10 one-line pins + 1 inline pin, shared error-branch helper, plus 3 corrections to the review's framing (inline pin form for auditverify, surface-specific hint, error branch as separate work). Tree builds/vets clean.
