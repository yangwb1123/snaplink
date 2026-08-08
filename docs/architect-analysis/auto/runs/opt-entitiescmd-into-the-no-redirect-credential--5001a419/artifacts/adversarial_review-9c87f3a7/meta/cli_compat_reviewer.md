Assessment complete. Artifact written to `docs/architect-analysis/auto/runs/opt-entitiescmd-into-the-no-redirect-credential--5001a419/artifacts/adversarial_review-9c87f3a7/meta/operator_contract_reviewer.md`. Verdicts on the four dimensions:

## 1. Release-note adequacy — inadequate as specified

- The design says only "release note for operators" (one clause in Migration) — no section, text, or scope. The vehicle is `CHANGELOG.md` `## [Unreleased]` (`### Security` exists at :79, and `docs/RELEASE.md` §1 mandates "security fixes and operator migration steps" in changelog entries).
- This is both a **security fix** (bearer + 307/308 body forwarding) and a **breaking operator change** (3xx exit 0→1) — one `### Security` entry must state the subcommand scope, the exit-code change, and the migration step (point `SSO_ADMIN_ADDR` at the canonical origin).
- Precision is load-bearing: the pin covers `tenants`/`users` only. `tui`/`tokenscmd`/`sessionscmd`/`clientscmd` still follow redirects (F5). An overbroad "sso-ctl now refuses redirects" note would be false and dangerous.

## 2. Error-message quality — not operator-diagnosable as designed

With `ErrUseLastResponse`, `Do` returns the 3xx response with nil error, so the existing `resp.StatusCode != 200` branches fire: `list failed (HTTP 307): <body>`. Status + exit 1 are right, but the message lacks:
- the **`Location` header** (the most diagnostic datum; must go through `redactURL` — sweep.go:218 — since a Location can embed userinfo and entitiescmd has no base-URL validation);
- explicit **"redirect" wording** and the **`SSO_ADMIN_ADDR` hint** — entitiescmd has no `--addr` flag (verified), so the env var is the *only* knob and the hint is accurate;
- **body truncation** (gateway 307 bodies are HTML; precedent: `sanitizeBody`/`bodyEchoLimit=200`, sweep.go:234/check.go:63).

Acceptance A1–A3b assert only exit code + target counter — nothing pins the stderr diagnostic. The 3xx branch must land in all three shared helpers (`fetchList`/`fetchOne`/`doWrite`), so "3 one-line edits" understates scope; still one small change.

## 3. No-flag fail-closed — correct and precedented

Uniform in-repo precedent: stripe-adapter main.go:97 and billing health.go:155 set `ErrUseLastResponse` unconditionally; the check sweep (check.go:148/:327, token.go:417) has **no** allow-redirect flag, with documented remediation "point --addr at the final origin" (apiclient design §2.4); AGENTS.md §3 fail-closed list has no escape hatches; B4-4 decisions §3.1 ("fail loud makes the outcome one deterministic, documented 400") applies directly. The only novelty is applying the pin to an *existing* surface — a deliberate break for redirecting-gateway deployments, with a complete workaround (`SSO_ADMIN_ADDR` → https origin; `DefaultAddr` is loopback, so local defaults untouched). Recommendation: name these precedents in the design and explain the decision in the commit body.

## 4. Docs — nothing strictly required; one cheap completion

AGENTS.md §5.6 maps no new `Err*`/endpoint/config knob (the env vars pre-exist at apiclient.go:27-28), so config-reference is not *mandated* — but `SSO_ADMIN_ADDR`/`SSO_ADMIN_TOKEN` are documented **nowhere** in `docs/`, and this change makes the env var the operator's remediation step. A config-reference row in the same change is the completion of the operator contract. No CLI reference doc exists (in-code usage strings are the reference; no change needed). Note pre-existing drift: `docs/deployment.md:50` still omits the shipped tenants/users surface — out of scope per AGENTS.md §6, but the release note must not inherit its framing.

**Bottom line:** the contract direction (visible 3xx, exit 1, no flag) is sound and precedented; the design needs three additions before implementation: a concrete changelog `### Security` entry, a redirect-specific error branch (status + redacted Location + `SSO_ADMIN_ADDR` hint + truncated body) with a message-pin test, and a config-reference env-var row.
