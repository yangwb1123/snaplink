Audit complete. I verified every production (non-test) HTTP-client construction in `cmd/sso-ctl`, the Go redirect semantics (stdlib source), and the design artifact's claims. Findings below.

## 1. Enumeration — every credential-bearing client construction surface

Safe surfaces (verified, consistent with the design):

| Site | Construction | Credential | Redirect policy |
|---|---|---|---|
| `apiclient/check.go:148` `ck.client` | `New(WithAddr(base), WithNoRedirect())` | env bearer (`SSO_ADMIN_TOKEN`) | rejected ✓ |
| `apiclient/check.go:323-327` `probeClient` | `&Client{...}` literal | none (body creds only) | `rejectRedirect` ✓ |
| `apiclient/token.go:417` T-9 bare client | `&http.Client{...}` | none | `rejectRedirect` ✓ |
| `apiclient/sweep.go` T-2 rows | `ck.client` / `probeClient` (`endpointClient`) | env bearer on on-base rows only | rejected ✓ |
| `entitiescmd/users.go` | zero constructions (shares the 3 helpers) | — | — (after fix, safe) |

Credential-bearing **redirect-following** surfaces (production):

| # | Site | Method(s) | Credential |
|---|---|---|---|
| 1 | `entitiescmd/tenants.go:254` `fetchList` | GET | env bearer — **fix target** |
| 2 | `entitiescmd/tenants.go:275` `fetchOne` | GET | env bearer — **fix target** |
| 3 | `entitiescmd/tenants.go:298` `doWrite` | POST/PUT/DELETE | env bearer + body — **fix target** |
| 4 | `clientscmd/clients.go:132` `fetchList` | GET | env bearer |
| 5 | `clientscmd/clients.go:158` `runGet` | GET | env bearer |
| 6 | `tokenscmd/tokens.go:74` `runRevoke` | POST | env bearer + body |
| 7 | `tokenscmd/tokens.go:133` `runIssueTemp` | POST | env bearer + body |
| 8 | `sessionscmd/sessions.go:132` `fetchList` | GET | env bearer |
| 9 | `sessionscmd/sessions.go:158` `runRevoke` | POST | env bearer + body |
| 10 | `tui/run.go:38` → `tui/api.go` (4 verbs) | GET/POST/PUT/DELETE | env bearer + bodies |
| 11 | **`auditverify/main.go:414` `readFromURL`/`fetchEventPage`** | GET | `--bearer` flag (`main.go:104/461`) |

**The design's enumeration is incomplete.** F5 lists tui/tokenscmd/sessionscmd/clientscmd but omits #11: `auditverify --from-url` builds a bare `&http.Client{Timeout: timeout}` with **no** `CheckRedirect` and sends `Authorization: Bearer <--bearer>` to `/api/v1/audit/events`. It is also a *separate construction path* (raw `http.Client`, not `apiclient.New`), so even a hypothetical "flip the `New` default" would not touch it. The "verified same pattern" claim is factually wrong as stated.

Severity nuance (Go stdlib semantics, `client.go:1005-1022`, `redirectBehavior`): Go strips `Authorization` only on redirects to a *different registrable domain*. Same-host-different-port (the repro's exact `127.0.0.1:portA→portB` scenario) and subdomain redirects **forward the bearer for every method and code**, and 307/308 replay the request body to *any* host. So the residual leak is: same-host/subdomain bearer exfiltration (all 11 sites) plus cross-host 307/308 body replay (all write sites) — the F1 class, not a lesser variant.

## 2. Ruling on F5 deferral: not acceptable as a final state

The change fixes 3 of 11 sites. The verified F1 leak remains live on 8 sites across 5 commands after merge. The remaining work is one-line per site plus mirror tests — the design already identified the pattern, so deferral buys no risk reduction and leaves the headline vulnerability of the change open on 73% of the surface. Two options, both acceptable:

- **Recommended:** fold all 8 (incl. `auditverify`, one `CheckRedirect: rejectRedirect` line) into the same change — still one commit, one release note, ~4 extra one-liners over the design's 3.
- If deferral is kept anyway, it is only defensible as an explicitly-scoped interim (tracked, same release), and the F5 list must be corrected to include `auditverify`.

## 3. Bypass resistance of the fix (as designed)

- **Redirect chains:** not bypassable. `CheckRedirect` is consulted before *any* follow; `ErrUseLastResponse` returns the first 3xx response with nil error and the target is never contacted — chain depth, code (301/302/303/307/308), and scheme are all moot. Pinned by `TestNew_NoRedirect` (target counter = 0) and `TestWithNoRedirect_StopsFollowing`.
- **Scheme downgrade:** not bypassable. `rejectRedirect` is unconditional — there is no same-host exception, no https-only carve-out, no re-issue path. A downgrade requires a follow; no follow exists.
- **Second construction path within the fixed surface:** none. `entitiescmd` has exactly the 3 `apiclient.New()` sites, all in the shared helpers; `users.go` constructs nothing; no bare `http.Client` exists in the package. The env override in `New` (`apiclient.go:63-65`) runs after options and never touches `CheckRedirect`. **Repo-wide, however, the bypass exists** — #4-#11 construct redirect-following clients (and #11 isn't even `apiclient`), which is exactly why the F5 ruling above matters.

## 4. New error path leaks no credentials

Post-fix 3xx path: `"%s: %s failed (HTTP %d): %s"` — program name, verb, status, body, to stderr; exit 1.

- **No headers, no request URL.** On the 3xx path `Do` returns nil error (`ErrUseLastResponse` special case), so no `url.Error` string is printed; `Location` is never printed. Header values cannot reach the diagnostic.
- **Body echo discloses to no new party.** The 3xx body is produced only by the server that already received the request — and therefore already holds the bearer. The only readers of stderr are the operator who supplied the token and CI log collectors; if a compromised gateway echoes the token into its 3xx body, that gateway already possessed it. The identical body-echo behavior already exists for non-200 responses (pre-existing path); the fix merely extends it to 3xx, adding no new disclosure channel.
- Two hygiene notes, neither blocking: (a) `auditverify`'s error path prints full bodies and raw `url.Error` strings (which embed the URL) — if it joins this change, consider the repo's existing `redactURL`/`sanitizeBody` precedent (`sweep.go:214-248`) for parity; (b) a `SSO_ADMIN_ADDR` embedding userinfo would surface in transport-error strings — pre-existing, not introduced by this fix, and already mitigated probe-side by `redactURL`.

## Verdict

- Enumeration: **incomplete** — `auditverify/main.go:414` is a real, credential-bearing, redirect-following surface the design never names, and it uses a second construction path.
- F5 deferral: **unacceptable as a final state**; fold all 8 residual sites into the same change (or correct the F5 list and scope it explicitly).
- Bypass: **none** within the fixed surface — chains, downgrade, and re-construction are all closed by the unconditional `ErrUseLastResponse` policy, pinned by existing tests; the only "second path" is the deferred/omitted surface itself.
- Error path: **no credential leak** — no header/URL echo on the 3xx path, and body echo carries no new-party disclosure.
