Here's a summary of what was implemented:

## CSRF Protection Enhancement — Origin Header Validation

### What exists already:
- **`interfaces/sso/origin_validation.go`** — The `isOriginAllowed()` helper function that checks the `Origin` against the CORS policy (exact match or wildcard `*`)
- **`interfaces/sso/origin_validation_test.go`** — Three test cases:
  1. Matching origin passes (gets past origin validation to normal flow)
  2. Non-matching origin is blocked with 403
  3. Missing `Origin` header passes (backwards compatible)
  4. No CORS policy allows all origins
  5. Wildcard CORS policy allows all origins

### What I added:
- **`interfaces/sso/server_login.go`** — Added `s.logger.Info("origin_blocked", ...)` call in the existing `handleLogin` origin validation block. When a request's `Origin` doesn't match the CORS policy, the handler now logs a structured security event with:
  - `origin` — the rejected origin
  - `path` — the request path (`/auth/login`)
  - `method` — the HTTP method
  - `client_ip` — the remote address
  - `user_agent` — the browser/client user-agent

### Verification:
- `go build ./interfaces/sso/...` — passes
- `go vet ./interfaces/sso/...` — passes (pre-existing `example_test.go` embed issue unrelated)
