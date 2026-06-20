# snaplink / sso

An OAuth 2.0 + OpenID Connect **SSO server**, shipped two ways: as a **Go SDK** you
embed as a library, and as a **runnable binary** you configure with YAML. Pure
Go (no CGO), no external SaaS dependencies; in-memory and pure-Go SQLite default
backends, with optional etcd / Redis for clustering.

```
import "github.com/snaplink/sso/interfaces/sso"     // the public SDK
go build ./cmd/sso-server                           // the runnable server
go build ./cmd/sso-ctl                              // the offline operator CLI
```

---

## Which surface do I want?

| You are… | Use | Entry point |
|---|---|---|
| A Go app that wants to **embed an SSO server** | **Go SDK / library** | `interfaces/sso` → `sso.NewServer(...).Handler()` |
| An operator who wants to **run a server** | **Binary** | `cmd/sso-server` + `config.yaml` |
| A downstream app **consuming** an SSO (verify tokens, authorize, audit) | **Client packages** | `interfaces/ssoclient` (`local` / `remote` / `dev`) |
| A relying party / SPA / resource server (any language) | **HTTP OAuth2/OIDC + gRPC** | `/.well-known/openid-configuration`, `/token`, `/userinfo`, `/api/v1/admin/*` |
| An operator running offline maintenance | **CLI** | `sso-ctl` (`audit-verify` / `import` / `migrate` / `snapshot`) |

---

## 30-second tour (actually runnable)

A complete, self-contained end-to-end demo — embeds the server, then drives a
full Authorization Code + PKCE flow and verifies the issued JWT locally:

```bash
go run ./docs/examples/quickstart
```

```
snaplink SSO quickstart -- in-memory server at http://127.0.0.1:NNNNN

[1] discovery   issuer=...  token=.../token  userinfo=.../userinfo  jwks=.../.well-known/jwks.json
[2] login       authorization_code + PKCE -> code=PW85OdRdHcmkty_EPw...
[3] token       access_token=eyJhbGciOiJFZERTQS...  id_token=eyJhbGciOiJFZERTQS...
[4] userinfo    map[amr:[pwd] auth_time:... sub:user-alice]
[5] local verify (signature checked against cached JWKS, no server call)  subject=user-alice  scopes=[openid profile email]

OK -- end-to-end OAuth2/OIDC flow complete.
```

Read `docs/examples/quickstart/main.go` — it is ~180 lines and exercises the SDK,
the wire API, and the remote-consumer verify path in one file.

---

## 1. Embed as a Go library (the SDK)

Construct a `*sso.Server` with functional options, then serve `srv.Handler()` on
any `net/http` listener. There is **one** constructor, `sso.NewServer`.

```go
import (
    "net/http"
    "github.com/snaplink/sso/infrastructure/defaultimpl"
    "github.com/snaplink/sso/interfaces/sso"
)

issuer := defaultimpl.NewEd25519JWTIssuer()
srv := sso.NewServer(
    sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),   // 3 mandatory SPIs
    sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
    sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
    sso.WithTokenIssuer("jwt", issuer),                          // access-token signer
    sso.WithIDTokenIssuer(issuer),                               // OIDC id_token (same key)
    sso.WithDefaultTokenStrategy("jwt"),
    sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), 0), // enables authorization_code
)
http.ListenAndServe(":8080", srv.Handler())   // Handler() calls Mount() for you
```

Key ideas:

- **Grants are opt-in by store option.** Wire `WithRefreshTokenStore` to enable
  `refresh_token` (with family rotation), `WithPARStore` for `/par`,
  `WithDeviceCodeStore` for the device flow, `WithDynamicClientRegistration` for
  `/register`, `WithCIBA` for backchannel auth. Omit one → that endpoint returns
  `501`.
- **Bring your own backends.** Implement the `sso.UserProvider` / `ClientStore` /
  `SessionManager` / `TokenIssuer` / `Authenticator` interfaces (all re-exported
  in `interfaces/sso/aliases.go`), or use `infrastructure/defaultimpl` (memory)
  / `infrastructure/defaultimpl/sqlite` (pure-Go, persistent).
- **~90 `WithXxx` options** cover security, multi-tenancy, observability, MFA,
  federation, CAEP, and embedded SPAs. See `interfaces/sso/options*.go`.

Examples: `docs/examples/quickstart`, `docs/examples/basic` (all 7 auth
methods), and the godoc `Example_minimumViable` / `Example_productionWiring` in
`interfaces/sso/example_test.go`.

## 2. Run the binary

No Go code — drive it with a YAML config:

```yaml
# config.yaml  (see docs/examples/basic/config.yaml)
server:
  issuer: https://sso.example.com      # your canonical public URL (not the SDK default)
  listen: ":8080"
  default_token_strategy: jwt
clients:
  - id: web-app
    secret: web-secret
    redirect_uris: [ "http://localhost:3000/callback" ]
    allowed_scopes: [ openid, profile, email ]
    allowed_authenticators: [ password ]
    active: true
authenticators:
  password: { enabled: true }
```

```bash
go build -o sso-server ./cmd/sso-server
./sso-server -config config.yaml        # HTTP on :8080, gRPC on :8081 (in-memory backends, OIDC on)
```

Config resolves low→high: **file < env (`SSO_SERVER__LISTEN=:9090`) < etcd (opt-in) < flags**.
TLS is terminated in-process only when both `-tls-cert` and `-tls-key` are given;
otherwise put a TLS-terminating edge (OpenResty / Envoy / NGINX) in front.

## 3. Consume from a downstream app (`ssoclient`)

A downstream service does **not** do login (that is the SSO server's HTTP
surface). It only **verifies** the issued token and answers authorization
questions. Write business code against the three interfaces and pick a backend
per capability at startup:

```go
import (
    "google.golang.org/grpc"
    "github.com/snaplink/sso/interfaces/ssoclient/remote"
)

// REMOTE mode — talk to a central SSO. Token verification is LOCAL (cached
// JWKS), so the SSO server is off the per-request hot path.
conn, _ := grpc.NewClient("sso:8081", grpc.WithTransportCredentials(insecure.NewCredentials()))
jwks := remote.NewJWKSCache("http://sso:8080/.well-known/jwks.json")

auth  := remote.NewAuthClient(jwks)     // ValidateToken / Logout
authz := remote.NewAuthzClient(conn)    // Check / ListPermissions / ListRoles / GetMenus (gRPC)
audit := remote.NewAuditClient(conn)    // Record (gRPC)

subj, _ := auth.ValidateToken(ctx, bearerToken)
ok, _   := authz.Check(ctx, &ssoclient.CheckRequest{SubjectID: subj.ID, Permission: "items:read"})
```

Backends: `local` (in-process embed), `remote` (gRPC + JWKS), `dev` (allow-all
stub for development — prints an AUTH-BYPASS warning), `bootstrap` (versioned
first-run init). Business code is identical across modes — see
`docs/examples/{appcore,remote-app,embedded-app}`.

## 4. Call over the wire (HTTP OAuth2/OIDC + gRPC)

Any language hits the standard endpoints (contract: `docs/openapi.yaml`):

```bash
curl https://sso.example.com/.well-known/openid-configuration   # discovery
curl https://sso.example.com/.well-known/jwks.json              # signing keys

# login (JSON; PKCE captured here) -> authorization code
curl -X POST https://sso.example.com/auth/login -H 'Content-Type: application/json' -d '{
  "provider":"password","client_id":"web-app","response_type":"code",
  "redirect_uri":"http://localhost:3000/callback","scope":["openid","profile"],
  "code_challenge":"<S256>","code_challenge_method":"S256",
  "credential":{"username":"alice","password":"..."}}'

# exchange the code at /token
curl -X POST https://sso.example.com/token -H 'Content-Type: application/json' -d '{
  "grant_type":"authorization_code","code":"<CODE>","client_id":"web-app",
  "client_secret":"web-secret","redirect_uri":"http://localhost:3000/callback",
  "code_verifier":"<VERIFIER>"}'

curl https://sso.example.com/userinfo -H 'Authorization: Bearer <ACCESS_TOKEN>'
```

A **gRPC + REST admin/control plane** runs alongside (gRPC `:8081`; the same
admin services are exposed as REST under `/api/v1/admin/*`, gated by the
`admin:read` / `admin:write` scope):

```bash
curl -X POST https://sso.example.com/api/v1/admin/clients \
  -H 'Authorization: Bearer <ADMIN_TOKEN>' -d '{"client":{"client_id":"new-app","redirect_uris":["https://new-app/cb"]}}'
```

`.proto` definitions (and their REST mappings) live in `proto/`; generated stubs
in `gen/proto/`. A Go gRPC client example is `docs/examples/grpc-client`.

## 5. Operator CLI (`sso-ctl`)

`cmd/` builds exactly two binaries — `sso-server` (runtime) and `sso-ctl`
(offline toolbelt):

```bash
make build      # or: python cli.py build   ->   ./bin/{sso-server, sso-ctl}

sso-ctl audit-verify --from-url https://sso --bearer "$ADMIN_TOKEN"   # verify the audit hash chain
sso-ctl import --dsn file:sso.db --format auth0|keycloak|csv --file export.json
sso-ctl migrate status --dsn 'file:sso.db?mode=ro' --json
sso-ctl snapshot verify --dir ./snapshots --id <id> --passphrase-file pass.txt
```

All are offline except `audit-verify --from-url` (which calls the live admin
audit API).

---

## Build & develop

The build/test entry point is `cli.py` (cross-platform); `make` / `Taskfile`
are thin wrappers.

```bash
python cli.py build          # -> ./bin/{sso-server, sso-ctl}
go build ./...               # compile everything
go test ./...                # unit + integration (package ssotest under test/)
go test ./test/ -race        # cross-wired HTTP + JWKS integration suite
```

## Further reading

- `docs/openapi.yaml` — the full HTTP API contract.
- `docs/examples/` — runnable samples (quickstart, basic, embedded-app, remote-app, appcore, grpc-client, playground).
- `interfaces/sso/example_test.go` — godoc SDK templates (render on pkg.go.dev).
- `AGENTS.md` — architecture, layering, and the engineering conventions enforced by the committed gates.
- `proto/` + `gen/proto/` — gRPC service + REST-gateway definitions.
