# sso-mcp

`sso-mcp` is a separately versioned MCP gateway for Snaplink's read-only
identity and authorization APIs. It is a nested Go module and is not embedded
in `sso-server`.

## Tools

| Tool | Result |
|---|---|
| `introspect_token` | Validates a Snaplink access token with JWKS and returns selected claims |
| `check_permission` | Checks one permission for a subject and client |
| `list_permissions` | Lists effective permissions |
| `list_roles` | Lists effective roles |
| `get_menus` | Returns the permitted menu tree |

Authorization queries use Snaplink's gRPC `Authorizer`. Token validation uses
the remote JWKS client under `interfaces/ssoclient/remote`.

## Run

```bash
cd cmd/sso-mcp
go build ./...
go test -race ./...

go run . \
  --transport http \
  --jwks-url https://sso.example.com/.well-known/jwks.json \
  --issuer https://sso.example.com \
  --resource https://mcp.example.com/
```

HTTP mode listens on `:8090` by default and exposes:

- `/mcp` — Streamable HTTP MCP transport;
- `/.well-known/oauth-protected-resource` — RFC 9728 metadata;
- `/livez` and `/readyz` — process and gRPC-connection probes.

Flags take precedence over the corresponding environment variables:

| Flag | Environment | Default |
|---|---|---|
| `--transport` | `SSO_MCP_TRANSPORT` | `http` |
| `--listen` | `SSO_MCP_LISTEN` | `:8090` |
| `--snaplink-grpc` | `SSO_MCP_SNAPLINK_GRPC` | `localhost:8081` |
| `--jwks-url` | `SSO_MCP_JWKS_URL` | required |
| `--issuer` | `SSO_MCP_ISSUER` | empty |
| `--resource` | `SSO_MCP_RESOURCE` | required in HTTP mode |
| `--required-scope` | `SSO_MCP_REQUIRED_SCOPE` | `mcp:read` |

## Security boundary

HTTP mode requires a bearer token whose signature and expiry validate against
JWKS, whose audience contains `--resource`, and whose scopes contain
`--required-scope`. Stdio mode trusts the host process, but
`introspect_token` still needs `--jwks-url`.

The downstream Authorizer gRPC client currently uses plaintext transport
without credentials. Keep that port on a trusted loopback or mesh boundary;
the HTTP resource-server gate protects the MCP endpoint, not direct access to
the Authorizer service.
