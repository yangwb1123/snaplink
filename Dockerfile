# Multi-stage build for cmd/sso-server and cmd/sso-mcp.
# Stage 0: builder — compiles both fully static binaries inside the
# official Go toolchain image. Stage 1a: sso-server runtime (distroless,
# default target). Stage 1b: sso-mcp runtime (distroless, target=build-mcp).
#
# Build sso-server:   docker build -t snaplink/sso-server .
# Build sso-mcp:      docker build --target sso-mcp -t snaplink/sso-mcp .
# Run sso-server:
#   docker run --rm -p 8080:8080 -p 8081:8081 \
#       -v $(pwd)/cmd/sso-server/config.yaml:/etc/sso/config.yaml \
#       snaplink/sso-server --config /etc/sso/config.yaml
#
# The image does NOT bake in a config file — operators bind-mount or
# template their own. The default cmd/sso-server/config.yaml in this
# repo is a good starting point but is tuned for local dev.

# ---- builder ----
FROM golang:1.26-alpine AS builder

# git is needed by `go build` when modules pull from a private VCS;
# harmless here, fixes the most-common future surprise.
RUN apk add --no-cache git ca-certificates

WORKDIR /src

# ── Layer 1: root module dependencies ─────────────────────────────
COPY go.mod go.sum ./
RUN go mod download

# ── Layer 2: sibling module dependencies (each in its own layer
#    so a source change in one doesn't invalidate another) ─────────
COPY cmd/sso-mcp/go.mod cmd/sso-mcp/go.sum ./cmd/sso-mcp/
RUN go mod download ./cmd/sso-mcp/

COPY infrastructure/extauthz/go.mod infrastructure/extauthz/go.sum ./infrastructure/extauthz/
RUN go mod download ./infrastructure/extauthz/

COPY infrastructure/kerberos/go.mod infrastructure/kerberos/go.sum ./infrastructure/kerberos/
RUN go mod download ./infrastructure/kerberos/

COPY infrastructure/kms/awskms/go.mod infrastructure/kms/awskms/go.sum ./infrastructure/kms/awskms/
RUN go mod download ./infrastructure/kms/awskms/

COPY infrastructure/kms/azurekeyvault/go.mod infrastructure/kms/azurekeyvault/go.sum ./infrastructure/kms/azurekeyvault/
RUN go mod download ./infrastructure/kms/azurekeyvault/

COPY infrastructure/kms/gcpkms/go.mod infrastructure/kms/gcpkms/go.sum ./infrastructure/kms/gcpkms/
RUN go mod download ./infrastructure/kms/gcpkms/

COPY infrastructure/kms/pkcs11/go.mod infrastructure/kms/pkcs11/go.sum ./infrastructure/kms/pkcs11/
RUN go mod download ./infrastructure/kms/pkcs11/

COPY infrastructure/ldap/go.mod infrastructure/ldap/go.sum ./infrastructure/ldap/
RUN go mod download ./infrastructure/ldap/

COPY infrastructure/radius/go.mod infrastructure/radius/go.sum ./infrastructure/radius/
RUN go mod download ./infrastructure/radius/

COPY infrastructure/saml/go.mod infrastructure/saml/go.sum ./infrastructure/saml/
RUN go mod download ./infrastructure/saml/

# ── Layer 3: source code ──────────────────────────────────────────
COPY . .

# ═════════════════════════════════════════════════════════════════
# Build sso-server  (http REST + gRPC — the main binary)
# ═════════════════════════════════════════════════════════════════
# CGO_ENABLED=0 + -ldflags="-s -w" gives a self-contained, stripped
# binary that runs on distroless static. -trimpath strips local paths
# from stack traces for reproducibility.
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/sso-server \
    ./cmd/sso-server

# ═════════════════════════════════════════════════════════════════
# Build sso-mcp  (MCP protocol gateway)
# ═════════════════════════════════════════════════════════════════
# sso-mcp is a nested module (has its own go.mod), so the build
# must run from ./cmd/sso-mcp with the module's own dependency
# tree. Identical hardening flags.
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/sso-mcp \
    ./cmd/sso-mcp

# ---- runtime: sso-server (default target) ----
FROM gcr.io/distroless/static:nonroot AS sso-server

COPY --from=builder /out/sso-server /sso-server

# HTTP REST surface (per consts.go: PathHealth, PathLogin, JWKS).
EXPOSE 8080
# gRPC back-channel (Authorizer, AuditWriter, Discovery).
EXPOSE 8081

USER nonroot:nonroot
ENTRYPOINT ["/sso-server"]

# ---- runtime: sso-mcp (target=build-mcp) ----
FROM gcr.io/distroless/static:nonroot AS sso-mcp

COPY --from=builder /out/sso-mcp /sso-mcp

# MCP server listens on configurable port (default 8082).
EXPOSE 8082

USER nonroot:nonroot
ENTRYPOINT ["/sso-mcp"]
