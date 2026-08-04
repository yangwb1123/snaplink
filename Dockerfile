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
#
# FIPS 140-3 build (see docs/fips.md): pass --build-arg GOFIPS140=latest to
# link both binaries against Go's native FIPS 140-3 Cryptographic Module —
# NO cgo, NO BoringCrypto, same distroless-static runtime image. Default
# (unset / "off") produces a BYTE-IDENTICAL image to before this arg existed
# (verified: GOFIPS140=off and an unset GOFIPS140 build to identical output).
#   docker build --build-arg GOFIPS140=latest -t snaplink/sso-server-fips .
# Pair with keys.signing.fips_mode: true in config.yaml so the server
# ALSO validates its own signing-algorithm choice at startup — the build
# arg alone only affects Go's stdlib crypto, not this server's config.

# ---- builder ----
FROM golang:1.26-alpine AS builder

# GOFIPS140: "off" (default, byte-identical to no FIPS support at all) |
# "latest" | a pinned module version (e.g. "v1.0.0") | "inprocess" |
# "certified" — see docs/fips.md for the tradeoffs between these.
ARG GOFIPS140=off
ARG VERSION
ARG BUILD_TIME
ARG GIT_HASH
ARG BUILD_MODIFIED

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
RUN cd cmd/sso-mcp && go mod download

COPY infrastructure/extauthz/go.mod infrastructure/extauthz/go.sum ./infrastructure/extauthz/
RUN cd infrastructure/extauthz && go mod download

COPY infrastructure/kerberos/go.mod infrastructure/kerberos/go.sum ./infrastructure/kerberos/
RUN cd infrastructure/kerberos && go mod download

COPY infrastructure/kms/awskms/go.mod infrastructure/kms/awskms/go.sum ./infrastructure/kms/awskms/
RUN cd infrastructure/kms/awskms && go mod download

COPY infrastructure/kms/azurekeyvault/go.mod infrastructure/kms/azurekeyvault/go.sum ./infrastructure/kms/azurekeyvault/
RUN cd infrastructure/kms/azurekeyvault && go mod download

COPY infrastructure/kms/gcpkms/go.mod infrastructure/kms/gcpkms/go.sum ./infrastructure/kms/gcpkms/
RUN cd infrastructure/kms/gcpkms && go mod download

COPY infrastructure/kms/pkcs11/go.mod infrastructure/kms/pkcs11/go.sum ./infrastructure/kms/pkcs11/
RUN cd infrastructure/kms/pkcs11 && go mod download

COPY infrastructure/ldap/go.mod infrastructure/ldap/go.sum ./infrastructure/ldap/
RUN cd infrastructure/ldap && go mod download

COPY infrastructure/radius/go.mod infrastructure/radius/go.sum ./infrastructure/radius/
RUN cd infrastructure/radius && go mod download

COPY infrastructure/saml/go.mod infrastructure/saml/go.sum ./infrastructure/saml/
RUN cd infrastructure/saml && go mod download

# ── Layer 3: source code ──────────────────────────────────────────
COPY . .

# ═════════════════════════════════════════════════════════════════
# Build sso-server  (http REST + gRPC — the main binary)
# ═════════════════════════════════════════════════════════════════
# CGO_ENABLED=0 + -ldflags="-s -w" gives a self-contained, stripped
# binary that runs on distroless static. -trimpath strips local paths
# from stack traces for reproducibility. GOFIPS140 (see ARG above) is a
# pure-Go stdlib build flag — orthogonal to CGO_ENABLED=0, never requires it.
RUN resolved_build_time="${BUILD_TIME:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"; \
    resolved_git_hash="${GIT_HASH:-$(git rev-parse HEAD 2>/dev/null || true)}"; \
    resolved_modified="${BUILD_MODIFIED:-$(test -z "$(git status --porcelain 2>/dev/null)" || echo true)}"; \
    CGO_ENABLED=0 GOOS=linux GOFIPS140=${GOFIPS140} go build \
      -trimpath \
      -buildvcs=true \
      -ldflags="-s -w \
        -X github.com/yangwb1123/snaplink/shared/core.BuildVersion=${VERSION} \
        -X github.com/yangwb1123/snaplink/shared/core.BuildTime=${resolved_build_time} \
        -X github.com/yangwb1123/snaplink/shared/core.GitHash=${resolved_git_hash} \
        -X github.com/yangwb1123/snaplink/shared/core.BuildModified=${resolved_modified}" \
      -o /out/sso-server \
      ./cmd/sso-server

# ═════════════════════════════════════════════════════════════════
# Build sso-mcp  (MCP protocol gateway)
# ═════════════════════════════════════════════════════════════════
# sso-mcp is a nested module (has its own go.mod), so the build
# must run from ./cmd/sso-mcp with the module's own dependency
# tree. Identical hardening flags.
RUN cd cmd/sso-mcp && CGO_ENABLED=0 GOOS=linux GOFIPS140=${GOFIPS140} go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/sso-mcp \
    .

# ---- runtime: sso-mcp (target=sso-mcp) ----
FROM gcr.io/distroless/static:nonroot AS sso-mcp

COPY --from=builder /out/sso-mcp /sso-mcp

# MCP server listens on configurable port (default 8082).
EXPOSE 8082

USER nonroot:nonroot
ENTRYPOINT ["/sso-mcp"]

# ---- runtime: sso-server (default target) ----
FROM gcr.io/distroless/static:nonroot AS sso-server

COPY --from=builder /out/sso-server /sso-server

# HTTP REST surface (per consts.go: PathHealth, PathLogin, JWKS).
EXPOSE 8080
# gRPC back-channel (Authorizer, AuditWriter, Discovery).
EXPOSE 8081

USER nonroot:nonroot
ENTRYPOINT ["/sso-server"]
