# Multi-stage build for cmd/sso-server, cmd/snaplink-billing,
# cmd/snaplink-stripe-adapter, cmd/snaplink-audit-provisioner and cmd/sso-mcp.
# The shared builder base owns dependencies and source; dedicated build stages
# compile one fully static binary each. The final sso-server runtime remains the
# default target. Named distroless targets build the other deployable units.
#
# Build sso-server:       docker build -t snaplink/sso-server .
# Build snaplink-billing: docker build --target snaplink-billing -t snaplink/billing .
# Build Stripe adapter:  docker build --target snaplink-stripe-adapter -t snaplink/stripe-adapter .
# Build audit provisioner: docker build --target snaplink-audit-provisioner -t snaplink/audit-provisioner .
# Build sso-mcp:          docker build --target sso-mcp -t snaplink/sso-mcp .
# Run sso-server:
#   docker run --rm -p 8080:8080 -p 8081:8081 \
#       -v $(pwd)/cmd/sso-server/config.yaml:/etc/sso/config.yaml \
#       snaplink/sso-server --config /etc/sso/config.yaml --grpc-insecure
#
# The image does NOT bake in a config file — operators bind-mount or
# template their own. The default cmd/sso-server/config.yaml in this
# repo is a good starting point but is tuned for local dev.
#
# FIPS 140-3 build (see docs/fips.md): pass --build-arg GOFIPS140=latest to
# link the selected binary against Go's native FIPS 140-3 Cryptographic Module —
# NO cgo, NO BoringCrypto, same distroless-static runtime image. Default
# (unset / "off") produces a BYTE-IDENTICAL image to before this arg existed
# (verified: GOFIPS140=off and an unset GOFIPS140 build to identical output).
#   docker build --build-arg GOFIPS140=latest -t snaplink/sso-server-fips .
# Pair with keys.signing.fips_mode: true in config.yaml so the server
# ALSO validates its own signing-algorithm choice at startup — the build
# arg alone only affects Go's stdlib crypto, not this server's config.

# ---- shared builder base ----
FROM golang:1.26-alpine AS builder-base

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
# The distroless runtime has no shell or network tools; build the tiny Go
# health probe (test/oidc-conformance/healthcheck) fully static for the
# compose healthcheck and debug exec.
FROM builder-base AS sso-server-builder

RUN cd test/oidc-conformance/healthcheck && CGO_ENABLED=0 go build -o /out/healthcheck .

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
# Build snaplink-billing  (API-only commerce + metering runtime)
# ═════════════════════════════════════════════════════════════════
FROM builder-base AS snaplink-billing-builder

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
      -o /out/snaplink-billing \
      ./cmd/snaplink-billing

# ═════════════════════════════════════════════════════════════════
# Build snaplink-stripe-adapter  (optional out-of-process provider adapter)
# ═════════════════════════════════════════════════════════════════
FROM builder-base AS snaplink-stripe-adapter-builder

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
      -o /out/snaplink-stripe-adapter \
      ./cmd/snaplink-stripe-adapter

# ═════════════════════════════════════════════════════════════════
# Build snaplink-audit-provisioner  (create-only governance control plane)
# ═════════════════════════════════════════════════════════════════
FROM builder-base AS snaplink-audit-provisioner-builder

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
      -o /out/snaplink-audit-provisioner \
      ./cmd/snaplink-audit-provisioner

# ═════════════════════════════════════════════════════════════════
# Build sso-mcp  (MCP protocol gateway)
# ═════════════════════════════════════════════════════════════════
# sso-mcp is a nested module (has its own go.mod), so the build
# must run from ./cmd/sso-mcp with the module's own dependency
# tree. Identical hardening flags.
FROM builder-base AS sso-mcp-builder

RUN cd cmd/sso-mcp && CGO_ENABLED=0 GOOS=linux GOFIPS140=${GOFIPS140} go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/sso-mcp \
    .

# ---- runtime: sso-mcp (target=sso-mcp) ----
FROM gcr.io/distroless/static:nonroot AS sso-mcp

COPY --from=sso-mcp-builder /out/sso-mcp /sso-mcp

# MCP server listens on configurable port (default 8082).
EXPOSE 8082

USER nonroot:nonroot
ENTRYPOINT ["/sso-mcp"]

# ---- runtime: snaplink-billing (target=snaplink-billing) ----
FROM gcr.io/distroless/static:nonroot AS snaplink-billing

COPY --from=snaplink-billing-builder /out/snaplink-billing /snaplink-billing

# Plaintext is loopback-only; expose through a same-Pod trusted TLS edge.
EXPOSE 8090

USER nonroot:nonroot
ENTRYPOINT ["/snaplink-billing"]

# ---- runtime: snaplink-stripe-adapter (target=snaplink-stripe-adapter) ----
FROM gcr.io/distroless/static:nonroot AS snaplink-stripe-adapter

COPY --from=snaplink-stripe-adapter-builder /out/snaplink-stripe-adapter /snaplink-stripe-adapter

# Production deployments use the adapter's built-in TLS on this port.
EXPOSE 8443

USER nonroot:nonroot
ENTRYPOINT ["/snaplink-stripe-adapter"]

# ---- runtime: snaplink-audit-provisioner (target=snaplink-audit-provisioner) ----
FROM gcr.io/distroless/static:nonroot AS snaplink-audit-provisioner

COPY --from=snaplink-audit-provisioner-builder /out/snaplink-audit-provisioner /snaplink-audit-provisioner

EXPOSE 8092

USER nonroot:nonroot
ENTRYPOINT ["/snaplink-audit-provisioner"]

# ---- runtime: sso-server (default target; keep this stage last) ----
FROM gcr.io/distroless/static:nonroot AS sso-server

COPY --from=sso-server-builder /out/sso-server /sso-server
COPY --from=sso-server-builder /out/healthcheck /healthcheck

# HTTP REST surface (per consts.go: PathHealth, PathLogin, JWKS).
EXPOSE 8080
# gRPC back-channel (Authorizer, AuditWriter, Discovery).
EXPOSE 8081

USER nonroot:nonroot
ENTRYPOINT ["/sso-server"]
