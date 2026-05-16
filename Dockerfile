# Multi-stage build for cmd/sso-server. Stage 1 compiles a fully static
# binary inside the official Go toolchain image; stage 2 ships only the
# binary on a distroless base so the runtime image is tiny (~20MB) and
# has no shell / no package manager / no userland tools an attacker can
# pivot through.
#
# Build:    docker build -t snaplink/sso-server .
# Run:      docker run --rm -p 8080:8080 -p 8081:8081 \
#               -v $(pwd)/cmd/sso-server/config.yaml:/etc/sso/config.yaml \
#               snaplink/sso-server --config /etc/sso/config.yaml
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

# Cache the module download as its own layer so source edits don't
# re-pull go.sum on every build.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0 + -ldflags="-s -w" gives a self-contained, stripped
# binary that runs on distroless static. -trimpath strips local paths
# from stack traces for reproducibility.
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/sso-server \
    ./cmd/sso-server

# ---- runtime ----
# distroless/static is the right base for a static Go binary: no libc,
# no shell, runs as UID 65532 (nonroot) by default. The :nonroot tag
# pins that UID even if the upstream default changes.
FROM gcr.io/distroless/static:nonroot

COPY --from=builder /out/sso-server /sso-server

# HTTP REST surface (per consts.go: PathHealth, PathLogin, JWKS).
EXPOSE 8080
# gRPC back-channel (Authorizer, AuditWriter, Discovery).
EXPOSE 8081

USER nonroot:nonroot
ENTRYPOINT ["/sso-server"]
