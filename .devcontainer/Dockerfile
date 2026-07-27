# Dev environment for github.com/yangwb1123/snaplink. Bookworm (glibc), not the
# runtime Dockerfile's golang:1.26-alpine — VS Code's remote server and
# tools like gopls/delve expect glibc, and this image is never shipped,
# only used locally / in Codespaces. Go version matches go.mod (`go
# 1.26.1`) and .github/workflows/*.yml (`go-version-file: go.mod` /
# `go-version: '1.26'`).
FROM golang:1.26-bookworm

# make: Makefile task runner (thin wrapper over `python cli.py` / go).
# git: module fetches from private VCS + DCO sign-off workflow.
# Python itself is added via the devcontainer "python" feature (see
# devcontainer.json) pinned to the version pyproject.toml declares
# (>=3.12), rather than whatever this Debian release ships by default.
RUN apt-get update && apt-get install -y --no-install-recommends \
        make \
        git \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# golangci-lint pinned to the version .github/workflows/ci.yml's lint
# job uses, so local `make lint` results match CI instead of drifting
# against whatever @latest resolves to on a given day.
RUN go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.1.0

# Root module has pure-Go, no-CGO default backends (defaultimpl/sqlite
# included) — CGO stays off by default so a plain `go build ./...`
# matches the smaller/portable build most contributors iterate against.
# `make build-with-pkcs11` explicitly re-enables it when needed.
ENV CGO_ENABLED=0

WORKDIR /workspace
