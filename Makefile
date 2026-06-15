# Common dev tasks. Mirrors what CI runs so "make ci" locally catches
# regressions before pushing. Pinned to the Go version in go.mod via
# `go` from PATH — keep the toolchain in sync via `go mod download`.

GO        ?= go
BIN_DIR   ?= bin
IMAGE     ?= snaplink/sso-server
IMAGE_TAG ?= dev

.PHONY: help test race bench vet fmt build docker ci ci-modules clean proto-lint proto-breaking docs-validate docs-serve release-snapshot release-check security-scan load-test lint harness filesize complexity architecture coverage coverage-check evaluate

help: ## Show this help.
	@awk 'BEGIN {FS = ":.*## "; printf "make targets:\n"} \
		/^[a-zA-Z_-]+:.*## / {printf "  %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

test: ## Run unit tests.
	$(GO) test ./...

race: ## Run tests with the race detector + no test cache.
	$(GO) test -race -count=1 ./...

bench: ## Run the hot-path benchmarks (token issue/validate, JWKS, param bind, rate limiter).
	$(GO) test -run='^$$' -bench=. -benchmem ./defaultimpl/ ./oauth/ ./ratelimit/ ./security/

load-test: ## Load-test the /token hot path against a RUNNING server (env: BASE_URL CLIENT_ID CLIENT_SECRET VUS DURATION). Requires k6.
	@command -v k6 >/dev/null 2>&1 || { echo "k6 not installed — see https://k6.io/docs/get-started/installation/" >&2; exit 1; }
	k6 run deploy/loadtest/token.js

vet: ## Static analysis (go vet).
	$(GO) vet ./...

lint: ## Run golangci-lint over the root module (.golangci.yml). Needs a go1.26-compatible golangci-lint; @latest tracks it.
	$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest run --timeout 5m

security-scan: ## Local SAST/SCA sweep over the root module (govulncheck CVEs + gosec). Mirrors the CI govulncheck + gosec jobs; CI also runs CodeQL + Trivy on GitHub infra.
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...
	$(GO) run github.com/securego/gosec/v2/cmd/gosec@latest -quiet ./...

fmt: ## Check gofmt; fails if any file needs formatting.
	@unformatted=$$(gofmt -l . | grep -v '^\.claude/'); \
	if [ -n "$$unformatted" ]; then \
		echo "Unformatted files:" >&2; \
		echo "$$unformatted" >&2; \
		exit 1; \
	fi

build: ## Compile cmd/sso-server and offline CLIs to $(BIN_DIR)/.
	@mkdir -p $(BIN_DIR)
	$(GO) build -trimpath -o $(BIN_DIR)/sso-server   ./cmd/sso-server
	$(GO) build -trimpath -o $(BIN_DIR)/sso-import   ./cmd/sso-import

docker: ## Build the sso-server container image.
	docker build -t $(IMAGE):$(IMAGE_TAG) .

proto-lint: ## Lint .proto files (MINIMAL ruleset, see proto/buf.yaml).
	cd proto && $(GO) run github.com/bufbuild/buf/cmd/buf@latest lint

proto-breaking: ## Check protos for wire-breaking changes vs main.
	cd proto && $(GO) run github.com/bufbuild/buf/cmd/buf@latest breaking \
		--against "../.git#branch=main,subdir=proto"

docs-validate: ## Validate docs/openapi.yaml against the OpenAPI 3 schema.
	@$(GO) run github.com/getkin/kin-openapi/cmd/validate@latest docs/openapi.yaml

release-check: ## Lint .goreleaser.yaml without building anything.
	$(GO) run github.com/goreleaser/goreleaser/v2@latest check

release-snapshot: ## Local goreleaser dry-run (no tag, no publish, full matrix).
	$(GO) run github.com/goreleaser/goreleaser/v2@latest release --snapshot --clean --skip=publish

docs-serve: ## Serve docs/openapi.yaml in swagger-ui on localhost:8088.
	@echo "swagger-ui at http://localhost:8088 (ctrl-c to stop)"
	@docker run --rm -p 8088:8080 \
		-e SWAGGER_JSON=/spec/openapi.yaml \
		-v $(PWD)/docs:/spec \
		swaggerapi/swagger-ui

playground: ## Run the interactive Web UI playground on localhost:8090.
	@echo "SSO playground at http://localhost:8090 (ctrl-c to stop)"
	@go run ./examples/playground

# ci-modules builds + tests each NESTED module separately. They are
# excluded from the root `go ... ./...` on purpose (kms/awskms carries
# aws-sdk-go-v2, kms/gcpkms carries cloud.google.com/go/kms, kms/azurekeyvault
# carries github.com/Azure/azure-sdk-for-go, kms/pkcs11 carries
# github.com/miekg/pkcs11 [cgo], redis carries go-redis, saml carries
# github.com/crewjam/saml [XML/DSig], ldap carries github.com/go-ldap/ldap/v3,
# extauthz carries github.com/envoyproxy/go-control-plane [Envoy ext_authz
# gRPC API], kerberos carries github.com/jcmturner/gokrb5/v8 [SPNEGO/Kerberos],
# radius carries layeh.com/radius [RADIUS/RFC 2865 client]
# — none MUST enter the core go.mod), so CI
# must enter each submodule explicitly. There is deliberately
# no go.work: a workspace would merge the build lists and surface those SDKs
# in the root module graph (`go list -m all`), blurring the core's
# zero-external-SDK invariant. Each submodule resolves the core module via
# its own `replace => ../` (or ../../).
ci-modules: ## Build + race-test the nested modules (kms/awskms, kms/gcpkms, kms/azurekeyvault, kms/pkcs11, redis, saml, ldap, extauthz, kerberos, radius).
	cd kms/awskms && $(GO) build ./... && $(GO) test -race -count=1 ./...
	cd kms/gcpkms && $(GO) build ./... && $(GO) test -race -count=1 ./...
	cd kms/azurekeyvault && $(GO) build ./... && $(GO) test -race -count=1 ./...
	cd kms/pkcs11 && $(GO) build ./... && $(GO) test -race -count=1 ./...
	cd redis && $(GO) build ./... && $(GO) test -race -count=1 ./...
	cd saml && $(GO) build ./... && $(GO) test -race -count=1 ./...
	cd ldap && $(GO) build ./... && $(GO) test -race -count=1 ./...
	cd extauthz && $(GO) build ./... && $(GO) test -race -count=1 ./...
	cd kerberos && $(GO) build ./... && $(GO) test -race -count=1 ./...
	cd radius && $(GO) build ./... && $(GO) test -race -count=1 ./...

ci: harness fmt vet race build proto-lint lint ci-modules ## Run the same checks CI runs.

# ───────────────────────────────────────────────
# Harness Engineering — 参见 HARNESS.md
# ───────────────────────────────────────────────

harness: filesize complexity architecture ## Run the harness gate suite.

filesize: ## GATE: 检查 .go 文件 ≤ 500 行。
	@bash .check-filesize.sh

complexity: ## GATE: 检查圈复杂度 ≤ 15。
	@bash .check-complexity.sh

architecture: ## GATE: 检查依赖方向。
	@bash .check-architecture.sh

# ───────────────────────────────────────────────
# Evaluation Engineering — 参见 EVALUATION.md
# ───────────────────────────────────────────────

coverage: ## 生成覆盖率报告。
	@mkdir -p $(BIN_DIR)
	$(GO) test -count=1 -coverprofile=$(BIN_DIR)/coverage.out ./...
	$(GO) tool cover -html=$(BIN_DIR)/coverage.out -o $(BIN_DIR)/coverage.html

coverage-check: ## GATE: 检查覆盖率。
	@bash .check-coverage.sh

evaluate: coverage coverage-check

clean: ## Remove build artifacts.
	rm -rf $(BIN_DIR)
