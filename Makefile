# Common dev tasks. Mirrors what CI runs so "make ci" locally catches
# regressions before pushing. Pinned to the Go version in go.mod via
# `go` from PATH — keep the toolchain in sync via `go mod download`.

GO        ?= go
BIN_DIR   ?= bin
IMAGE     ?= snaplink/sso-server
IMAGE_TAG ?= dev

.PHONY: help test race vet fmt build docker ci clean proto-lint proto-breaking docs-validate docs-serve release-snapshot release-check

help: ## Show this help.
	@awk 'BEGIN {FS = ":.*## "; printf "make targets:\n"} \
		/^[a-zA-Z_-]+:.*## / {printf "  %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

test: ## Run unit tests.
	$(GO) test ./...

race: ## Run tests with the race detector + no test cache.
	$(GO) test -race -count=1 ./...

vet: ## Static analysis (go vet).
	$(GO) vet ./...

fmt: ## Check gofmt; fails if any file needs formatting.
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "Unformatted files:" >&2; \
		echo "$$unformatted" >&2; \
		exit 1; \
	fi

build: ## Compile cmd/sso-server to $(BIN_DIR)/sso-server.
	@mkdir -p $(BIN_DIR)
	$(GO) build -trimpath -o $(BIN_DIR)/sso-server ./cmd/sso-server

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

ci: fmt vet race build proto-lint ## Run the same checks CI runs.

clean: ## Remove build artifacts.
	rm -rf $(BIN_DIR)
