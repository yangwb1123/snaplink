# Compatibility layer — delegates to Taskfile or Python CLI.
# Preferred: `task <target>` or `python cli.py <command>` (cross-platform).
# Keep: `make <target>` works on Linux/macOS via thin wrappers.

GO        ?= go
BIN_DIR   ?= bin
IMAGE     ?= snaplink/sso-server
IMAGE_TAG ?= dev

CLI = python cli.py

.PHONY: help test race bench vet fmt build docker ci ci-modules clean proto-lint proto-breaking proto-gen docs-validate docs-serve release-snapshot release-check security-scan load-test load-test-record load-test-compare load-test-ci lint generate-engineering harness filesize complexity architecture coverage coverage-check evaluate check-exemptions self-test check-invariants review health-report diagnose trend acceptance examples lint-all bench-all config-validate config-validate-all k8s-render k8s-diff

# ── Go Dev (via $GO directly for speed) ──────────────────────────────

help:
	@awk 'BEGIN {FS = ":.*## "; printf "make targets:\n"} \
		/^[a-zA-Z_-]+:.*## / {printf "  %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

test: ## Run unit tests.
	$(GO) test ./...

race: ## Run tests with the race detector.
	$(GO) test -race -count=1 ./...

bench: ## Run benchmarks.
	$(GO) test -run='^$$' -bench=. -benchmem ./...

bench-all: ## Run benchmarks on all packages (same as bench).
	$(GO) test -run='^$$' -bench=. -benchmem ./...

load-test: ## Load-test /token (requires k6).
	@command -v k6 >/dev/null 2>&1 || { echo "k6 not installed" >&2; exit 1; }
	k6 run ops/deploy/loadtest/token.js

vet: ## Static analysis.
	$(GO) vet ./...

lint: ## Run golangci-lint.
	$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest run --timeout 5m

lint-all: ## Run golangci-lint on all nested modules.
	find . -name go.mod -not -path './.git/*' -execdir sh -c 'echo "=== lint $$(pwd) ===" && golangci-lint run --timeout 5m' \;

security-scan: ## SAST/SCA (govulncheck + gosec).
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...
	$(GO) run github.com/securego/gosec/v2/cmd/gosec@latest -quiet ./...

fmt: ## Check gofmt.
	@unformatted=$$(gofmt -l . | grep -v '^\.claude/'); \
	if [ -n "$$unformatted" ]; then \
		echo "Unformatted files:" >&2; \
		echo "$$unformatted" >&2; \
		exit 1; \
	fi

build: ## Compile to $(BIN_DIR)/.
	$(CLI) build

examples: ## Compile example apps to ensure they stay buildable.
	$(GO) build ./docs/examples/...

config-validate: ## Validate all deploy config.yaml files against current server.
	@echo "==> Validating all config.yaml files..."
	@fail=0; \
	for cfg in cmd/sso-server/config.yaml bin/config.yaml ops/deploy/compose/config.yaml ops/deploy/baremetal-ha/sso/config.yaml ops/deploy/k8s/config.yaml ops/deploy/k8s-prod/config.yaml docs/examples/basic/config.yaml; do \
		echo -n "  $$cfg ... "; \
		if [ -f "$$cfg" ]; then \
			if $(GO) run ./cmd/sso-server --config="$$cfg" --validate-only 2>/dev/null; then \
				echo "OK"; \
			else \
				echo "FAIL"; fail=1; \
			fi; \
		else \
			echo "SKIP (not found)"; \
		fi; \
	done; \
	exit $$fail

docker: ## Build container image.
	docker build -t $(IMAGE):$(IMAGE_TAG) .

proto-lint: ## Lint .proto files.
	cd proto && $(GO) run github.com/bufbuild/buf/cmd/buf@latest lint

proto-gen: ## Generate Go code from .proto files.
	cd proto && buf generate

proto-breaking: ## Check proto wire-breaking vs main.
	cd proto && $(GO) run github.com/bufbuild/buf/cmd/buf@latest breaking \
		--against "../.git#branch=main,subdir=proto"

docs-validate: ## Validate openapi.yaml.
	@$(GO) run github.com/getkin/kin-openapi/cmd/validate@latest docs/openapi.yaml

release-check: ## Lint .goreleaser.yaml.
	$(GO) run github.com/goreleaser/goreleaser/v2@latest check

release-snapshot: ## goreleaser dry-run.
	$(GO) run github.com/goreleaser/goreleaser/v2@latest release --snapshot --clean --skip=publish

docs-serve: ## Serve openapi.yaml in swagger-ui.
	@echo "swagger-ui at http://localhost:8088 (ctrl-c to stop)"
	@docker run --rm -p 8088:8080 \
		-e SWAGGER_JSON=/spec/openapi.yaml \
		-v $(PWD)/docs:/spec \
		swaggerapi/swagger-ui

playground: ## Run Web UI playground.
	@echo "SSO playground at http://localhost:8090 (ctrl-c to stop)"
	@go run ./examples/playground

ci-modules: ## Build + test all nested modules.
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
	cd cmd/sso-mcp && $(GO) build ./... && $(GO) test -race -count=1 ./...

ci: fmt vet race build examples proto-lint ci-modules ## Run CI checks.

mod-tidy-all: ## Run go mod tidy in all modules.
	find . -name go.mod -not -path './.git/*' -execdir go mod tidy \;

clean: ## Remove build artifacts.
	rm -rf $(BIN_DIR)

# ── Engineering System Gates (delegated to CLI) ──────────────────────

generate-engineering: ## Regenerate scaffolding
	$(CLI) generate

check-quick: filesize vet ## Fast post-edit check (filesize + vet). Same as `python cli.py check`.

check-filesize-direct: ## Direct filesize check (no scaffolding).
	$(CLI) check-filesize

harness: ## Full gates (regenerates + filesize + complexity + architecture).
	$(CLI) harness

filesize: ## File size check.
	$(CLI) check-filesize

complexity: ## Cyclomatic + cognitive complexity.
	$(CLI) complexity

architecture: ## Dependency direction.
	$(CLI) architecture

coverage: ## Test coverage report.
	$(CLI) coverage

coverage-check: ## Coverage regression check.
	$(CLI) coverage

acceptance: ## Full acceptance (EVALUATION.md).
	$(CLI) accept

evaluate: ## Coverage evaluation.
	$(CLI) evaluate

check-exemptions: ## Exemption list sync.
	$(CLI) check-exemptions

self-test: ## Harness self-test.
	$(CLI) self-test

check-invariants: ## Security invariants.
	$(CLI) check-invariants

review: ## Review checklist.
	$(CLI) review

diagnose: ## Run diagnosis.
	$(CLI) diagnose

trend: ## Record trend snapshot.
	$(CLI) trend

health-report: ## Health report.
	$(CLI) health-report

# -------------------------------------------------------------------
# Release & Docker targets.
# -------------------------------------------------------------------

release-snapshot: ## Build snapshot binaries (local, no publish).
	goreleaser release --snapshot --clean

release: ## Build + publish to GitHub Releases (requires git tag).
	goreleaser release --clean

docker-push: ## Build + push multi-arch Docker image (requires git tag).
	docker buildx build --platform linux/amd64,linux/arm64 \
		-t ghcr.io/snaplink/sso-server:latest \
		--push .

docker-multiarch: ## Build local multi-arch manifest (no push).
	docker buildx build --platform linux/amd64,linux/arm64 \
		-t snaplink/sso-server:multiarch --load .

lint-all: ## Run golangci-lint on root + all nested modules.
	golangci-lint run ./...
	@for dir in infrastructure/kms/awskms infrastructure/kms/gcpkms infrastructure/kms/azurekeyvault infrastructure/kms/pkcs11 infrastructure/redis infrastructure/saml infrastructure/ldap infrastructure/kerberos infrastructure/radius infrastructure/extauthz; do \
		echo "linting $$dir..."; \
		cd "$$dir" && golangci-lint run ./...; \
		cd "$(CURDIR)"; \
	done

security-scan-all: ## Run gosec on root + all nested modules.
	go run github.com/securego/gosec/v2/cmd/gosec@latest -no-fail ./...
	@for dir in infrastructure/kms/awskms infrastructure/kms/gcpkms infrastructure/kms/azurekeyvault infrastructure/kms/pkcs11 infrastructure/redis infrastructure/saml infrastructure/ldap infrastructure/kerberos infrastructure/radius infrastructure/extauthz; do \
		echo "gosec $$dir..."; \
		cd "$$dir" && go run github.com/securego/gosec/v2/cmd/gosec@latest -no-fail ./...; \
		cd "$(CURDIR)"; \
	done

config-validate-all: ## Validate all 7 deploy config files against the server.
	@for cfg in cmd/sso-server/config.yaml bin/config.yaml ops/deploy/compose/config.yaml ops/deploy/baremetal-ha/sso/config.yaml ops/deploy/k8s/config.yaml ops/deploy/k8s-prod/config.yaml docs/examples/basic/config.yaml; do \
		echo -n "$$cfg ... "; \
		if go run ./cmd/sso-server --config="$$cfg" --validate-only 2>/dev/null; then \
			echo "OK"; \
		else \
			echo "FAIL"; \
		fi; \
	done

smoke-test: ## Run smoke tests against a running server.
	sh ops/deploy/baremetal-ha/smoke.sh

k8s-render: ## Render all Kustomize overlays to flat YAML for auditing.
	@command -v kustomize >/dev/null 2>&1 || { echo "kustomize not installed" >&2; exit 1; }
	@mkdir -p $(BIN_DIR)/k8s-rendered/dev $(BIN_DIR)/k8s-rendered/prod
	@echo "==> Rendering k8s (dev)..."
	kustomize build ops/deploy/k8s > $(BIN_DIR)/k8s-rendered/dev/all.yaml
	@echo "==> Rendering k8s-prod..."
	kustomize build ops/deploy/k8s-prod > $(BIN_DIR)/k8s-rendered/prod/all.yaml
	@echo "Rendered YAML in $(BIN_DIR)/k8s-rendered/"

k8s-diff: ## Diff rendered output between dev and prod overlays.
	@command -v kustomize >/dev/null 2>&1 || { echo "kustomize not installed" >&2; exit 1; }
	@mkdir -p $(BIN_DIR)/k8s-rendered/dev $(BIN_DIR)/k8s-rendered/prod
	@kustomize build ops/deploy/k8s > $(BIN_DIR)/k8s-rendered/dev/all.yaml
	@kustomize build ops/deploy/k8s-prod > $(BIN_DIR)/k8s-rendered/prod/all.yaml
	@echo "==> Diff between dev and prod overlays:"
	@diff $(BIN_DIR)/k8s-rendered/dev/all.yaml $(BIN_DIR)/k8s-rendered/prod/all.yaml || true

# ── Terraform Infrastructure ──────────────────────────────────────

terraform-validate: ## Validate Terraform configurations.
	@command -v terraform >/dev/null 2>&1 || { echo "terraform not installed" >&2; exit 1; }
	@echo "==> Validating Terraform..."
	cd ops/deploy/terraform && terraform init -backend=false -input=false >/dev/null
	cd ops/deploy/terraform && terraform validate
	@echo "Terraform configuration is valid"

terraform-plan-dev: ## Plan Terraform changes for dev environment.
	@command -v terraform >/dev/null 2>&1 || { echo "terraform not installed" >&2; exit 1; }
	@echo "==> Planning Terraform (dev)..."
	cd ops/deploy/terraform && terraform init -backend=false -input=false >/dev/null
	cd ops/deploy/terraform && terraform plan -var-file="environments/dev/terraform.tfvars"

terraform-plan-prod: ## Plan Terraform changes for prod environment.
	@command -v terraform >/dev/null 2>&1 || { echo "terraform not installed" >&2; exit 1; }
	@echo "==> Planning Terraform (prod)..."
	cd ops/deploy/terraform && terraform init -backend=false -input=false >/dev/null
	cd ops/deploy/terraform && terraform plan -var-file="environments/prod/terraform.tfvars"

# ── License Compliance ───────────────────────────────────────────────

licenses: ## Generate dependency license report (CSV) + check for forbidden licenses.
	@echo "==> Installing go-licenses..."
	@which go-licenses 2>/dev/null || go install github.com/google/go-licenses/v2@latest
	@mkdir -p $(BIN_DIR)
	@echo "==> Generating dependency-license CSV -> $(BIN_DIR)/licenses.csv..."
	@go-licenses csv ./... > $(BIN_DIR)/licenses.csv 2>/dev/null || true
	@echo "==> Checking for forbidden licenses (GPL/AGPL/SSPL)..."
	@go-licenses check ./... 2>&1 || echo "[WARN] go-licenses check found issues — review $(BIN_DIR)/licenses.csv for details"
	@echo "==> License report written to $(BIN_DIR)/licenses.csv"
	@wc -l < $(BIN_DIR)/licenses.csv | xargs -I{} echo "    {} dependencies catalogued"

licenses-check: ## CI gate: reject GPL/AGPL/SSPL dependencies.
	@echo "==> Checking for forbidden licenses (CI gate)..."
	@which go-licenses 2>/dev/null || go install github.com/google/go-licenses/v2@latest
	@go-licenses check ./... 2>&1; status=$$?; \
	if [ $$status -ne 0 ]; then \
		echo "FAIL: Forbidden license detected — GPL/AGPL/SSPL are not allowed."; \
		echo "      Run 'make licenses' for the full report."; \
		exit 1; \
	fi; \
	echo "OK: All dependencies use permitted licenses"

licenses-notice: ## Generate NOTICE.txt for distribution (Apache 2.0 §4).
	@echo "==> Generating NOTICE.txt..."
	@which go-licenses 2>/dev/null || go install github.com/google/go-licenses/v2@latest
	@go-licenses csv ./... 2>/dev/null | awk -F, '$$2 ~ /Apache-2\.0/ {print "This software includes " $$1 " under the Apache License 2.0:"}' > NOTICE.txt
	@echo "" >> NOTICE.txt
	@echo "Full dependency list: see licenses.csv (make licenses)" >> NOTICE.txt
	@echo "NOTICE.txt written ($$(wc -l < NOTICE.txt) lines)"

.PHONY: licenses licenses-check licenses-notice release-snapshot release docker-push docker-multiarch lint-all security-scan-all config-validate-all smoke-test k8s-render k8s-diff terraform-validate terraform-plan-dev terraform-plan-prod
