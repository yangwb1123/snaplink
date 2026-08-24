# Compatibility layer — delegates to Taskfile or Python CLI.
# Preferred: `task <target>` or `python cli.py <command>` (cross-platform).
# Keep: `make <target>` works on Linux/macOS via thin wrappers.

GO        ?= go
BIN_DIR   ?= bin
IMAGE     ?= snaplink/sso-server
IMAGE_TAG ?= dev
PROFILE   ?= standard
VERSION   ?= v0.0.0-dev
MODULE_ARGS ?=
VALIDATION_POSTGRES_DSN := postgres://validation@postgres.invalid/snaplink?sslmode=verify-full

CLI = python cli.py

.PHONY: help test ai-dev-test race bench vet fmt build configure build-profile build-prototype build-minimal build-full build-production build-small modules-list modules-plan modules-check modules-smoke capabilities-check capabilities-generate sdk-surface-diff docker docker-stripe-adapter ci ci-modules clean clean-all proto-lint proto-breaking proto-gen docs-validate docs-check docs-serve route-contract proto-openapi-parity adapters-check release-snapshot release-check security-scan security-scan-all load-test load-test-record load-test-compare load-test-ci lint generate-engineering harness filesize complexity architecture coverage coverage-check evaluate check-exemptions self-test check-invariants review health-report diagnose trend acceptance examples lint-all bench-all bench-gate bench-gate-record config-validate config-validate-all k8s-render k8s-diff helm-render docker-scan test-e2e backend-semantics chaos-test mod-tidy-all check-test skill-test adr-compliance playground dev

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

# Benchmark budget CI gate (ops/deploy/benchgate/): opt-in perf-regression
# check for the gated hot-path benchmark set (JWT issuance/validation, JWKS,
# OAuth store concurrency, param binding, rate limiting — see
# benchmarks.yaml). Deliberately NOT a dependency of `ci`/`race`: benchmarks
# are noisier and much slower than the race-detector suite other agents rely
# on as a hard, fast gate. Run manually pre-release, or from the separate,
# non-blocking .github/workflows/benchmark-gate.yml — never wire into a
# PR-blocking job.
bench-gate: ## Benchmark budget CI gate: fails if a gated hot-path benchmark regresses beyond threshold vs. baseline. Opt-in — NOT part of `make ci`.
	bash ops/deploy/benchgate/compare-baseline.sh

bench-gate-record: ## Regenerate ops/deploy/benchgate/baseline.txt from the current tree. Run manually after an accepted perf change.
	bash ops/deploy/benchgate/record-baseline.sh

load-test: ## Load-test the hot-path scenarios (requires k6).
	@command -v k6 >/dev/null 2>&1 || { echo "k6 not installed" >&2; exit 1; }
	k6 run ops/deploy/loadtest/token.js
	k6 run ops/deploy/loadtest/authcode.js
	k6 run ops/deploy/loadtest/introspect.js
	k6 run ops/deploy/loadtest/par.js
	k6 run ops/deploy/loadtest/discovery.js

load-test-record: ## Record load test baseline (SCENARIO=token|authcode|introspect|par|discovery).
	@command -v k6 >/dev/null 2>&1 || { echo "k6 not installed" >&2; exit 1; }
	@command -v jq >/dev/null 2>&1 || { echo "jq not installed" >&2; exit 1; }
	cd ops/deploy/loadtest && bash record-baseline.sh baseline.json

load-test-compare: ## Compare current load test results against baseline (threshold=20%%, SCENARIO).
	@command -v k6 >/dev/null 2>&1 || { echo "k6 not installed" >&2; exit 1; }
	@command -v jq >/dev/null 2>&1 || { echo "jq not installed" >&2; exit 1; }
	@command -v bc >/dev/null 2>&1 || { echo "bc not installed" >&2; exit 1; }
	cd ops/deploy/loadtest && bash compare-baseline.sh baseline.json ${THRESHOLD:-20}

load-test-ci: ## Run load test in CI (compare against baseline on target branch).
	@command -v k6 >/dev/null 2>&1 || { echo "k6 not installed" >&2; exit 1; }
	@command -v jq >/dev/null 2>&1 || { echo "jq not installed" >&2; exit 1; }
	@command -v bc >/dev/null 2>&1 || { echo "bc not installed" >&2; exit 1; }
	@echo "==> Load test CI: running baseline comparison..."
	@for scenario in token authcode; do \
		cd ops/deploy/loadtest && \
		if [ -f baseline-$$scenario.json ]; then \
			SCENARIO=$$scenario bash compare-baseline.sh baseline-$$scenario.json ${THRESHOLD:-20}; \
		else \
			SCENARIO=$$scenario bash record-baseline.sh baseline-$$scenario.json; \
		fi; \
	done

vet: ## Static analysis.
	$(GO) vet ./...

lint: ## Run golangci-lint.
	$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest run --timeout 5m

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

configure: ## Resolve PROFILE and write its module lock/build inputs.
	$(CLI) configure --profile $(PROFILE) --version $(VERSION) $(MODULE_ARGS)

build-profile: ## Build sso-server from PROFILE (default: standard).
	$(CLI) configure --profile $(PROFILE) --version $(VERSION) --build $(MODULE_ARGS)

modules-list: ## List cold/hot module catalog entries and migration state.
	$(CLI) modules list

modules-plan: ## Show dependency closure and blockers for PROFILE.
	$(CLI) modules plan --profile $(PROFILE) $(MODULE_ARGS)

modules-check: ## Validate module schemas, catalog, manifests, and profiles.
	$(CLI) modules check

modules-smoke: ## Build supported profiles plus every currently buildable preview.
	$(CLI) modules smoke

capabilities-check: ## Validate capability metadata and generated feature matrix.
	$(CLI) capabilities check

sdk-surface-check: ## Validate the generated-SDK surface registry against OpenAPI + capabilities.
	$(CLI) sdk-surface check

sdk-surface-diff: ## Compare SDK-surface registry with SDK_SURFACE_BASELINE_REF (required; local git ref).
	@test -n "$(SDK_SURFACE_BASELINE_REF)" || { echo "SDK_SURFACE_BASELINE_REF is required (for example: make sdk-surface-diff SDK_SURFACE_BASELINE_REF=HEAD^)" >&2; exit 1; }
	$(CLI) sdk-surface diff --baseline-ref "$(SDK_SURFACE_BASELINE_REF)"

profiles-evidence: ## Build + prove per-profile physical isolation (packages/modules/symbols/size).
	$(CLI) profiles evidence

capabilities-generate: ## Regenerate feature-matrix capability availability.
	$(CLI) capabilities generate

build-prototype: ## Build the OAuth SSO prototype tier.
	$(CLI) configure --profile prototype --version $(VERSION) --build $(MODULE_ARGS)

build-minimal: ## Build the common OAuth/OIDC SSO tier.
	$(CLI) configure --profile minimal --version $(VERSION) --build $(MODULE_ARGS)

build-full: ## Build the complete current Snaplink edition.
	$(CLI) configure --profile full --version $(VERSION) --build $(MODULE_ARGS)

build-production: build-full ## Compatibility alias for build-full.

build-small: build-prototype ## Compatibility alias for build-prototype.

build-with-pkcs11: ## Deprecated placeholder; PKCS#11 is not yet registered by a supported profile.
	@echo "PKCS#11 is a nested module but is not yet connected to the profile host API." >&2
	@echo "Use a custom composition today; track extraction with docs/plugin-system.md." >&2
	@exit 1

examples: ## Compile example apps to ensure they stay buildable.
	$(GO) build ./docs/examples/...

config-validate: ## Validate all deploy config.yaml files against current server.
	@echo "==> Validating all config.yaml files..."
	@fail=0; \
	for cfg in cmd/sso-server/config.yaml bin/config.yaml ops/deploy/compose/config.yaml ops/deploy/baremetal-ha/sso/config.yaml ops/deploy/k8s/config.yaml ops/deploy/k8s-prod/config.yaml docs/examples/basic/config.yaml; do \
		echo -n "  $$cfg ... "; \
		if [ -f "$$cfg" ]; then \
			if SSO_POSTGRES__DSN='$(VALIDATION_POSTGRES_DSN)' $(GO) run ./cmd/sso-server --config="$$cfg" --validate-only -grpc-insecure 2>/dev/null; then \
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

docker-stripe-adapter: ## Build the standalone Stripe adapter container target.
	docker build --target snaplink-stripe-adapter -t snaplink/stripe-adapter:$(IMAGE_TAG) .

proto-lint: ## Lint .proto files.
	cd proto && $(GO) run github.com/bufbuild/buf/cmd/buf@latest lint

proto-gen: ## Generate Go code from .proto files.
	cd proto && buf generate

proto-breaking: ## Check proto wire-breaking vs main.
	cd proto && $(GO) run github.com/bufbuild/buf/cmd/buf@latest breaking \
		--against "../.git#branch=main,subdir=proto"

docs-validate: route-contract capabilities-check ## Validate OpenAPI and generated capability docs.
	@$(GO) run github.com/getkin/kin-openapi/cmd/validate@latest docs/openapi.yaml

route-contract: ## Fail when a runtime route is absent from OpenAPI.
	$(CLI) check-routes

proto-openapi-parity: ## Fail when a proto message field drifts from its OpenAPI schema.
	$(CLI) check-proto-openapi-parity

adapters-check: ## Fail when the adapters delivery contract loses its evidence.
	$(CLI) adapters

docs-check: ## Validate documentation quality (cross-references, required files).
	@echo "=== Documentation Quality Check ==="
	@err=0; \
	for f in docs/error-codes.md docs/openapi.yaml docs/SECURITY.md .github/SECURITY.md; do \
		if [ ! -f "$$f" ]; then \
			echo "  [-] MISSING: $$f"; \
			err=1; \
		else \
			echo "  [+] $$f"; \
		fi; \
	done; \
	if grep -q 'docs/SECURITY.md' .github/SECURITY.md 2>/dev/null; then \
		echo "  [+] .github/SECURITY.md references docs/SECURITY.md"; \
	else \
		echo "  [-] .github/SECURITY.md missing cross-reference to docs/SECURITY.md"; \
		err=1; \
	fi; \
	if grep -q '.github/SECURITY.md' docs/SECURITY.md 2>/dev/null; then \
		echo "  [+] docs/SECURITY.md references .github/SECURITY.md"; \
	else \
		echo "  [-] docs/SECURITY.md missing cross-reference to .github/SECURITY.md"; \
		err=1; \
	fi; \
	exit "$$err"

release-check: ## Lint .goreleaser.yaml.
	$(GO) run github.com/goreleaser/goreleaser/v2@latest check

release-snapshot: ## goreleaser dry-run.
	@profile_release_root=$$(mktemp -d); \
	trap 'rm -rf -- "$$profile_release_root"' EXIT; \
	env_file="$$profile_release_root/release.env"; \
	python ops/scripts/profile_release.py prepare \
		--version "$(VERSION)" \
		--output-root "$$profile_release_root" \
		--env-file "$$env_file"; \
	set -a; . "$$env_file"; set +a; \
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

dev: ## Hot-reload dev loop for cmd/sso-server (air-verse/air, fetched on demand — see .air.toml; not a go.mod dependency).
	$(GO) run github.com/air-verse/air@latest -c .air.toml

ci-modules: ## Build + test all nested modules.
	cd infrastructure/kms/awskms && $(GO) build ./... && $(GO) test -race -count=1 ./...
	cd infrastructure/kms/gcpkms && $(GO) build ./... && $(GO) test -race -count=1 ./...
	cd infrastructure/kms/azurekeyvault && $(GO) build ./... && $(GO) test -race -count=1 ./...
	cd infrastructure/kms/pkcs11 && $(GO) build ./... && $(GO) test -race -count=1 ./...
	cd infrastructure/saml && $(GO) build ./... && $(GO) test -race -count=1 ./...
	cd infrastructure/ldap && $(GO) build ./... && $(GO) test -race -count=1 ./...
	cd infrastructure/extauthz && $(GO) build ./... && $(GO) test -race -count=1 ./...
	cd infrastructure/kerberos && $(GO) build ./... && $(GO) test -race -count=1 ./...
	cd infrastructure/radius && $(GO) build ./... && $(GO) test -race -count=1 ./...
	cd infrastructure/kafka && $(GO) build ./... && $(GO) test -race -count=1 ./...
	cd infrastructure/mqtt && $(GO) build ./... && $(GO) test -race -count=1 ./...
	cd cmd/sso-mcp && $(GO) build ./... && $(GO) test -race -count=1 ./...
	cd cmd/sso-operator && $(GO) build ./... && $(GO) test -race -count=1 ./...

ci: fmt vet race build examples proto-lint ci-modules config-validate-all modules-check modules-smoke route-contract proto-openapi-parity capabilities-check sdk-surface-check profiles-evidence adapters-check ## Run CI checks.

ci-full: ci terraform-validate k8s-render ## Run all CI checks including IaC validation (requires kustomize + terraform).

mod-tidy-all: ## Run go mod tidy in all modules.
	find . -name go.mod -not -path './.git/*' -execdir go mod tidy \;

clean: ## Remove build artifacts.
	rm -rf $(BIN_DIR) dist/modules

clean-all: ## Remove build artifacts + go build cache + tidy all modules.
	rm -rf $(BIN_DIR) dist/modules
	$(GO) clean -cache
	find . -name go.mod -not -path './.git/*' -execdir go mod tidy \;

test-e2e: ## Run integration tests in test/ (package ssotest).
	$(GO) test -race -count=1 ./test/...

backend-semantics: ## Cross-backend semantic-equivalence tests (memory vs sqlite; fast — run every PR).
	$(GO) test ./test/backendsemantics/... -race -count=1

chaos-test: ## Fault-injection chaos tests (storage error fail-open/closed, panic recovery, clock jumps); slower — run on main/pre-release, not every PR.
	$(GO) test -tags chaos ./test/chaos/... -race -count=2

dr-drill: ## DR failover drill harness (replicate/corrupt/restore + signing-key + audit-chain invariants over real snapshot machinery). Run on demand / pre-release, NOT in default ci.
	$(GO) test ./test/dr/... -race -count=1 -v

docker-scan: ## Scan Docker image with trivy.
	@command -v trivy >/dev/null 2>&1 || { echo "trivy not installed (install from https://trivy.dev)" >&2; exit 1; }
	trivy image --severity HIGH,CRITICAL $(IMAGE):$(IMAGE_TAG)

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

ai-dev-test: ## Run ai-dev/ unit tests (validate review and pipeline runners).
	python -m pytest ai-dev/tests/ -v
check-test: ## Run checks/ unit tests (validate engineering gates themselves).
	python -m pytest checks/ -v

skill-test: ## Run skills/ unit tests (validate automated scripts).
	@for skill_dir in docs/skills/*/; do \
		if [ -f "$${skill_dir}test_skill.py" ]; then \
			echo "=== Testing $$(basename $$skill_dir) ==="; \
			cd "$$skill_dir" && python -m pytest test_skill.py -v; \
			cd "$(CURDIR)"; \
		fi; \
	done

adr-compliance: ## Check ADR compliance (ADR-0003, ADR-0004, ADR-0007).
	$(CLI) adr-compliance

# -------------------------------------------------------------------
# Release & Docker targets.
# -------------------------------------------------------------------

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
	@for dir in infrastructure/kms/awskms infrastructure/kms/gcpkms infrastructure/kms/azurekeyvault infrastructure/kms/pkcs11 infrastructure/saml infrastructure/ldap infrastructure/kerberos infrastructure/radius infrastructure/extauthz infrastructure/kafka infrastructure/mqtt cmd/sso-mcp cmd/sso-operator; do \
		echo "linting $$dir..."; \
		cd "$$dir" && golangci-lint run ./...; \
		cd "$(CURDIR)"; \
	done

security-scan-all: ## Run gosec on root + all nested modules.
	go run github.com/securego/gosec/v2/cmd/gosec@latest -no-fail ./...
	@for dir in infrastructure/kms/awskms infrastructure/kms/gcpkms infrastructure/kms/azurekeyvault infrastructure/kms/pkcs11 infrastructure/saml infrastructure/ldap infrastructure/kerberos infrastructure/radius infrastructure/extauthz infrastructure/kafka infrastructure/mqtt cmd/sso-mcp cmd/sso-operator; do \
		echo "gosec $$dir..."; \
		cd "$$dir" && go run github.com/securego/gosec/v2/cmd/gosec@latest -no-fail ./...; \
		cd "$(CURDIR)"; \
	done

config-validate-all: ## Validate all 7 deploy config files against the server.
	@echo "==> Validating all config.yaml files..."
	@fail=0; \
	for cfg in cmd/sso-server/config.yaml bin/config.yaml ops/deploy/compose/config.yaml ops/deploy/baremetal-ha/sso/config.yaml ops/deploy/k8s/config.yaml ops/deploy/k8s-prod/config.yaml docs/examples/basic/config.yaml; do \
		echo -n "  $$cfg ... "; \
		if [ -f "$$cfg" ]; then \
			if SSO_POSTGRES__DSN='$(VALIDATION_POSTGRES_DSN)' $(GO) run ./cmd/sso-server --config="$$cfg" --validate-only -grpc-insecure 2>/dev/null; then \
				echo "OK"; \
			else \
				echo "FAIL"; fail=1; \
			fi; \
		else \
			echo "SKIP (not found)"; \
		fi; \
	done; \
	exit $$fail

smoke-test: ## Run smoke tests against a running server.
	sh ops/deploy/baremetal-ha/smoke.sh

k8s-render: ## Render all Kustomize overlays to flat YAML for auditing.
	@mkdir -p $(BIN_DIR)/k8s-rendered/dev $(BIN_DIR)/k8s-rendered/prod $(BIN_DIR)/k8s-rendered/billing $(BIN_DIR)/k8s-rendered/stripe-adapter $(BIN_DIR)/k8s-rendered/audit-provisioner
	@echo "==> Rendering kustomize overlays (dev)..."
	@KUSTOMIZE=$$(command -v kustomize 2>/dev/null || command -v kubectl 2>/dev/null); \
	if [ -z "$$KUSTOMIZE" ]; then echo "kustomize or kubectl not installed" >&2; exit 1; fi; \
	if echo "$$KUSTOMIZE" | grep -q kubectl; then \
		kubectl kustomize ops/deploy/kustomize/overlays/dev > $(BIN_DIR)/k8s-rendered/dev/all.yaml; \
	else \
		kustomize build ops/deploy/kustomize/overlays/dev > $(BIN_DIR)/k8s-rendered/dev/all.yaml; \
	fi
	@echo "==> Rendering kustomize overlays (prod)..."
	@KUSTOMIZE=$$(command -v kustomize 2>/dev/null || command -v kubectl 2>/dev/null); \
	if echo "$$KUSTOMIZE" | grep -q kubectl; then \
		kubectl kustomize ops/deploy/kustomize/overlays/prod > $(BIN_DIR)/k8s-rendered/prod/all.yaml; \
	else \
		kustomize build ops/deploy/kustomize/overlays/prod > $(BIN_DIR)/k8s-rendered/prod/all.yaml; \
	fi
	@echo "==> Rendering snaplink-billing deployment..."
	@KUSTOMIZE=$$(command -v kustomize 2>/dev/null || command -v kubectl 2>/dev/null); \
	if echo "$$KUSTOMIZE" | grep -q kubectl; then \
		kubectl kustomize ops/deploy/billing > $(BIN_DIR)/k8s-rendered/billing/all.yaml; \
	else \
		kustomize build ops/deploy/billing > $(BIN_DIR)/k8s-rendered/billing/all.yaml; \
	fi
	@echo "==> Rendering Stripe adapter deployment..."
	@KUSTOMIZE=$$(command -v kustomize 2>/dev/null || command -v kubectl 2>/dev/null); \
	if echo "$$KUSTOMIZE" | grep -q kubectl; then \
		kubectl kustomize ops/deploy/billing/stripe-adapter > $(BIN_DIR)/k8s-rendered/stripe-adapter/all.yaml; \
	else \
		kustomize build ops/deploy/billing/stripe-adapter > $(BIN_DIR)/k8s-rendered/stripe-adapter/all.yaml; \
	fi
	@echo "==> Rendering Audit Governance provisioner deployment..."
	@KUSTOMIZE=$$(command -v kustomize 2>/dev/null || command -v kubectl 2>/dev/null); \
	if echo "$$KUSTOMIZE" | grep -q kubectl; then \
		kubectl kustomize ops/deploy/audit-provisioner > $(BIN_DIR)/k8s-rendered/audit-provisioner/all.yaml; \
	else \
		kustomize build ops/deploy/audit-provisioner > $(BIN_DIR)/k8s-rendered/audit-provisioner/all.yaml; \
	fi
	@echo "Rendered YAML in $(BIN_DIR)/k8s-rendered/"

helm-render: ## Strict-lint and render the standalone service Helm charts.
	@command -v helm >/dev/null 2>&1 || { echo "helm not installed" >&2; exit 1; }
	@mkdir -p $(BIN_DIR)/helm-rendered
	helm lint --strict ops/deploy/helm/snaplink-billing
	helm template billing ops/deploy/helm/snaplink-billing \
		--namespace snaplink-sso > $(BIN_DIR)/helm-rendered/snaplink-billing.yaml
	helm lint --strict ops/deploy/helm/snaplink-stripe-adapter
	helm template stripe-adapter ops/deploy/helm/snaplink-stripe-adapter \
		--namespace snaplink-sso > $(BIN_DIR)/helm-rendered/snaplink-stripe-adapter.yaml
	helm lint --strict ops/deploy/helm/snaplink-audit-provisioner
	helm template audit-provisioner ops/deploy/helm/snaplink-audit-provisioner \
		--namespace snaplink-sso \
		--set-file desiredState=ops/deploy/audit-provisioner/desired-state.example.json \
		> $(BIN_DIR)/helm-rendered/snaplink-audit-provisioner.yaml
	@echo "Rendered YAML in $(BIN_DIR)/helm-rendered/"

k8s-diff: ## Diff rendered output between dev and prod overlays.
	@echo "==> Building dev overlay..."
	@KUSTOMIZE=$$(command -v kustomize 2>/dev/null || command -v kubectl 2>/dev/null); \
	if [ -z "$$KUSTOMIZE" ]; then echo "kustomize or kubectl not installed" >&2; exit 1; fi; \
	mkdir -p $(BIN_DIR)/k8s-rendered/dev $(BIN_DIR)/k8s-rendered/prod; \
	if echo "$$KUSTOMIZE" | grep -q kubectl; then \
		kubectl kustomize ops/deploy/kustomize/overlays/dev > $(BIN_DIR)/k8s-rendered/dev/all.yaml; \
		kubectl kustomize ops/deploy/kustomize/overlays/prod > $(BIN_DIR)/k8s-rendered/prod/all.yaml; \
	else \
		kustomize build ops/deploy/kustomize/overlays/dev > $(BIN_DIR)/k8s-rendered/dev/all.yaml; \
		kustomize build ops/deploy/kustomize/overlays/prod > $(BIN_DIR)/k8s-rendered/prod/all.yaml; \
	fi
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

.PHONY: ai-dev-test licenses licenses-check licenses-notice release-snapshot release docker-push docker-multiarch lint-all security-scan-all config-validate-all smoke-test k8s-render k8s-diff helm-render terraform-validate terraform-plan-dev terraform-plan-prod check-test skill-test adr-compliance
