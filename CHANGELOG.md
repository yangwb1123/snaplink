# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Engineering system infrastructure:
  - P0 — Harness layer with 6 automated gates (filesize, complexity, architecture, build/test, mock, security)
  - P1 — Context layer (BOOTSTRAP, ARCHITECTURE, AGENTS docs)
  - P2 — Skills layer (split-large-file, add-new-handler, refactor-high-complexity cards)
  - P3 — Evaluation layer with coverage gates and TODO tracking
  - P4 — Process layer (PR template, review checklist, ADR, check registry)
  - P5 — Self-diagnosis engine (diagnose.sh, health-report)
  - P6 — pi agent integration (.pi/ prompts, APPEND_SYSTEM.md)
  - P7 — Developer experience (make help, dependabot, CODEOWNERS, issue templates)
  - P8 — Trend monitor (weekly snapshot of engineering metrics)
  - P9 — Security policy (vulnerability reporting, fail-open/closed docs)
  - P10 — CI/CD integration (engineering.yml workflow, ci.yml harness step)
- Self-bootstrapping: `make harness` regenerates all 25+ engineering files from
  `docs/templates/engineering/generate-engineering.sh`
- GitHub Actions workflow `engineering.yml` for PR gating
- Dependabot configuration for automated dependency updates
- Issue templates (bug report, feature request, technical debt)
- CODEOWNERS file for PR routing
- Developer guide, release process, security policy documentation

### Changed
- Makefile: 15+ new targets added (harness, filesize, complexity, architecture,
  check-invariants, self-test, check-exemptions, health-report, diagnose,
  trend, generate-engineering, make help)
- .golangci.yml: Added funlen(60), gocyclo(15), gocognit(20) linters
- AGENTS.md: Streamlined to focus on behavior rules and protocol invariants
- CONTRIBUTING.md: Updated with engineering system references
- ci.yml: Added engineering gates step before build

### Fixed
- Oracle-leak hardening patterns documented and checked
- Anti-enumeration patterns (bcrypt dummy hash) verified
- Cache-Control: no-store and WWW-Authenticate presence verified across 9+ files

### Security
- Security invariant checker (10 checks) enforces no-store headers,
  bearer challenges, oracle-safe error responses, constant-time comparisons
- Security policy defines fail-open vs fail-closed boundaries
- Vulnerability reporting process documented
