# Stage 04: Implementation Review

## Roles Active
Staff Engineer · Tech Lead

## Objective
Review code organization, interface quality, error handling, and maintainability.
Verify compliance with the committed budget gates.
Produce a refactoring plan with specific file/function targets.

Read `.ai/prompts/shared/engineering-principles.md` before starting.

---

## Context

**Project**: {{PROJECT_NAME}}

**Subsystem**: {{SUBSYSTEM}}

**Repository**: {{REPO_PATH}}

**Primary Files**:
{{PRIMARY_FILES}}

**Prior Findings (Stage 01-03)**:
{{PRIOR_FINDINGS}}

---

## Review Tasks

### 1. Budget Gate Compliance
Run these checks first. A gate failure is a blocker.

- Are all `.go` files ≤ 500 lines? (Check every file in the subsystem.)
- Are all functions ≤ 50 lines?
- Is cyclomatic complexity ≤ 15 for every function?
- Is if-nesting depth ≤ 3?
- Does the directory structure comply with the layer map? No 4th-level nesting?
- Does adding this code require any new maintainability exemptions? (If yes: split instead.)

### 2. Package & File Organization
- Does each file have a single, clear topic? (A 300-line file mixing validation, HTTP handling, and DB queries is three files.)
- Are files named by their responsibility, not by their implementation? (`token_validate.go`, not `util.go`)
- Is there a `_test.go` file beside every non-trivial `.go` file?
- Is there dead code (unreachable functions, unused types)?

### 3. Interface Quality
- Are interfaces defined in terms of what callers need, not what implementors provide?
- Are interfaces small? (A 12-method interface is a god object; split it.)
- Is there an interface with exactly one implementation and no planned second? (Justify or collapse to a concrete type.)
- Are `Deps` interfaces passed by value to free functions (`Handle*(deps Deps, ctx)`)? (Hexagonal pattern.)

### 4. Error Handling
- Are all errors handled explicitly? (No `_ = err` except in deferred cleanup.)
- Are errors wrapped with context at the point they cross a package boundary?
- Are sentinel errors used for control flow? (Acceptable. Are they documented in `consts.go`?)
- Does error handling distinguish between: client errors (4xx), server errors (5xx), and retryable errors?
- Is the oracle-leak hardening applied? All "not found" / "wrong token" paths return the same error code.

### 5. Logging & Observability
- Does every operation that changes state emit a structured log event?
- Are log fields consistent? (`user_id`, `client_id`, `session_id`, `trace_id` must be present where relevant.)
- Are there any `log.Printf("error: %v", err)` without context fields? (Replace with structured logging.)
- Are sensitive values (tokens, passwords, PII) excluded from logs?

### 6. Test Coverage
- Is the happy path tested?
- Are error paths tested? (Every `if err != nil` branch should have a test that triggers it.)
- Are race conditions tested? (`go test -race -count=10`)
- Is there a test for every security invariant? (Token reuse rejected, scope enforcement, etc.)
- Are tests using real `Memory*` implementations, not mocks of SPI interfaces?
- Is the test suite runnable without external infrastructure (`go test ./...`)?

### 7. Naming & Readability
- Are exported names self-describing without reading the implementation?
- Are there abbreviations that require context to understand? (`tkn`, `cfg`, `hdl` — expand them.)
- Are boolean parameters used in function calls? (`process(true, false, true)` — replace with options struct.)
- Are magic numbers or magic strings inlined? (Move to `consts.go`.)

### 8. Technical Debt
- What shortcuts were taken to ship? List them explicitly.
- Which shortcuts are acceptable long-term vs. which must be addressed next sprint?
- Are there `TODO` comments? (Per project convention, these must be refactored immediately, not deferred.)

---

## Required Output

### Budget Gate Report
List every file with line count. Flag violations.
List every function with complexity and length. Flag violations.

### Refactoring Plan
For each violation or quality issue, specify:
- File and line range
- What to extract or rename
- Target file name
- Estimated effort

### Interface Definitions (final)
The cleaned-up interface signatures after applying refactoring recommendations.

### Technical Debt List
| Item | Severity | Effort | Deferred To |
|------|----------|--------|-------------|
| | | | |

Produce findings using `.ai/prompts/shared/output-format.md`.
Sort: Critical → High → Medium → Low → Info.

Conclude with the Stage Summary Block.
