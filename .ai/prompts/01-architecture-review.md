# Stage 01: Architecture Review

## Roles Active
Principal Architect · Backend Architect · CTO

## Objective
Determine whether the proposed architecture has the right boundaries, the right abstractions, and the right tradeoffs.
Challenge over-engineering and premature abstraction.
Produce an Architecture Decision Record (ADR) as output.

Read `.ai/prompts/shared/engineering-principles.md` before starting.

---

## Context

**Project**: {{PROJECT_NAME}}

**Subsystem**: {{SUBSYSTEM}}

**Repository**: {{REPO_PATH}}

**Primary Files**:
{{PRIMARY_FILES}}

**Architecture Summary**:
{{ARCHITECTURE_SUMMARY}}

**Stage 00 Output (if available)**:
{{PRODUCT_DISCOVERY_OUTPUT}}

---

## Review Tasks

### 1. Module Responsibility
- Does this subsystem have a single, clearly stated responsibility?
- Is the responsibility statement narrow enough to fit in one sentence?
- Does this subsystem duplicate responsibility already owned by another module?
- What happens if this module is removed? Which parts of the system break?

### 2. Boundary & Interface Design
- Are all external dependencies behind interfaces (SPI pattern)?
- Is the public interface surface too wide? Which methods could be package-internal?
- Does the SPI make sense to three different implementations? (If not, it's over-abstracted.)
- Are there interfaces with only one implementation and no planned second? (Suspect — justify or collapse.)
- Does the `Deps` interface or equivalent grow unboundedly? (Sign of a god-object dependency graph.)

### 3. Dependency Direction
- Do all imports point downward toward `shared/core`?
- Are there any peer imports between `protocols/oauth` ↔ `protocols/oidc` or equivalent?
- Are there any upward imports (lower layer importing higher layer)?
- Does adding this module require a new `layerExemptions` entry? (That is a gate failure.)

### 4. State Ownership
- Where does state live? Is there exactly one authoritative writer per state type?
- Is session state owned by the session store or duplicated across multiple caches?
- Is any state stored in memory that must survive pod restart? (Should it be in Redis/Postgres?)
- Are there distributed state mutations without locking or idempotency guarantees?

### 5. Extensibility vs. Complexity
- Is the plugin/extension mechanism necessary for the current sprint, or is it speculative?
- Could the first two use cases be solved with a simple `if/switch` and extended later?
- Is the configuration surface justified by actual operator needs, or is it future-proofing?
- What is the cognitive overhead of adding a new implementation of the SPI?

### 6. Testability
- Can the core logic be tested without infrastructure (Redis, Postgres, LDAP)?
- Does a `Memory*` implementation exist for every SPI?
- Are there untestable hidden dependencies (time, random, network) that aren't injected?

### 7. Fit with Existing Architecture
- Does this follow the hexagonal extraction pattern (`Handle*(deps Deps, ctx)` free functions)?
- Does the directory placement follow the layer map in `docs/architecture/DIRECTORY_MAP.md`?
- Does the file and function count respect the committed budget gates?

---

## Required Output

### Architecture Decision Record (ADR)

**Title**: [ADR-NNNN] [Subsystem] — [Core decision]

**Status**: Proposed

**Context**: What problem is being solved and why this decision matters.

**Decision**: What architecture was chosen.

**Consequences**:
- Good: [benefits]
- Bad: [tradeoffs accepted]
- Risks: [what could go wrong with this decision]

**Alternatives Considered**:
List at least two alternatives with one-line rejection reasons.

### Package Structure Proposal
```
layer/subsystem/
├── spi.go          # interfaces only
├── memory.go       # in-memory implementation
├── handle_X.go     # one handler function per operation
└── validate.go     # pure validation logic
```

### API Contract
Method signatures only. No implementation. Flag any method with >4 parameters as a smell.

### Coupling Assessment
List modules this subsystem imports, and modules that will import this subsystem.
Flag any bidirectional dependency.

### Recommendation
**Approve** | **Approve with Changes** | **Redesign** | **Reject**
List specific changes required before approval.
