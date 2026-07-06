# AI-SDLC: Engineering Review Framework

A 10-stage review framework for production-grade software subsystems.
Works with Claude Code, Codex, Gemini CLI, OpenCode, and any `pi`-compatible agent.

---

## What This Is

Not a security scanner. Not a linter. A structured engineering review process that maps to how real software teams work:

| Stage | Name | Roles | Goal |
|-------|------|-------|------|
| 00 | Product Discovery | PM · BA · UX | Is this worth building? |
| 01 | Architecture Review | Architect · Backend Arch · CTO | Is the design right? |
| 02 | Security & RFC Review | Security Eng · Protocol Expert | Is it safe and compliant? |
| 03 | Distributed Systems Review | Distributed Eng · DB Architect | Does it hold under multi-pod failure? |
| 04 | Implementation Review | Staff Eng · Tech Lead | Is the code maintainable? |
| 05 | Performance Review | Perf Eng · DB Architect | Will it scale? |
| 06 | Production Readiness | SRE · DevOps · QA · Security | Can we operate it? |
| 07 | Sprint Planning | PM · Architect · Tech Lead | What gets built this sprint? |
| 08 | Post-Sprint Review | Staff Eng · QA · SRE | Did we actually deliver it? |
| 09 | CTO Review | CTO · Principal Reviewer | Should this ship? |

---

## Quick Start

### Single Stage (simplest)

```bash
# Fill context and run Stage 02 (Security & RFC Review)
python ai-dev/ai/run-review.py \
  --stage 02 \
  --project "Snaplink SSO" \
  --subsystem "OIDC RP-Initiated Logout" \
  --files "interfaces/sso/server_logout.go,protocols/oidc/" \
  --rfcs "OIDC RP-Initiated Logout 1.0,RFC6749,RFC7519" \
  --model claude-sonnet
```

### Context File (recommended for multi-stage reviews)

```bash
# Copy the example and fill in your subsystem details
cp ai-dev/ai/examples/oidc-logout-context.yaml ai-dev/ai/reviews/my-subsystem/context.yaml
# Edit the context file
vi ai-dev/ai/reviews/my-subsystem/context.yaml

# Run a specific stage
python ai-dev/ai/run-review.py --stage 01 --context ai-dev/ai/reviews/my-subsystem/context.yaml

# Dry-run to inspect the filled prompt before invoking pi
python ai-dev/ai/run-review.py --stage 02 --context ai-dev/ai/reviews/my-subsystem/context.yaml --dry-run

# Run all stages sequentially
python ai-dev/ai/run-review.py --all --context ai-dev/ai/reviews/my-subsystem/context.yaml
```

### Directly with pi (no run-review.py)

```bash
# Manually fill {{VARIABLES}} in a template copy and pipe to pi
cat ai-dev/ai/prompts/02-security-rfc-review.md | pi -p "$(cat -)"

# Or pass the filled file directly
pi -p "$(cat my-filled-stage02.md)"
```

### With pi-batch (parallel multi-subsystem)

```bash
# Create a task YAML for reviewing multiple subsystems in parallel
python ai-dev/pi-batch.py tasks.yaml --mode parallel --workers 4

# Use a pipeline for chained stages
python ai-dev/pi-batch.py --pipeline ai-dev/ai/examples/oidc-logout-pipeline.yaml
```

---

## Stage Selection Guide

You don't need to run all 10 stages for every subsystem. Choose based on what you need:

| Situation | Recommended Stages |
|-----------|-------------------|
| "Should we build this?" | 00 → 09 |
| Reviewing an existing feature pre-merge | 02 → 04 → 06 |
| Planning a sprint | 07 (with prior 01 output) |
| Pre-production hardening | 02 → 03 → 06 |
| Performance investigation | 05 |
| Post-incident retrospective | 08 |
| Executive go/no-go on a large feature | 00 → 01 → 09 |

---

## Context File Reference

All fields are optional. Unfilled fields appear as `(not provided: FIELD_NAME)` in the output.

```yaml
project: "Project name"
subsystem: "Subsystem or feature name"
repo: "/absolute/path/to/repo"

# Files to review (relative to repo root or absolute)
files:
  - path/to/primary/file.go
  - path/to/directory/

# Applicable RFCs and standards
rfcs:
  - RFC 6749 (OAuth 2.0)
  - OpenID Connect Core 1.0

# Used by Stage 01
architecture_summary: |
  Describe the proposed or existing architecture.

# Used by Stages 03, 05, 06
storage: "Redis Cluster, PostgreSQL"
load_profile: "500 req/s peak, p99 < 200ms target"
infra: "Kubernetes 3-pod, Redis Cluster, PostgreSQL HA"
deployment_target: "Kubernetes + Prometheus/Grafana"
slo_targets: "99.9% availability, p99 < 200ms"

# Used by Stage 07
sprint_goal: "What this sprint is trying to achieve"
team_size: 3
sprint_duration: "2 weeks"
velocity: "22 story points last sprint"

# Used by Stage 09
age: "8 months in codebase"

# Stage-specific overrides (key: stage_NN)
stage_09:
  CRITICAL_COUNT: "2"
  HIGH_COUNT: "5"
```

---

## Output Structure

Review outputs land in `ai-dev/ai/reviews/<subsystem>/`:

```
ai-dev/ai/reviews/oidc-logout/
├── context.yaml          # your context file
├── stage-00.out.md       # Product Discovery output
├── stage-01.out.md       # Architecture Review output
├── stage-02.out.md       # Security & RFC output
├── stage-03.out.md       # Distributed Systems output
├── stage-04.out.md       # Implementation Review output
├── stage-05.out.md       # Performance Review output
├── stage-06.out.md       # Production Readiness output
├── stage-07.out.md       # Sprint Planning output
├── stage-08.out.md       # Post-Sprint Review output
└── stage-09.out.md       # CTO Review output
```

---

## Framework Files

```
ai-dev/ai/
├── README.md                          # this file
├── run-review.py                      # template runner + agent invoker
├── sdlc.yaml                          # declarative stage/variable schema (edit this to add/remove/rename stages)
├── prompts/
│   ├── 00-product-discovery.md
│   ├── 01-architecture-review.md
│   ├── 02-security-rfc-review.md
│   ├── 03-distributed-review.md
│   ├── 04-implementation-review.md
│   ├── 05-performance-review.md
│   ├── 06-production-readiness.md
│   ├── 07-sprint-planning.md
│   ├── 08-post-sprint-review.md
│   ├── 09-cto-review.md
│   └── shared/
│       ├── role-definitions.md        # 17 review roles
│       ├── output-format.md           # standard finding format
│       ├── engineering-principles.md  # project gates (from AGENTS.md)
│       └── review-checklists.md       # domain checklists
├── adrs/                              # Architecture Decision Records
├── architecture/                      # architecture diagrams and notes
├── reviews/                           # review outputs per subsystem
│   └── <subsystem>/
│       ├── context.yaml
│       └── stage-NN.out.md
├── sprint/                            # sprint backlogs
└── examples/
    ├── oidc-logout-context.yaml       # worked example context file
    └── oidc-logout-pipeline.yaml      # pi-batch pipeline example
```

---

## Adding a New Subsystem Review

1. Create a context file:
   ```bash
   cp ai-dev/ai/examples/oidc-logout-context.yaml ai-dev/ai/reviews/my-subsystem/context.yaml
   ```

2. Fill in the fields relevant to your subsystem.

3. Dry-run the stage you need to verify the filled prompt looks correct:
   ```bash
   python ai-dev/ai/run-review.py --stage 02 --context ai-dev/ai/reviews/my-subsystem/context.yaml --dry-run
   ```

4. Run the review:
   ```bash
   python ai-dev/ai/run-review.py --stage 02 --context ai-dev/ai/reviews/my-subsystem/context.yaml --model claude-sonnet
   ```

5. Review the output in `ai-dev/ai/reviews/my-subsystem/stage-02.out.md`.

6. Feed output into the next stage by adding it to your context YAML under `stage_03.ARCHITECTURE_OUTPUT`.
