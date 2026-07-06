#!/usr/bin/env python3
"""run-review -- fill context into an AI-SDLC review template and invoke pi.

Usage:
  # Run a specific stage with inline context
  python ai-dev/ai/run-review.py --stage 02 \\
    --project "Snaplink SSO" \\
    --subsystem "OIDC RP-Initiated Logout" \\
    --files "interfaces/sso/server_logout.go,protocols/oidc/" \\
    --rfcs "RFC6749,OIDC Session Management,OIDC RP-Initiated Logout" \\
    --model claude-sonnet

  # Run from a context YAML file (recommended for multi-stage runs)
  python ai-dev/ai/run-review.py --stage 01 --context ai-dev/ai/reviews/oidc-logout/context.yaml

  # Dry-run: print the filled prompt without invoking pi
  python ai-dev/ai/run-review.py --stage 02 --context ai-dev/ai/reviews/oidc-logout/context.yaml --dry-run

  # Run all stages sequentially
  python ai-dev/ai/run-review.py --all --context ai-dev/ai/reviews/oidc-logout/context.yaml

Context YAML format:
  project: "Snaplink SSO"
  subsystem: "OIDC RP-Initiated Logout"
  repo: "/home/dwp/snaplink"
  files:
    - interfaces/sso/server_logout.go
    - protocols/oidc/
  rfcs:
    - OIDC Core (OpenID Connect Core 1.0)
    - OIDC RP-Initiated Logout 1.0
    - RFC6749
  architecture_summary: |
    The logout handler lives in interfaces/sso/server_logout.go.
    It coordinates session termination, front-channel logout, and back-channel logout.
  load_profile: "200 req/s peak, p99 < 100ms target"
  infra: "3-pod k8s, Redis Cluster, PostgreSQL HA"
  slo_targets: "99.9% availability, p99 < 200ms"
  sprint_goal: "Harden logout against session fixation and add back-channel support"
  team_size: 3
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

# Fallback stage/variable schema, used if sdlc.yaml is missing (so this
# script still runs standalone with zero config). When present, sdlc.yaml
# fully replaces both dicts below -- see _load_stage_schema().
_DEFAULT_STAGES = {
    "00": "00-product-discovery.md",
    "01": "01-architecture-review.md",
    "02": "02-security-rfc-review.md",
    "03": "03-distributed-review.md",
    "04": "04-implementation-review.md",
    "05": "05-performance-review.md",
    "06": "06-production-readiness.md",
    "07": "07-sprint-planning.md",
    "08": "08-post-sprint-review.md",
    "09": "09-cto-review.md",
}

_DEFAULT_STAGE_VARS = {
    "00": {
        "PROJECT_NAME": "",
        "SUBSYSTEM": "",
        "FEATURE_DESCRIPTION": "(describe the proposed feature)",
        "BUSINESS_JUSTIFICATION": "(state the business reason)",
        "TARGET_USERS": "(list target personas)",
        "PAIN_POINT_EVIDENCE": "(cite observable evidence)",
        "COMPARABLE_IMPLEMENTATIONS": "(optional: comparable systems)",
    },
    "01": {
        "PROJECT_NAME": "",
        "SUBSYSTEM": "",
        "REPO_PATH": "",
        "PRIMARY_FILES": "",
        "ARCHITECTURE_SUMMARY": "(describe the proposed architecture)",
        "PRODUCT_DISCOVERY_OUTPUT": "(paste Stage 00 output, or 'N/A')",
    },
    "02": {
        "PROJECT_NAME": "",
        "SUBSYSTEM": "",
        "REPO_PATH": "",
        "PRIMARY_FILES": "",
        "RFC_REFERENCES": "",
        "ARCHITECTURE_OUTPUT": "(paste Stage 01 ADR, or 'N/A')",
    },
    "03": {
        "PROJECT_NAME": "",
        "SUBSYSTEM": "",
        "REPO_PATH": "",
        "PRIMARY_FILES": "",
        "STORAGE_SUMMARY": "",
        "ARCHITECTURE_OUTPUT": "(paste Stage 01 ADR, or 'N/A')",
    },
    "04": {
        "PROJECT_NAME": "",
        "SUBSYSTEM": "",
        "REPO_PATH": "",
        "PRIMARY_FILES": "",
        "PRIOR_FINDINGS": "(paste Critical/High findings from Stages 01-03, or 'N/A')",
    },
    "05": {
        "PROJECT_NAME": "",
        "SUBSYSTEM": "",
        "REPO_PATH": "",
        "PRIMARY_FILES": "",
        "LOAD_PROFILE": "",
        "INFRA_SUMMARY": "",
    },
    "06": {
        "PROJECT_NAME": "",
        "SUBSYSTEM": "",
        "REPO_PATH": "",
        "PRIMARY_FILES": "",
        "DEPLOYMENT_TARGET": "",
        "SLO_TARGETS": "",
        "PRIOR_FINDINGS": "(paste Critical/High findings from Stages 02-05, or 'N/A')",
    },
    "07": {
        "PROJECT_NAME": "",
        "SUBSYSTEM": "",
        "SPRINT_GOAL": "",
        "TEAM_SIZE": "3",
        "SPRINT_DURATION": "2 weeks",
        "CRITICAL_HIGH_FINDINGS": "(paste Critical/High findings from all prior stages)",
        "ARCHITECTURE_OUTPUT": "(paste Stage 01 ADR)",
        "VELOCITY": "(last sprint velocity, or 'unknown')",
    },
    "08": {
        "PROJECT_NAME": "",
        "SUBSYSTEM": "",
        "SPRINT_GOAL": "",
        "COMMITTED_STORIES": "(list stories from Stage 07)",
        "REPO_PATH": "",
        "SHIPPED_CHANGES": "(git log or PR list)",
    },
    "09": {
        "PROJECT_NAME": "",
        "SUBSYSTEM": "",
        "ALL_PRIOR_FINDINGS_SUMMARY": "(1-paragraph summary of all findings)",
        "CRITICAL_COUNT": "0",
        "HIGH_COUNT": "0",
        "GRADE_00": "N/A",
        "GRADE_01": "N/A",
        "GRADE_02": "N/A",
        "GRADE_03": "N/A",
        "GRADE_04": "N/A",
        "GRADE_05": "N/A",
        "GRADE_06": "N/A",
        "TEAM_SIZE": "3",
        "AGE": "(unknown)",
    },
}


def _load_stage_schema() -> tuple[dict, dict]:
    """Load stages/vars from sdlc.yaml next to this script; fall back to
    the built-in defaults above if the file is absent or unparsable."""
    sdlc_path = Path(__file__).parent / "sdlc.yaml"
    if not yaml or not sdlc_path.exists():
        return dict(_DEFAULT_STAGES), {k: dict(v) for k, v in _DEFAULT_STAGE_VARS.items()}
    data = yaml.safe_load(sdlc_path.read_text(encoding="utf-8")) or {}
    stages_cfg = data.get("stages")
    if not isinstance(stages_cfg, dict) or not stages_cfg:
        return dict(_DEFAULT_STAGES), {k: dict(v) for k, v in _DEFAULT_STAGE_VARS.items()}
    stages = {sid: s.get("template", "") for sid, s in stages_cfg.items()}
    stage_vars = {sid: dict(s.get("vars", {})) for sid, s in stages_cfg.items()}
    return stages, stage_vars


def _load_agent_bin() -> str:
    """Read agent.bin from ai-dev/pi-batch.yaml (shared with pi-batch.py,
    which lives alongside this script's parent dir); default to 'pi' if
    absent."""
    if not yaml:
        return "pi"
    path = Path(__file__).parent.parent / "pi-batch.yaml"
    if not path.exists():
        return "pi"
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return (data.get("agent") or {}).get("bin", "pi")


STAGES, STAGE_VARS = _load_stage_schema()
AGENT_BIN = _load_agent_bin()


def load_context(path: str) -> dict:
    if not yaml:
        print("ERROR: PyYAML not installed. Run: pip install pyyaml", file=sys.stderr)
        sys.exit(1)
    fpath = Path(path)
    if not fpath.exists():
        print(f"ERROR: context file not found: {path}", file=sys.stderr)
        sys.exit(1)
    return yaml.safe_load(fpath.read_text(encoding="utf-8")) or {}


def context_to_vars(ctx: dict, stage: str) -> dict:
    """Map context YAML keys to template {{VARIABLE}} placeholders for a given stage."""
    files = ctx.get("files", [])
    if isinstance(files, list):
        files_str = "\n".join(f"  - {f}" for f in files)
    else:
        files_str = str(files)

    rfcs = ctx.get("rfcs", [])
    if isinstance(rfcs, list):
        rfcs_str = "\n".join(f"  - {r}" for r in rfcs)
    else:
        rfcs_str = str(rfcs)

    base = {
        "PROJECT_NAME": ctx.get("project", ""),
        "SUBSYSTEM": ctx.get("subsystem", ""),
        "REPO_PATH": ctx.get("repo", os.getcwd()),
        "PRIMARY_FILES": files_str,
        "RFC_REFERENCES": rfcs_str,
        "ARCHITECTURE_SUMMARY": ctx.get("architecture_summary", "(see primary files)"),
        "STORAGE_SUMMARY": ctx.get("storage", "Redis Cluster, PostgreSQL"),
        "LOAD_PROFILE": ctx.get("load_profile", "(not specified)"),
        "INFRA_SUMMARY": ctx.get("infra", "(not specified)"),
        "SLO_TARGETS": ctx.get("slo_targets", "(not specified)"),
        "DEPLOYMENT_TARGET": ctx.get("deployment_target", ctx.get("infra", "(not specified)")),
        "SPRINT_GOAL": ctx.get("sprint_goal", "(not specified)"),
        "TEAM_SIZE": str(ctx.get("team_size", 3)),
        "SPRINT_DURATION": ctx.get("sprint_duration", "2 weeks"),
        "VELOCITY": ctx.get("velocity", "(unknown)"),
        "AGE": ctx.get("age", "(unknown)"),
    }

    # Allow stage-specific overrides in context YAML under key "stage_NN"
    stage_overrides = ctx.get(f"stage_{stage}", {})
    base.update(stage_overrides)

    return base


def fill_template(template_path: Path, variables: dict) -> str:
    text = template_path.read_text(encoding="utf-8")
    for key, value in variables.items():
        text = text.replace("{{" + key + "}}", str(value) if value else f"(not provided: {key})")
    return text


def run_stage(stage: str, prompt: str, args) -> int:
    out_dir = Path(args.output_dir) if args.output_dir else Path(__file__).parent / "reviews" / args.context_name
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"stage-{stage}.out.md"

    cmd = [AGENT_BIN, "-p", prompt]
    if args.model:
        cmd.extend(["--model", args.model])

    print(f"\n{'='*60}", flush=True)
    print(f"  Stage {stage}: {STAGES[stage]}", flush=True)
    print(f"  Output: {out_file}", flush=True)
    print(f"{'='*60}\n", flush=True)

    try:
        result = subprocess.run(cmd, capture_output=False, text=True, cwd=args.repo or os.getcwd())
        if result.returncode == 0 and hasattr(result, "stdout") and result.stdout:
            out_file.write_text(result.stdout, encoding="utf-8")
            print(f"\nWROTE: {out_file}", flush=True)
        return result.returncode
    except FileNotFoundError:
        print(f"ERROR: '{AGENT_BIN}' not found in PATH.", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="AI-SDLC review runner — fill template variables and invoke pi",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--stage", metavar="NN",
                   help="Stage number to run (00-09)")
    p.add_argument("--all", action="store_true",
                   help="Run all stages sequentially")
    p.add_argument("--context", metavar="FILE",
                   help="Context YAML file with subsystem details")
    p.add_argument("--project", help="Project name (overrides context YAML)")
    p.add_argument("--subsystem", help="Subsystem name (overrides context YAML)")
    p.add_argument("--files", help="Comma-separated list of primary files")
    p.add_argument("--rfcs", help="Comma-separated RFC/standard references")
    p.add_argument("--repo", help="Repository path (default: cwd)")
    p.add_argument("--model", default="", help="Model for pi invocation")
    p.add_argument("--output-dir", metavar="DIR", help="Output directory for review files")
    p.add_argument("--dry-run", action="store_true",
                   help="Print filled prompt without invoking pi")
    return p


def main() -> None:
    args = build_parser().parse_args()

    prompts_dir = Path(__file__).parent / "prompts"
    if not prompts_dir.exists():
        print(f"ERROR: prompts directory not found: {prompts_dir}", file=sys.stderr)
        sys.exit(1)

    # Build context
    ctx = {}
    if args.context:
        ctx = load_context(args.context)
        args.context_name = Path(args.context).stem
    else:
        args.context_name = args.subsystem or "review"

    # CLI overrides
    if args.project:
        ctx["project"] = args.project
    if args.subsystem:
        ctx["subsystem"] = args.subsystem
    if args.files:
        ctx["files"] = [f.strip() for f in args.files.split(",")]
    if args.rfcs:
        ctx["rfcs"] = [r.strip() for r in args.rfcs.split(",")]
    if args.repo:
        ctx["repo"] = args.repo

    # Determine stages to run
    if args.all:
        stages_to_run = sorted(STAGES.keys())
    elif args.stage:
        stage = args.stage.zfill(2)
        if stage not in STAGES:
            print(f"ERROR: unknown stage '{args.stage}'. Valid: {', '.join(STAGES.keys())}", file=sys.stderr)
            sys.exit(1)
        stages_to_run = [stage]
    else:
        print("ERROR: specify --stage NN or --all", file=sys.stderr)
        sys.exit(1)

    failures = []
    for stage in stages_to_run:
        template_file = prompts_dir / STAGES[stage]
        if not template_file.exists():
            print(f"ERROR: template not found: {template_file}", file=sys.stderr)
            failures.append(stage)
            continue

        # Build variable map for this stage
        defaults = STAGE_VARS.get(stage, {})
        variables = {k: ctx.get(k.lower(), v) for k, v in defaults.items()}
        variables.update(context_to_vars(ctx, stage))

        prompt = fill_template(template_file, variables)

        if args.dry_run:
            print(f"\n{'='*60}")
            print(f"  Stage {stage} — DRY RUN")
            print(f"{'='*60}")
            print(prompt)
            continue

        rc = run_stage(stage, prompt, args)
        if rc != 0:
            failures.append(stage)
            if not args.all:
                sys.exit(rc)

    if failures:
        print(f"\nFailed stages: {', '.join(failures)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
