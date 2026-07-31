#!/usr/bin/env python3
"""run-review -- fill context into an AI-SDLC review template and invoke pi.

Usage:
  # Run a specific stage with inline context
  python ai-dev/ai/run-review.py --stage 02 \\
    --project "Snaplink SSO" \\
    --subsystem "OIDC RP-Initiated Logout" \\
    --files "interfaces/sso/handlers.go,protocols/oidc/handle_end_session.go" \\
    --rfcs "RFC6749,OIDC Session Management,OIDC RP-Initiated Logout" \\
    --model claude-sonnet

  # Run from a context YAML file (recommended for multi-stage runs)
  python ai-dev/ai/run-review.py --stage 01 --context ai-dev/ai/examples/oidc-logout-context.yaml

  # Dry-run: print the filled prompt without invoking pi
  python ai-dev/ai/run-review.py --stage 02 --context ai-dev/ai/examples/oidc-logout-context.yaml --dry-run

  # Run all stages sequentially
  python ai-dev/ai/run-review.py --all --context ai-dev/ai/examples/oidc-logout-context.yaml

Context YAML format:
  project: "Snaplink SSO"
  subsystem: "OIDC RP-Initiated Logout"
  files:
    - interfaces/sso/handlers.go
    - protocols/oidc/handle_end_session.go
  rfcs:
    - OIDC Core (OpenID Connect Core 1.0)
    - OIDC RP-Initiated Logout 1.0
    - RFC6749
  architecture_summary: |
    The logout use case lives in protocols/oidc/handle_end_session.go.
    It coordinates session termination, front-channel logout, and back-channel logout.
  load_profile: "(not provided)"
  infra: "(not provided)"
  slo_targets: "(not provided)"
  sprint_goal: "Review the existing flow and define one evidence-backed improvement"
  team_size: "(unknown)"
"""

import argparse
import os
import re
import signal
import subprocess
import sys
import threading
from pathlib import Path
from typing import Optional

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
        "TEAM_SIZE": "",
        "SPRINT_DURATION": "",
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
        "TEAM_SIZE": "",
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

# pi-style session flags (shared with pi-batch.py via ai-dev/pi-batch.yaml
# agent.session_flags when present); {session}/{name} are substituted per run.
_DEFAULT_SESSION_FLAGS = {
    "start": ["--session-id", "{session}", "--name", "{name}"],
    "continue": ["--session-id", "{session}"],
}


def _load_session_flags() -> dict:
    """Read agent.session_flags from ai-dev/pi-batch.yaml (shared with
    pi-batch.py); fall back to pi-style flags when absent."""
    if not yaml:
        return {k: list(v) for k, v in _DEFAULT_SESSION_FLAGS.items()}
    path = Path(__file__).parent.parent / "pi-batch.yaml"
    if not path.exists():
        return {k: list(v) for k, v in _DEFAULT_SESSION_FLAGS.items()}
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    cfg = (data.get("agent") or {}).get("session_flags")
    if isinstance(cfg, dict):
        return {k: list(v) for k, v in cfg.items()}
    return {k: list(v) for k, v in _DEFAULT_SESSION_FLAGS.items()}


SESSION_FLAGS = _load_session_flags()


def session_flags(key: str, session_id: str, session_name: str) -> list:
    flags = SESSION_FLAGS.get(key) or _DEFAULT_SESSION_FLAGS[key]
    return [f.replace("{session}", session_id).replace("{name}", session_name) for f in flags]


def load_context(path: str) -> dict:
    if not yaml:
        print("ERROR: PyYAML not installed. Install the project: uv sync (or pip install pyyaml)", file=sys.stderr)
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
        "STORAGE_SUMMARY": ctx.get("storage", ""),
        "LOAD_PROFILE": ctx.get("load_profile", "(not specified)"),
        "INFRA_SUMMARY": ctx.get("infra", "(not specified)"),
        "SLO_TARGETS": ctx.get("slo_targets", "(not specified)"),
        "DEPLOYMENT_TARGET": ctx.get("deployment_target", ctx.get("infra", "(not specified)")),
        "SPRINT_GOAL": ctx.get("sprint_goal", "(not specified)"),
        "TEAM_SIZE": str(ctx.get("team_size", "")),
        "SPRINT_DURATION": ctx.get("sprint_duration", ""),
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


# Stage output chaining for --all: target stage -> variable -> source stages.
# Only paste-style variables get chained; explicit context values win (checked
# in main before chain_variables runs).
CHAIN_SOURCES = {
    "01": {"PRODUCT_DISCOVERY_OUTPUT": ["00"]},
    "02": {"ARCHITECTURE_OUTPUT": ["01"]},
    "03": {"ARCHITECTURE_OUTPUT": ["01"]},
    "04": {"PRIOR_FINDINGS": ["01", "02", "03"]},
    "06": {"PRIOR_FINDINGS": ["02", "03", "04", "05"]},
    "07": {
        "CRITICAL_HIGH_FINDINGS": ["00", "01", "02", "03", "04", "05", "06"],
        "ARCHITECTURE_OUTPUT": ["01"],
    },
    "08": {"COMMITTED_STORIES": ["07"]},
    "09": {"ALL_PRIOR_FINDINGS_SUMMARY": ["00", "01", "02", "03", "04", "05", "06", "07", "08"]},
}


def chain_variables(prior_outputs: dict, stage: str, variables: dict, schema_defaults: dict) -> dict:
    """Inject completed stage outputs into the current stage's paste-style
    variables. A variable is treated as explicitly provided (and left
    untouched) only when it differs from the schema placeholder default or
    the context-provided value; schema placeholders are chainable slots."""
    chained = {}
    for var, sources in CHAIN_SOURCES.get(stage, {}).items():
        current = variables.get(var)
        if current and current != schema_defaults.get(var):
            continue
        parts = []
        for src in sources:
            text = prior_outputs.get(src)
            if text:
                parts.append(f"--- Stage {src} output ---\n{text}")
        if parts:
            chained[var] = "\n\n".join(parts)
    return chained


def stage_out_dir(args) -> Path:
    if args.output_dir:
        return Path(args.output_dir)
    return Path(__file__).parent / "reviews" / args.context_name


# Provider/CLI failure signatures. Only signatures that never appear in
# legitimate review prose are matched across the whole output; generic words
# like "error" or "timeout" are intentionally absent so that review findings
# about timeouts or unauthorized responses are not misclassified. The network
# group covers offline/DNS/TLS/proxy failures, which agent CLIs report with
# these exact phrases when the machine loses connectivity.
_AGENT_ERROR_PATTERNS = (
    # provider error codes (quota, rate limit, billing, auth)
    re.compile(r"rate_?limit_?error", re.IGNORECASE),
    re.compile(r"insufficient_?quota", re.IGNORECASE),
    re.compile(r"quota_?exceeded", re.IGNORECASE),
    re.compile(r"credit_?balance_?too_?low", re.IGNORECASE),
    re.compile(r"billing_?error", re.IGNORECASE),
    re.compile(r"payment_?required", re.IGNORECASE),
    re.compile(r"invalid_?api_?key", re.IGNORECASE),
    re.compile(r"authentication_?error", re.IGNORECASE),
    re.compile(r"context_?length_?exceeded", re.IGNORECASE),
    re.compile(r"overloaded_?error", re.IGNORECASE),
    re.compile(r"429 too many requests", re.IGNORECASE),
    # network connectivity failures (offline, DNS, TLS, proxy)
    re.compile(r"network is unreachable", re.IGNORECASE),
    re.compile(r"no route to host", re.IGNORECASE),
    re.compile(r"temporary failure in name resolution", re.IGNORECASE),
    re.compile(r"name or service not known", re.IGNORECASE),
    re.compile(r"dns resolution failed", re.IGNORECASE),
    re.compile(r"getaddrinfo", re.IGNORECASE),
    re.compile(r"max retries exceeded", re.IGNORECASE),
    re.compile(r"certificate verify failed", re.IGNORECASE),
    re.compile(r"connectionerror", re.IGNORECASE),
    re.compile(r"sslerror", re.IGNORECASE),
    re.compile(r"proxyerror", re.IGNORECASE),
    re.compile(r"econnrefused", re.IGNORECASE),
    re.compile(r"econnreset", re.IGNORECASE),
    re.compile(r"etimedout", re.IGNORECASE),
    re.compile(r"curl: \(\d+\)", re.IGNORECASE),
    re.compile(r"connection timed out", re.IGNORECASE),
    re.compile(r"connect timed out", re.IGNORECASE),
    re.compile(r"operation timed out", re.IGNORECASE),
    re.compile(r"connection refused", re.IGNORECASE),
    re.compile(r"connection reset", re.IGNORECASE),
    re.compile(r"connection closed", re.IGNORECASE),
    re.compile(r"broken pipe", re.IGNORECASE),
    re.compile(r"failed to connect", re.IGNORECASE),
    re.compile(r"unable to connect", re.IGNORECASE),
    re.compile(r"could not connect", re.IGNORECASE),
    # CLI-level failure banners
    re.compile(r"^\[?error\]?:", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^fatal:", re.IGNORECASE | re.MULTILINE),
)


def agent_failure_reason(returncode: int, output: str) -> str:
    """Return a short reason when the agent result must be discarded, or ''
    when the output is a usable result. Non-zero exit, empty output, and
    provider/CLI failure signatures (quota, rate limit, auth, billing) all
    reject the result so error replies are never saved as review files."""
    if returncode != 0:
        return f"agent exited {returncode}"
    if not output or not output.strip():
        return "agent produced no output"
    for pattern in _AGENT_ERROR_PATTERNS:
        if pattern.search(output):
            return f"agent reported provider failure ({pattern.pattern})"
    return ""


def run_stage(stage: str, prompt: str, args, session_flags: Optional[list] = None) -> int:
    """Invoke the agent and persist only validated output. Output streams to
    the terminal while running; stage-NN.out.md is written only when the
    agent exits 0 and the output carries no provider/CLI failure signature.
    Rejected output is not saved and the stage fails, so quota or rate-limit
    replies cannot become committed review artifacts."""
    out_dir = stage_out_dir(args)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"stage-{stage}.out.md"

    agent_bin = args.agent_bin or AGENT_BIN
    cmd = [agent_bin, "-p", prompt]
    if args.model:
        cmd.extend(["--model", args.model])
    if session_flags:
        cmd.extend(session_flags)

    print(f"\n{'='*60}", flush=True)
    print(f"  Stage {stage}: {STAGES[stage]}", flush=True)
    print(f"  Output: {out_file}", flush=True)
    print(f"{'='*60}\n", flush=True)

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=args.repo or os.getcwd(),
            start_new_session=True,  # own process group so the whole child tree can be killed on timeout
        )
        assert proc.stdout is not None

        # Stream to the terminal from a reader thread so the main thread can
        # enforce the deadline; a hung agent (e.g. offline machine) must not
        # block the runner forever.
        lines = []

        def _read():
            for line in proc.stdout:
                print(line, end="", flush=True)
                lines.append(line)

        reader = threading.Thread(target=_read, daemon=True)
        reader.start()
        try:
            rc = proc.wait(timeout=getattr(args, "timeout", 0) or 600)
        except subprocess.TimeoutExpired:
            # Kill the whole group: the direct child may have spawned helpers
            # (e.g. a shell running sleep) that keep the pipe open.
            os.killpg(proc.pid, signal.SIGKILL)
            reader.join(timeout=5)
            print(f"\nStage {stage} REJECTED: agent timed out; output NOT saved to {out_file}", file=sys.stderr, flush=True)
            return 1
        reader.join(timeout=5)
    except FileNotFoundError:
        print(f"ERROR: '{agent_bin}' not found in PATH.", file=sys.stderr)
        return 1

    output = "".join(lines)
    reason = agent_failure_reason(rc, output)
    if reason:
        print(f"\nStage {stage} REJECTED: {reason}; output NOT saved to {out_file}", file=sys.stderr, flush=True)
        return 1
    out_file.write_text(output, encoding="utf-8")
    print(f"\nWROTE: {out_file}", flush=True)
    return 0


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
    p.add_argument("--resume", action="store_true",
                   help="Resume a previous --all session: skip stages whose output file already exists and chain from the saved outputs")
    p.add_argument("--context", metavar="FILE",
                   help="Context YAML file with subsystem details")
    p.add_argument("--project", help="Project name (overrides context YAML)")
    p.add_argument("--subsystem", help="Subsystem name (overrides context YAML)")
    p.add_argument("--files", help="Comma-separated list of primary files")
    p.add_argument("--rfcs", help="Comma-separated RFC/standard references")
    p.add_argument("--repo", help="Repository path (default: cwd)")
    p.add_argument("--model", default="", help="Model for pi invocation")
    p.add_argument("--agent-bin", default="", help="Agent CLI binary (default: ai-dev/pi-batch.yaml agent.bin, else 'pi')")
    p.add_argument("--timeout", type=int, default=0,
                   help="Per-stage agent timeout in seconds (default: 600; 0 = default)")
    p.add_argument("--session-mode", choices=["new", "shared"], default="new",
                   help="Session reuse across --all stages: new = fresh session per stage (default), shared = one session for the whole review run")
    p.add_argument("--session-name", default="",
                   help="Reproducible session base name (default: context name); shared sessions continue across runs")
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

    if args.resume and not args.all:
        print("ERROR: --resume requires --all", file=sys.stderr)
        sys.exit(1)

    if args.session_mode != "new" and not args.all:
        print("ERROR: --session-mode shared requires --all", file=sys.stderr)
        sys.exit(1)

    out_dir = stage_out_dir(args)
    failures = []
    prior_outputs: dict = {}
    session_name = args.session_name or args.context_name
    if args.resume:
        # Resume a previous session: load completed outputs from disk so
        # downstream stages chain from them, and skip stages that already
        # produced a non-empty file (they ran and passed validation last
        # time; rejected stages never leave a file, so they rerun).
        for stage in stages_to_run:
            out_file = out_dir / f"stage-{stage}.out.md"
            if out_file.exists() and out_file.stat().st_size > 0:
                prior_outputs[stage] = out_file.read_text(encoding="utf-8")
        skipped = len(prior_outputs)
        print(f"Resume: {skipped} completed stage(s) found, {len(stages_to_run) - skipped} to run", flush=True)

    session_active = False
    for stage in stages_to_run:
        if args.resume and stage in prior_outputs:
            print(f"  Stage {stage}: SKIP (output exists: {out_dir / f'stage-{stage}.out.md'})", flush=True)
            continue

        template_file = prompts_dir / STAGES[stage]
        if not template_file.exists():
            print(f"ERROR: template not found: {template_file}", file=sys.stderr)
            failures.append(stage)
            continue

        # Build variable map for this stage
        defaults = STAGE_VARS.get(stage, {})
        variables = {k: ctx.get(k.lower(), v) for k, v in defaults.items()}
        variables.update(context_to_vars(ctx, stage))
        variables.update(chain_variables(prior_outputs, stage, variables, defaults))

        prompt = fill_template(template_file, variables)

        if args.dry_run:
            print(f"\n{'='*60}")
            print(f"  Stage {stage} — DRY RUN")
            print(f"{'='*60}")
            print(prompt)
            continue

        # Shared session: the first executed stage starts the session, later
        # stages continue it; --resume skips do not consume the session.
        flags = None
        if args.session_mode != "new":
            if not session_active:
                flags = session_flags("start", session_name, session_name)
                session_active = True
            else:
                flags = session_flags("continue", session_name, session_name)

        rc = run_stage(stage, prompt, args, flags)
        if rc != 0:
            failures.append(stage)
            if not args.all:
                sys.exit(rc)
            continue

        # Keep completed output for chaining into later stages of --all.
        out_file = stage_out_dir(args) / f"stage-{stage}.out.md"
        if out_file.exists():
            prior_outputs[stage] = out_file.read_text(encoding="utf-8")

    if failures:
        print(f"\nFailed stages: {', '.join(failures)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
