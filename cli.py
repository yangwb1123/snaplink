#!/usr/bin/env python3
"""snaplink engineering CLI — cross-platform entry point.

Usage:
    python cli.py <command> [options]

Commands:
    generate              Regenerate engineering scaffolding
    check                 Quick check (filesize + vet)
    check-filesize        File size check
    accept                Full acceptance suite (EVALUATION.md)
    harness               Full engineering gates (filesize + complexity + architecture)
    complexity            Cyclomatic + cognitive complexity check
    architecture          Dependency direction check
    coverage              Run test coverage
    evaluate              Coverage + coverage-check
    review [spec]         Review checklist / feature review
    diagnose              Run diagnosis
    trend                 Record trend snapshot
    health-report         Health report
    check-exemptions      Check exemption sync
    self-test             Harness self-test
    check-invariants      Security invariants
    test                  Run go tests
    race                  Run tests with -race
    bench                 Run benchmarks
    vet                   Run go vet
    fmt                   Check gofmt
    build                 Build binaries to bin/
    lint                  Run golangci-lint
    security-scan         Run govulncheck + gosec
    skill <name> [args..] Run a skill by directory name
    help                  Show this message
"""

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# Ensure checks/ is on the path
sys.path.insert(0, str(ROOT))


def run(*args: str, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), capture_output=False, text=True, check=False, **kwargs)


def cmd_generate():
    sys.path.insert(0, str(ROOT / "scripts"))
    from generate_engineering import run as gen_run
    return gen_run()


def cmd_check():
    cmd_generate()
    from checks.filesize import run as fs_run
    ec = fs_run()
    if ec != 0:
        return ec
    return run("go", "vet", "./...").returncode


def cmd_check_filesize():
    cmd_generate()
    from checks.filesize import run as fs_run
    return fs_run()


def cmd_accept():
    from checks.acceptance import run as acc_run
    return acc_run()


def cmd_harness():
    ec = cmd_generate()
    if ec != 0:
        return ec
    from checks.filesize import run as fs_run
    from checks.complexity import run as cx_run
    from checks.architecture import run as ar_run
    ec = fs_run()
    ec += cx_run()
    ec += ar_run()
    return 1 if ec > 0 else 0


def cmd_complexity():
    from checks.complexity import run as cx_run
    return cx_run()


def cmd_architecture():
    from checks.architecture import run as ar_run
    return ar_run()


def cmd_coverage():
    from checks.coverage import run as cv_run
    return cv_run()


def cmd_evaluate():
    ec = cmd_coverage()
    if ec != 0:
        return ec
    from checks.coverage import run as cv_run
    return cv_run()


def cmd_review(spec: str | None):
    if spec:
        from checks.review_feature import run as rv_run
        return rv_run(spec)
    checklist = ROOT / "docs" / "review-checklist.md"
    if checklist.exists():
        print(checklist.read_text())
    return 0


def cmd_diagnose():
    sys.path.insert(0, str(ROOT / "scripts"))
    from diagnose import run as diag_run
    return diag_run()


def cmd_trend():
    sys.path.insert(0, str(ROOT / "scripts"))
    from trend import run as tr_run
    return tr_run()


def cmd_health_report():
    from checks.health_report import run as hr_run
    return hr_run()


def cmd_check_exemptions():
    from checks.exemptions import run as ex_run
    return ex_run()


def cmd_self_test():
    from checks.self_test import run as st_run
    return st_run()


def cmd_check_invariants():
    from checks.invariants import run as iv_run
    return iv_run()


def cmd_test():
    return run("go", "test", "./...").returncode


def cmd_race():
    return run("go", "test", "-race", "-count=1", "./...").returncode


def cmd_bench():
    return run("go", "test", "-run=^$", "-bench=.", "-benchmem",
               "./defaultimpl/", "./oauth/", "./ratelimit/", "./security/").returncode


def cmd_vet():
    return run("go", "vet", "./...").returncode


def cmd_fmt():
    result = subprocess.run(
        "gofmt -l . | grep -v '^.claude/'",
        shell=True, text=True, capture_output=True, check=False
    )
    if result.stdout and result.stdout.strip():
        print("Unformatted files:", result.stdout, file=sys.stderr)
        return 1
    return 0


def cmd_build():
    bin_dir = ROOT / "bin"
    bin_dir.mkdir(exist_ok=True)
    r1 = run("go", "build", "-trimpath", "-o", str(bin_dir / "sso-server"), "./cmd/sso-server")
    if r1.returncode != 0:
        return r1.returncode
    return run("go", "build", "-trimpath", "-o", str(bin_dir / "sso-import"), "./cmd/sso-import").returncode


def cmd_lint():
    return run("go", "run", "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest",
               "run", "--timeout", "5m").returncode


def cmd_security_scan():
    r1 = run("go", "run", "golang.org/x/vuln/cmd/govulncheck@latest", "./...")
    if r1.returncode != 0:
        return r1.returncode
    return run("go", "run", "github.com/securego/gosec/v2/cmd/gosec@latest",
               "-quiet", "./...").returncode


def cmd_skill(args: list[str]):
    if not args:
        print("Usage: python cli.py skill <name> [args..]", file=sys.stderr)
        skill_dir = ROOT / "skills"
        print("\nAvailable skills:", file=sys.stderr)
        for d in sorted(skill_dir.iterdir()):
            if d.is_dir() and not d.name.startswith("_") and d.name != "shared":
                print(f"  {d.name}", file=sys.stderr)
        return 1
    name = args[0]
    skill_path = ROOT / "skills" / name / "run.py"
    if not skill_path.exists():
        print(f"ERROR: skill '{name}' not found at {skill_path}", file=sys.stderr)
        return 1
    return subprocess.run([sys.executable, str(skill_path)] + args[1:]).returncode


def cmd_help():
    print(__doc__.strip())
    return 0


COMMANDS = {
    "generate": cmd_generate,
    "check": cmd_check,
    "check-filesize": cmd_check_filesize,
    "accept": cmd_accept,
    "harness": cmd_harness,
    "complexity": cmd_complexity,
    "architecture": cmd_architecture,
    "coverage": cmd_coverage,
    "evaluate": cmd_evaluate,
    "review": cmd_review,
    "diagnose": cmd_diagnose,
    "trend": cmd_trend,
    "health-report": cmd_health_report,
    "check-exemptions": cmd_check_exemptions,
    "self-test": cmd_self_test,
    "check-invariants": cmd_check_invariants,
    "test": cmd_test,
    "race": cmd_race,
    "bench": cmd_bench,
    "vet": cmd_vet,
    "fmt": cmd_fmt,
    "build": cmd_build,
    "lint": cmd_lint,
    "security-scan": cmd_security_scan,
    "skill": cmd_skill,
    "help": cmd_help,
}


def main():
    parser = argparse.ArgumentParser(
        prog="agent",
        description="snaplink engineering CLI",
        add_help=False,
    )
    parser.add_argument("command", nargs="?", default="help", help="Command to run")
    parser.add_argument("args", nargs=argparse.REMAINDER, help="Command arguments")

    parsed, unknown = parser.parse_known_args()
    cmd = parsed.command

    if cmd in ("-h", "--help"):
        cmd = "help"

    if cmd not in COMMANDS:
        print(f"ERROR: unknown command '{cmd}'. Use 'python cli.py help' for usage.", file=sys.stderr)
        return 1

    handler = COMMANDS[cmd]
    if cmd == "review":
        spec = parsed.args[0] if parsed.args else None
        return handler(spec)
    elif cmd == "skill":
        return handler(parsed.args + unknown)
    elif cmd == "help":
        return handler()
    else:
        return handler()


if __name__ == "__main__":
    sys.exit(main())
