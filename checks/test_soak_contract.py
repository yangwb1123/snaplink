"""The soak observer must refuse to start on its own terms.

Each refusal is a boundary that keeps an unattended window from silently
becoming something the operator never authorized, so they are asserted here
rather than only checked by hand.
"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path.cwd()
SCRIPT = ROOT / "ops" / "scripts" / "soak.py"
BASE = ["--root", "/tmp/soak-contract", "--container", "c", "--label", "l",
        "--database", "snaplink_mig_contract", "--snapshot", "s", "--snapshot-sha256", "0" * 64,
        "--policy-template", "p", "--base-commit", "0" * 40, "--schema-init", "i",
        "--sso-server", "b", "--authorize", "I-ACCEPT-THE-SOAK-BUDGET"]


def run(*extra):
    result = subprocess.run([sys.executable, "-B", str(SCRIPT), *BASE, *extra],
                            capture_output=True, text=True, timeout=120, cwd=ROOT)
    body = {}
    for line in (result.stdout or "").splitlines():
        if line.startswith("{"):
            body = json.loads(line)
    return result.returncode, body


def test_script_is_discoverable():
    assert SCRIPT.is_file()
    makefile = (ROOT / "docs" / "agent-os" / "MIGRATION_REHEARSAL.md").read_text()
    assert "ops/scripts/soak.py" in makefile


def test_refuses_without_authorization():
    code, body = run("--days", "30", "--plan", "--authorize", "")
    assert code == 2 and body["reason"] == "soak_authorization_required"


def test_refuses_day_budget_outside_the_ceiling():
    for days in ("0", "400"):
        code, body = run("--days", days, "--plan")
        assert code == 2 and body["reason"] == "soak_days_out_of_range", days


def test_refuses_interval_below_the_floor():
    code, body = run("--days", "1", "--interval", "5", "--plan")
    assert code == 2 and body["reason"] == "soak_interval_out_of_range"


def test_refuses_budget_above_the_ceiling():
    code, body = run("--days", "1", "--max-log-mib", "128", "--plan")
    assert code == 2 and body["reason"] == "soak_budget_above_ceiling"
    code, body = run("--days", "1", "--max-disk-mib", "4096", "--plan")
    assert code == 2 and body["reason"] == "soak_budget_above_ceiling"


def test_refuses_a_database_that_is_not_a_rehearsal_candidate():
    code, body = run("--days", "1", "--plan", "--database", "snaplink")
    assert code == 2 and body["reason"] == "soak_database_must_be_a_rehearsal_candidate"


def test_refuses_a_deadline_in_the_past():
    code, body = run("--days", "1", "--plan", "--deadline", "2020-01-01T00:00:00+00:00")
    assert code == 2 and body["reason"] == "soak_deadline_in_the_past"


def test_plan_records_what_will_actually_be_observed():
    code, body = run("--days", "30", "--interval", "3600", "--plan")
    assert code == 0
    plan = body["plan"]
    assert plan["cycles"] == 720
    assert plan["budget"]["days"] == 30
    assert 0 < plan["budget"]["observed_days"] <= 30
    assert plan["budget"]["storage"] == "tmpfs"
    assert plan["budget"]["log_mib"] == 64


def test_remote_upgrade_refuses_without_its_inputs():
    """The remote upgrader must not run on a half-specified plan."""
    script = ROOT / "ops" / "scripts" / "remote_upgrade.sh"
    assert script.is_file()
    for args, reason in (([], "service_required"),
                         (["--service", "x"], "binary_required"),
                         (["--service", "x", "--binary", "y"], "target_required")):
        result = subprocess.run(["bash", str(script), *args], capture_output=True, text=True, timeout=60, cwd=ROOT)
        assert result.returncode == 2 and reason in result.stderr, (args, result.stderr)


def test_remote_upgrade_dry_run_requires_a_real_binary_and_sql():
    script = ROOT / "ops" / "scripts" / "remote_upgrade.sh"
    result = subprocess.run(["bash", str(script), "--dry-run", "--service", "s", "--binary", "/nonexistent/sso-server",
                             "--target", "/tmp/t", "--pg-host", "h", "--verify-sql", "/nonexistent.sql",
                             "--workdir", "/tmp/w"], capture_output=True, text=True, timeout=60, cwd=ROOT)
    assert result.returncode == 2 and "binary_missing" in result.stderr


def test_remote_upgrade_refuses_a_relative_bootstrap_state_path(tmp_path):
    """A hardened unit cannot write a relative tracker; the deploy must refuse it."""
    script = ROOT / "ops" / "scripts" / "remote_upgrade.sh"
    bad = tmp_path / "bad.yaml"
    bad.write_text('bootstrap:\n  disabled: false\n  state_path: "bootstrap.json"\n')
    binary = tmp_path / "sso-server"
    binary.write_text("#!/bin/sh\necho fake\n")
    binary.chmod(0o755)
    sql = tmp_path / "verify.sql"
    sql.write_text("select 1;\n")
    result = subprocess.run(["bash", str(script), "--dry-run", "--service", "s", "--binary", str(binary),
                             "--target", str(tmp_path / "t"), "--pg-host", "h", "--config", str(bad),
                             "--verify-sql", str(sql), "--workdir", str(tmp_path / "w")],
                            capture_output=True, text=True, timeout=60, cwd=ROOT)
    assert result.returncode == 2 and "bootstrap_state_path_relative" in result.stderr
