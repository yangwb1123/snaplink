"""The rehearsal must stay discoverable and refuse to run with missing inputs."""
import subprocess
import sys
from pathlib import Path


def test_make_target_is_documented_for_help():
    text = (Path.cwd() / "Makefile").read_text()
    line = next(l for l in text.splitlines() if l.startswith("migration-rehearsal:"))
    assert "##" in line and "SNAPSHOT" in line


def test_make_target_refuses_without_required_inputs():
    result = subprocess.run(["make", "migration-rehearsal"], capture_output=True, text=True, timeout=120)
    assert result.returncode == 2
    assert "SNAPSHOT is required" in (result.stdout + result.stderr)


def test_runbook_states_the_non_claims():
    doc = (Path.cwd() / "docs/agent-os/MIGRATION_REHEARSAL.md").read_text()
    for phrase in ("does **not** authorize cutover", "authenticated HTTP", "bcrypt hashes"):
        assert phrase in doc


def test_entry_script_exists_and_refuses_without_arguments():
    script = Path.cwd() / "ops/scripts/migration_rehearsal.py"
    assert script.is_file()
    result = subprocess.run([sys.executable, "-B", str(script)], capture_output=True, text=True, timeout=120)
    assert result.returncode == 2, "argparse must reject a missing action"


def test_makefile_invokes_the_entry_script_not_the_package_module():
    text = (Path.cwd() / "Makefile").read_text()
    assert "ops/scripts/migration_rehearsal.py" in text
    assert "rehearsal_cli.py run" not in text


def test_makefile_forwards_every_opt_in_step():
    makefile = (Path.cwd() / "Makefile").read_text()
    for flag in ("--replay-guard", "--concurrency-guard", "--durable-storage", "--auth-smoke", "--sso-ctl", "--determinism", "--drift-check", "--write-check", "--readpath", "--sso-server"):
        assert flag in makefile, flag


def test_makefile_and_runbook_avoid_sso_prefixed_variables():
    makefile = (Path.cwd() / "Makefile").read_text()
    assert "REHEARSAL_SSO_SERVER" in makefile and '$(if $(SSO_SERVER)' not in makefile
    doc = (Path.cwd() / "docs/agent-os/MIGRATION_REHEARSAL.md").read_text()
    assert "REHEARSAL_SSO_SERVER" in doc and "maps them into its own config tree" in doc
