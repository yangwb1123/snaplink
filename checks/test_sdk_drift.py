from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from checks import sdk_drift


FAKE_GENERATOR = """
import pathlib
import shutil
import sys

payload_ts = pathlib.Path(sys.argv[1])
payload_py = pathlib.Path(sys.argv[2])
out_ts = out_py = None
for argument in sys.argv[3:]:
    if argument.startswith('--out-ts='):
        out_ts = pathlib.Path(argument.split('=', 1)[1])
    if argument.startswith('--out-py='):
        out_py = pathlib.Path(argument.split('=', 1)[1])
shutil.copyfile(payload_ts, out_ts)
shutil.copyfile(payload_py, out_py)
"""


def _write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def _git_commit(root: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=sdk-drift-test",
            "-c",
            "user.email=sdk-drift-test@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
        cwd=root,
        check=True,
    )


@pytest.fixture
def tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    return _make_tree(tmp_path, monkeypatch)


def _make_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    root = tmp_path / "repo"
    payload_ts = tmp_path / "payload.ts"
    payload_py = tmp_path / "payload.py"
    _write(payload_ts, b"export const generated = 'ts';\n")
    _write(payload_py, b"generated = 'py'\n")
    _write(root / "docs/openapi.yaml", b"openapi: 3.0.3\n")
    _write(root / "docs/sdks/typescript/client.ts", payload_ts.read_bytes())
    _write(root / "docs/sdks/python/client.py", payload_py.read_bytes())
    _write(root / "docs/sdks/typescript/dist/client.js", b"built\n")
    _write(root / "ops/deploy/openresty/fullstack/static/docs/openapi.yaml", b"openapi: 3.0.3\n")
    _write(
        root / "ops/deploy/openresty/fullstack/static/docs/sdks/client.ts",
        payload_ts.read_bytes(),
    )
    _write(
        root / "ops/deploy/openresty/fullstack/static/docs/sdks/client.py",
        payload_py.read_bytes(),
    )
    _git_commit(root)
    monkeypatch.setattr(sdk_drift, "ROOT", root)
    monkeypatch.setattr(
        sdk_drift,
        "REGEN_CMD",
        [sys.executable, "-c", FAKE_GENERATOR, str(payload_ts), str(payload_py)],
    )
    return {
        "root": root,
        "ts": root / "docs/sdks/typescript/client.ts",
        "py": root / "docs/sdks/python/client.py",
        "dist": root / "docs/sdks/typescript/dist/client.js",
        "openapi": root / "docs/openapi.yaml",
        "static": root / "ops/deploy/openresty/fullstack/static",
        "static_ts": root / "ops/deploy/openresty/fullstack/static/docs/sdks/client.ts",
        "static_py": root / "ops/deploy/openresty/fullstack/static/docs/sdks/client.py",
        "static_openapi": root / "ops/deploy/openresty/fullstack/static/docs/openapi.yaml",
    }


def test_clean_tree_passes(tree: dict[str, Path], capsys: pytest.CaptureFixture[str]):
    assert sdk_drift.run(["check"]) == 0
    output = capsys.readouterr().out
    assert "OK (regen 2/2, deploy 3/3)" in output


def test_absent_deploy_tree_skips(tree: dict[str, Path], capsys: pytest.CaptureFixture[str]):
    shutil.rmtree(tree["static"])

    assert sdk_drift.run(["check"]) == 0
    output = capsys.readouterr().out
    assert "SKIP deploy leg (static tree absent)" in output


@pytest.mark.parametrize(
    ("key", "label"),
    [("ts", "docs/sdks/typescript/client.ts"), ("py", "docs/sdks/python/client.py")],
)
def test_stale_committed_copy_fails_and_restores(
    tree: dict[str, Path], key: str, label: str, capsys: pytest.CaptureFixture[str]
):
    original = tree[key].read_bytes()
    tree[key].write_bytes(original + b"stale\n")

    assert sdk_drift.run(["check"]) == 1
    assert label in capsys.readouterr().out

    tree[key].write_bytes(original)
    assert sdk_drift.run(["check"]) == 0


@pytest.mark.parametrize(
    ("key", "source"),
    [
        ("static_openapi", "docs/openapi.yaml"),
        ("static_ts", "docs/sdks/typescript/client.ts"),
        ("static_py", "docs/sdks/python/client.py"),
    ],
)
def test_stale_deploy_copy_fails_and_restores(
    tree: dict[str, Path], key: str, source: str, capsys: pytest.CaptureFixture[str]
):
    original = tree[key].read_bytes()
    tree[key].write_bytes(original + b"stale\n")

    assert sdk_drift.run(["check"]) == 1
    output = capsys.readouterr().out
    assert str(tree[key].relative_to(tree["root"])) in output
    assert source in output

    tree[key].write_bytes(original)
    assert sdk_drift.run(["check"]) == 0


@pytest.mark.parametrize("key", ["static_openapi", "static_ts", "static_py"])
def test_missing_deploy_target_fails(tree: dict[str, Path], key: str, capsys: pytest.CaptureFixture[str]):
    tree[key].unlink()

    assert sdk_drift.run(["check"]) == 1
    assert str(tree[key].relative_to(tree["root"])) in capsys.readouterr().out


def test_stray_file_under_docs_sdks_fails(tree: dict[str, Path], capsys: pytest.CaptureFixture[str]):
    stray = tree["root"] / "docs/sdks/stray.txt"
    stray.write_text("not generated")

    assert sdk_drift.run(["check"]) == 1
    assert "docs/sdks/stray.txt" in capsys.readouterr().out


def test_dist_dirt_does_not_fail(tree: dict[str, Path], capsys: pytest.CaptureFixture[str]):
    tree["dist"].write_bytes(b"local npm build\n")

    assert sdk_drift.run(["check"]) == 0
    assert "OK (regen 2/2, deploy 3/3)" in capsys.readouterr().out


def test_generator_failure_reports_stderr_and_does_not_mutate_tree(
    tree: dict[str, Path], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    before = {key: tree[key].read_bytes() for key in ("ts", "py")}
    monkeypatch.setattr(
        sdk_drift,
        "REGEN_CMD",
        [sys.executable, "-c", "import sys; print('fake generator failed', file=sys.stderr); sys.exit(7)"],
    )

    assert sdk_drift.run(["check"]) == 1
    output = capsys.readouterr().out
    assert "generator failed with exit 7" in output
    assert "fake generator failed" in output
    assert {key: tree[key].read_bytes() for key in ("ts", "py")} == before


def test_missing_go_is_a_clear_failure(tree: dict[str, Path], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
    monkeypatch.setattr(sdk_drift, "REGEN_CMD", ["go-command-that-is-not-installed"])

    assert sdk_drift.run(["check"]) == 1
    assert "generator unavailable" in capsys.readouterr().out


def test_git_failure_is_fail_closed(tree: dict[str, Path], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
    monkeypatch.setattr(
        sdk_drift,
        "run_git",
        lambda args, cwd: SimpleNamespace(returncode=128, stdout="", stderr="not a git repository"),
    )

    assert sdk_drift.run(["check"]) == 1
    output = capsys.readouterr().out
    assert "git status failed" in output
    assert "not a git repository" in output


def test_temp_dir_cleaned_on_failure(
    tree: dict[str, Path], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    scratch = tmp_path / "temp-root"
    scratch.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(scratch))
    monkeypatch.setattr(
        sdk_drift,
        "REGEN_CMD",
        [sys.executable, "-c", "import sys; sys.exit(3)"],
    )

    assert sdk_drift.run(["check"]) == 1
    assert list(scratch.iterdir()) == []


def test_diff_sample_is_capped(tree: dict[str, Path], capsys: pytest.CaptureFixture[str]):
    tree["ts"].write_bytes(b"".join(f"canonical-{i}\n".encode() for i in range(100)))

    assert sdk_drift.run(["check"]) == 1
    output = capsys.readouterr().out
    assert "diff sample truncated at 10 lines" in output
    assert len(output) < 2000


def test_unknown_action_has_usage_error():
    with pytest.raises(SystemExit) as error:
        sdk_drift.run(["unknown"])
    assert error.value.code == 2


def test_cli_wiring_and_existing_sdk_surface_entrypoint():
    import cli

    assert cli.COMMANDS["sdk-drift"] is cli.cmd_sdk_drift
    source = Path("cli.py").read_text()
    assert "sdk-drift              Regenerate SDKs" in source
    assert '"sdk-drift"' in source
    assert '"sdk-surface": cmd_sdk_surface' in source
    assert "from checks.sdk_drift import run as sdk_drift_run" in source
    assert "sdk_drift" not in Path("ops/scripts/sdk_surface.py").read_text()


def test_makefile_wiring():
    source = Path("Makefile").read_text()
    assert any(
        line.startswith(".PHONY:") and "sdk-drift-check" in line
        for line in source.splitlines()
    )
    assert "sdk-drift-check: ## Regenerate SDKs in a temporary tree" in source
    ci_line = next(line for line in source.splitlines() if line.startswith("ci: "))
    assert "sdk-drift-check" in ci_line


def test_real_gensdk_is_deterministic(tmp_path: Path):
    go = shutil.which("go")
    if go is None:
        pytest.skip("Go toolchain is unavailable; fake-generator acceptance tests still run")
    outputs = [tmp_path / "one", tmp_path / "two"]
    env = os.environ.copy()
    env["GOPROXY"] = "off"
    for output in outputs:
        output.mkdir()
        result = subprocess.run(
            [
                go,
                "run",
                "./cmd/gensdk",
                "--lang=all",
                f"--out-ts={output / 'client.ts'}",
                f"--out-py={output / 'client.py'}",
                "--out-package-py=",
            ],
            cwd=sdk_drift.ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
    assert (outputs[0] / "client.ts").read_bytes() == (outputs[1] / "client.ts").read_bytes()
    assert (outputs[0] / "client.py").read_bytes() == (outputs[1] / "client.py").read_bytes()
