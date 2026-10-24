"""Ownership/credential/input controls and owned-process budget witnesses."""
import json
import os
import sys

import pytest

from checks.migration_guard_fixture import connection_config, private_config
from migration_guard.postgres import bounded_psql, connection_file
from migration_guard.snapshot import GuardFailure


def test_only_private_owned_loopback_candidate_is_accepted(tmp_path):
    config = connection_config()
    path = private_config(tmp_path, config)
    assert connection_file(path) == config
    for key, value in [("host", "192.168.123.52"), ("database", "snaplink"), ("port", True),
                       ("port", 65536), ("owner_token", "unknown"), ("password", "")]:
        path.write_text(json.dumps(dict(config, **{key: value})))
        with pytest.raises(GuardFailure):
            connection_file(path)
    path.write_text(json.dumps(dict(config, unknown_field=True)))
    with pytest.raises(GuardFailure, match="unknown_or_missing"):
        connection_file(path)


def test_duplicate_connection_fields_and_public_mode_reject(tmp_path):
    config = connection_config()
    path = private_config(tmp_path, config)
    text = path.read_text()
    path.write_text(text[:-1] + ', "password":"ambiguous"}')
    with pytest.raises(GuardFailure, match="duplicate_connection"):
        connection_file(path)
    path.write_text(text)
    path.chmod(0o644)
    with pytest.raises(GuardFailure, match="file_mode"):
        connection_file(path)


def test_child_nonzero_does_not_disclose_diagnostic_secret():
    env = dict(os.environ, SYNTHETIC_SECRET="synthetic-private-password")
    child = [sys.executable, "-c", "import os,sys;sys.stderr.write(os.environ['SYNTHETIC_SECRET']);sys.exit(3)"]
    with pytest.raises(GuardFailure, match="diagnostics_withheld") as error:
        bounded_psql(child, env, "SELECT 1;", 2)
    assert "synthetic-private-password" not in str(error.value)


def test_child_stdout_stderr_and_wall_limits_are_closed():
    for pipe, size in [("stdout", (2 << 20) + 1), ("stderr", (8 << 10) + 1)]:
        code = f"import sys;sys.{pipe}.buffer.write(b'x'*{size});sys.{pipe}.flush()"
        with pytest.raises(GuardFailure, match="output_budget"):
            bounded_psql([sys.executable, "-c", code], os.environ.copy(), "SELECT 1;", 2)
    with pytest.raises(GuardFailure, match="target_query_timeout"):
        bounded_psql([sys.executable, "-c", "import time;time.sleep(5)"], os.environ.copy(), "SELECT 1;", .1)


def test_input_limit_and_normal_child_exit():
    with pytest.raises(GuardFailure, match="input_budget"):
        bounded_psql([sys.executable], os.environ.copy(), "x" * 4097, 2)
    child = [sys.executable, "-c", "import sys;data=sys.stdin.read();print(len(data))"]
    assert bounded_psql(child, os.environ.copy(), "SELECT 1;", 2) == b"9\n"
