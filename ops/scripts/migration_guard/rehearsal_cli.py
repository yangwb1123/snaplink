"""Owned, explicit, bounded rehearsal driver: provision, initialize, import, verify, close.

Every step is fail-closed and refuses to act on anything it cannot prove it owns:
a container is only removed when the receipt, the live inspect body, the image
digest, the loopback binding and the tmpfs-only layout all still match.
"""
import argparse
import contextlib
import hashlib
import io
import subprocess
import json
import os
import re
import secrets
import socket
import stat
import time
import subprocess
import sys
import time
from pathlib import Path

from .conversion_policy import digest, target_shape_sha256
from .import_cli import main as import_main
from .postgres import connection_file, inspect_target
from .snapshot import GuardFailure, inspect_snapshot
from .target_schema import inspect_native_schema
from .verify_cli import main as verify_main

IMAGE_PIN = "sha256:de3a4eab8fdfa507ea92aac488b916b08089e515db49b055fe71dfa271ba3a28"
DATABASE = re.compile(r"snaplink_mig_[a-z0-9_]{1,32}")
SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
TMPFS = {"/var/lib/postgresql/data": "rw,noexec,nosuid,size=768m"}


def private_dir(root):
    root = Path(root).absolute()
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise GuardFailure("rehearsal_private_directory_required")
    return root


def write_private(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + ".new")
    with temporary.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    os.chmod(path, 0o600)
    return path


def provision_args(values):
    root = private_dir(values["root"])
    if not SHA256.fullmatch(values["image"]):
        raise GuardFailure("rehearsal_digest_pinned_image_required")
    if values["image"] != IMAGE_PIN:
        raise GuardFailure("rehearsal_approved_postgres_digest_required")
    if not DATABASE.fullmatch(values["database"]):
        raise GuardFailure("rehearsal_dedicated_candidate_database_required")
    if not values["container"] or not values["label"]:
        raise GuardFailure("rehearsal_container_and_label_required")
    if (root / "fixture-receipt.json").exists() or (root / "fixture-receipt.json").is_symlink():
        raise GuardFailure("rehearsal_receipt_already_exists")
    return root


def verify_ownership(body, cid, name, label, image):
    if not isinstance(body, dict) or body.get("Id") != cid:
        raise GuardFailure("rehearsal_container_identity_mismatch")
    if body.get("Name") != "/" + name:
        raise GuardFailure("rehearsal_container_name_mismatch")
    if body.get("Image") != image or image != IMAGE_PIN:
        raise GuardFailure("rehearsal_image_digest_mismatch")
    config = body.get("Config") or {}
    if (config.get("Labels") or {}).get("abr.owner") != label:
        raise GuardFailure("rehearsal_owner_label_mismatch")
    host = body.get("HostConfig") or {}
    if host.get("Memory") != 1 << 30 or host.get("MemorySwap") != 1 << 30 or host.get("NanoCpus") != 2_000_000_000:
        raise GuardFailure("rehearsal_resource_caps_mismatch")
    if host.get("Tmpfs") != TMPFS:
        raise GuardFailure("rehearsal_tmpfs_layout_mismatch")
    # docker reports --tmpfs under HostConfig.Tmpfs; Mounts carries bind/volume mounts only,
    # so an empty Mounts list is the expected healthy state and any non-tmpfs entry is a refusal.
    mounts = body.get("Mounts") or []
    if any(m.get("Type") != "tmpfs" for m in mounts):
        raise GuardFailure("rehearsal_tmpfs_only_storage_required")
    ports = ((body.get("NetworkSettings") or {}).get("Ports") or {}).get("5432/tcp") or []
    if len(ports) != 1 or ports[0].get("HostIp") != "127.0.0.1":
        raise GuardFailure("rehearsal_loopback_binding_required")
    port = int(ports[0]["HostPort"])
    if not 1 <= port <= 65535:
        raise GuardFailure("rehearsal_port_out_of_range")
    return port


def close_receipt(root, inspect_body=None, remove=None):
    root = private_dir(root)
    path = root / "fixture-receipt.json"
    if not path.is_file() or path.is_symlink():
        raise GuardFailure("rehearsal_receipt_missing")
    receipt = json.loads(path.read_text())
    for key in ("container_id", "name", "label", "image_id", "database", "port"):
        if key not in receipt:
            raise GuardFailure("rehearsal_receipt_incomplete")
    if inspect_body is None:
        raise GuardFailure("rehearsal_live_ownership_recheck_required")
    port = verify_ownership(inspect_body, receipt["container_id"], receipt["name"], receipt["label"], receipt["image_id"])
    if port != receipt["port"]:
        raise GuardFailure("rehearsal_receipt_port_mismatch")
    if remove is None:
        raise GuardFailure("rehearsal_removal_action_required")
    remove(receipt["container_id"])
    with socket.socket() as probe:
        probe.settimeout(1)
        refused = probe.connect_ex(("127.0.0.1", port)) != 0
    if not refused:
        raise GuardFailure("rehearsal_port_still_accepting")
    for name in ("postgres.env", "test-connection.json", "candidate-connection.json", "ci.dsn", "ci-postgres.env"):
        candidate = root / name
        if candidate.exists() or candidate.is_symlink():
            candidate.unlink()
    write_private(root / "cleanup-receipt.json", dict(result="passed", container_id=receipt["container_id"],
                                                       port_refused=True, private_inputs_removed=True))
    return receipt


def run_bounded(argv, timeout, cwd=None, env=None, stdin=None):
    return subprocess.run(argv, capture_output=True, timeout=timeout, cwd=cwd, env=env, input=stdin)


def provision(root, container, label, database, user, timeout=90):
    root = private_dir(root)
    provision_args(dict(root=root, image=IMAGE_PIN, database=database, container=container, label=label))
    password = secrets.token_urlsafe(32)
    env_file = root / "postgres.env"
    with env_file.open("x") as stream:
        stream.write(f"POSTGRES_USER={user}\nPOSTGRES_DB={database}\nPOSTGRES_PASSWORD={password}\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(env_file, 0o600)
    command = ["docker", "run", "--pull=never", "--detach", "--name", container, "--label", "abr.owner=" + label,
               "--cpus", "2", "--memory", "1g", "--memory-swap", "1g",
               "--tmpfs", "/var/lib/postgresql/data:rw,noexec,nosuid,size=768m",
               "--env-file", str(env_file), "-p", "127.0.0.1::5432", IMAGE_PIN, "-c", "max_connections=100"]
    started = run_bounded(command, timeout)
    if started.returncode:
        raise GuardFailure("rehearsal_provision_failed_diagnostics_withheld")
    cid = started.stdout.decode().strip()
    inspected = run_bounded(["docker", "inspect", cid], 20)
    if inspected.returncode:
        raise GuardFailure("rehearsal_inspect_failed")
    body = json.loads(inspected.stdout.decode())[0]
    port = verify_ownership(body, cid, container, label, IMAGE_PIN)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready = run_bounded(["docker", "exec", cid, "pg_isready", "-h", "127.0.0.1", "-q", "-U", user, "-d", database], 10)
        if ready.returncode == 0:
            break
        time.sleep(0.5)
    else:
        raise GuardFailure("rehearsal_readiness_timeout")
    receipt = dict(container_id=cid, name=container, label=label, image_id=IMAGE_PIN, database=database,
                   port=port, created=body.get("Created"))
    write_private(root / "fixture-receipt.json", receipt)
    connection = dict(host="127.0.0.1", port=port, user=user, database=database, password=password,
                      owner_token=secrets.token_hex(24))
    write_private(root / "test-connection.json", connection)
    return receipt


def run_steps(steps, close):
    """Execute rehearsal steps in order; always try to close the owned fixture.

    A failing step stops the sequence, but cleanup still runs and its outcome is
    reported separately: an unclosed owned container is worse than a failed step.
    """
    results = []
    failure = None
    for name, action in steps:
        if failure is not None:
            results.append(dict(step=name, result="not_executed", reason="previous step failed"))
            continue
        try:
            action()
            results.append(dict(step=name, result="passed"))
        except Exception as exc:  # noqa: BLE001 - every step failure is recorded, never swallowed
            failure = f"{name}: {exc}"
            results.append(dict(step=name, result="failed", reason=str(exc)[:300]))
    cleanup = dict(step="close", result="passed")
    try:
        close()
    except Exception as exc:  # noqa: BLE001 - cleanup failure is reported, not hidden
        cleanup = dict(step="close", result="failed", reason=str(exc)[:300])
    return dict(result="failed" if failure or cleanup["result"] == "failed" else "passed",
                failure=failure, steps=results, cleanup=cleanup,
                scope="owned rehearsal orchestration;NOT cutover or production acceptance")


def remove_container(cid):
    done = run_bounded(["docker", "rm", "-f", cid], 60)
    if done.returncode:
        raise GuardFailure("rehearsal_removal_failed")


def close_owned(root):
    receipt = json.loads((root / "fixture-receipt.json").read_text())
    inspected = run_bounded(["docker", "inspect", receipt["container_id"]], 20)
    if inspected.returncode:
        raise GuardFailure("rehearsal_inspect_failed")
    return close_receipt(root, inspect_body=json.loads(inspected.stdout.decode())[0], remove=remove_container)


def step_plan(args):
    """Ordered step names; write_check is last because it mutates the candidate."""
    names = ["provision", "schema_init"]
    if args.source_snapshot or args.source_sha256 or args.policy_template:
        names += ["import", "verify"]
    if getattr(args, "replay_guard", False):
        names.append("replay_guard")
    if getattr(args, "readpath", None):
        names.append("readpath")
    if getattr(args, "sso_server", None):
        names.append("smoke")
    if getattr(args, "concurrency_guard", False):
        names.append("concurrency_guard")
    if getattr(args, "determinism", False):
        names.append("determinism")
    if getattr(args, "drift_check", False):
        names.append("drift_check")
    if getattr(args, "write_check", False):
        names.append("write_check")
    return names


def run_command(args, root):
    """Orchestrate provision, owned init, optional import+verify, then close.

    Import runs only when a snapshot, its digest and a policy template are
    supplied; the template names the conversion decisions, while source and
    target-shape digests are bound mechanically from the live objects.
    """
    state = {}

    def initialise():
        state["candidate"] = initialise_candidate(root, args.database, args.schema_init)[1]

    def bind_and_import():
        return bind_and_import_inputs(root, args, state["candidate"])

    steps = [("provision", lambda: provision(root, args.container, args.label, args.database, args.user)),
             ("schema_init", initialise)]
    if args.source_snapshot or args.source_sha256 or args.policy_template:
        steps.append(("import", bind_and_import))
        steps.append(("verify", lambda: verify_candidate(root, args)))
    if getattr(args, "replay_guard", False):
        steps.append(("replay_guard", lambda: replay_guard(root, args, state["candidate"])))
    if getattr(args, "readpath", None):
        steps.append(("readpath", lambda: readpath_candidate(root, args.readpath, args.readpath_expect)))
    if getattr(args, "sso_server", None):
        steps.append(("smoke", lambda: smoke_candidate(root, args.sso_server)))
    if getattr(args, "concurrency_guard", False):
        steps.append(("concurrency_guard", lambda: concurrency_guard(root, args, state["candidate"])))
    if getattr(args, "determinism", False):
        steps.append(("determinism", lambda: determinism_check(root, args, state["candidate"])))
    if getattr(args, "drift_check", False):
        steps.append(("drift_check", lambda: native_history_drift(root)))
    # write_check runs last: it mutates the disposable candidate, so every row-count
    # comparison above must already have been taken.
    if getattr(args, "write_check", False):
        steps.append(("write_check", lambda: write_check(root)))
    report = run_steps(steps, lambda: close_owned(root))
    write_private(Path(args.evidence), report)
    print(json.dumps({"result": report["result"], "evidence": args.evidence}))
    return 0 if report["result"] == "passed" else 1


def bind_and_import_inputs(root, args, candidate):
    if not (args.source_snapshot and args.source_sha256 and args.policy_template):
        raise GuardFailure("rehearsal_import_requires_snapshot_digest_and_policy_template")
    connection = connection_file(root / "candidate-connection.json")
    if connection["database"] != candidate:
        raise GuardFailure("rehearsal_candidate_connection_mismatch")
    source = inspect_snapshot(Path(args.source_snapshot), args.source_sha256, timeout=120)
    target = inspect_target(root / "candidate-connection.json")
    base_commit = getattr(args, "base_commit", None)
    if not isinstance(base_commit, str) or re.fullmatch(r"[0-9a-f]{40}", base_commit) is None:
        raise GuardFailure("rehearsal_base_commit_required")
    template = json.loads(Path(args.policy_template).read_text())
    if template.get("version") != 2 or not isinstance(template.get("mappings"), list):
        raise GuardFailure("rehearsal_policy_template_invalid")
    policy = dict(template, source_sha256=source["sha256"], target_shape_sha256=target_shape_sha256(target))
    observed = inspect_native_schema(root / "candidate-connection.json", source, target, policy)
    contract = dict(version=1, algorithm="pg_native_schema_facets_v1", source_sha256=source["sha256"],
                    target_shape_sha256=target_shape_sha256(target),
                    schema_source=dict(base_commit=base_commit, combination_sha256=digest(policy)),
                    environment_sha256=observed["environment_sha256"],
                    tables=[dict(table=n, facets=v["facets"]) for n, v in sorted(observed["tables"].items())])
    policy_path, contract_path = root / "policy.json", root / "schema-contract.json"
    write_private(policy_path, policy)
    write_private(contract_path, contract)
    intent = dict(version=1, scope="owned_candidate_import_v1", source_sha256=source["sha256"],
                  policy_sha256=digest(policy), schema_contract_sha256=_sha(contract_path),
                  target_shape_sha256=target_shape_sha256(target), target_database=candidate,
                  target_owner_sha256=hashlib.sha256(connection["owner_token"].encode()).hexdigest(),
                  expires_at=int(time.time()) + 3600, candidate_exclusive=True,
                  source_is_final_cutover_snapshot=False, historical_audit_chain_certified=False,
                  sequence_mode="pg_transactional_restart_v1")
    intent_path = root / "intent.json"
    write_private(intent_path, intent)
    code, _stderr = run_import(root, args, candidate, source, policy_path, contract_path, intent_path,
                               "import-journal.jsonl", "import-report.json")
    report = json.loads((root / "import-report.json").read_text())
    if code != 0 or report.get("result") != "passed":
        raise GuardFailure("rehearsal_import_failed")
    return report


def run_import(root, args, candidate, source, policy_path, contract_path, intent_path, journal, report_name):
    """Run one import; the guard's own stderr verdict is captured, not swallowed."""
    stderr = io.StringIO()
    argv = ["--snapshot", args.source_snapshot, "--snapshot-sha256", source["sha256"],
            "--target-connection-file", str(root / "candidate-connection.json"),
            "--conversion-policy-file", str(policy_path),
            "--schema-contract-file", str(contract_path), "--schema-contract-sha256", _sha(contract_path),
            "--intent-file", str(intent_path), "--intent-sha256", _sha(intent_path),
            "--confirm-candidate-database", candidate,
            "--journal", str(root / journal), "--report", str(root / report_name)]
    with contextlib.redirect_stderr(stderr):
        code = import_main(argv)
    return code, stderr.getvalue()


def import_refusal_reason(root, stderr_text, report_name):
    path = root / report_name
    if path.is_file():
        reason = json.loads(path.read_text()).get("reason")
        if reason:
            return reason
    for line in reversed((stderr_text or "").strip().splitlines()):
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and value.get("reason"):
            return value["reason"]
    return None


def replay_guard(root, args, candidate):
    """A second import against the populated candidate must be refused, leaving it unchanged."""
    before = table_counts(root)
    source = inspect_snapshot(Path(args.source_snapshot), args.source_sha256, timeout=120)
    code, stderr_text = run_import(root, args, candidate, source, root / "policy.json",
                                   root / "schema-contract.json", root / "intent.json",
                                   "import-journal-replay.jsonl", "import-report-replay.json")
    after = table_counts(root)
    report_path = root / "import-report-replay.json"
    report = json.loads(report_path.read_text()) if report_path.is_file() else {}
    reason = import_refusal_reason(root, stderr_text, "import-report-replay.json")
    unchanged = before == after
    result = dict(result="passed" if code != 0 and reason and unchanged else "failed",
                  first_import_refused=code != 0, counts_unchanged=unchanged, reason=reason,
                  target_changed=report.get("target_changed"),
                  scope="populated-replay refusal;NOT cutover approval")
    write_private(root / "replay-guard.json", result)
    if code == 0:
        raise GuardFailure("rehearsal_replay_was_accepted")
    if not reason:
        raise GuardFailure("rehearsal_replay_refusal_unattributed")
    if not unchanged:
        raise GuardFailure("rehearsal_replay_changed_the_candidate")
    return result


def verify_candidate(root, args):
    code = verify_main(["--snapshot", args.source_snapshot, "--snapshot-sha256", args.source_sha256,
                        "--target-connection-file", str(root / "candidate-connection.json"),
                        "--conversion-policy-file", str(root / "policy.json"),
                        "--schema-contract-file", str(root / "schema-contract.json"),
                        "--schema-contract-sha256", _sha(root / "schema-contract.json"),
                        "--report", str(root / "verify-report.json"), "--timeout", "60"])
    if code != 0:
        raise GuardFailure("rehearsal_verify_failed")
    report = json.loads((root / "verify-report.json").read_text())
    if report.get("result") != "passed":
        raise GuardFailure("rehearsal_verify_failed")
    return report


def concurrency_guard(root, args, candidate_a):
    """Two imports racing on one fresh candidate: at most one may apply, and rows must not double."""
    import concurrent.futures
    third = candidate_a + "_c"
    if not DATABASE.fullmatch(third):
        raise GuardFailure("rehearsal_concurrency_candidate_name_invalid")
    connection_path = create_candidate(root, third, args.schema_init, "candidate-connection-c.json")
    connection = json.loads(connection_path.read_text())
    policy = json.loads((root / "policy.json").read_text())
    source = inspect_snapshot(Path(args.source_snapshot), args.source_sha256, timeout=120)
    intent = root / "intent-c.json"
    write_private(intent, dict(
        version=1, scope="owned_candidate_import_v1", source_sha256=source["sha256"],
        policy_sha256=digest(policy), schema_contract_sha256=_sha(root / "schema-contract.json"),
        target_shape_sha256=policy["target_shape_sha256"], target_database=third,
        target_owner_sha256=hashlib.sha256(connection["owner_token"].encode()).hexdigest(),
        expires_at=int(time.time()) + 3600, candidate_exclusive=True,
        source_is_final_cutover_snapshot=False, historical_audit_chain_certified=False,
        sequence_mode="pg_transactional_restart_v1"))

    def attempt(tag):
        stderr = io.StringIO()
        argv = ["--snapshot", args.source_snapshot, "--snapshot-sha256", source["sha256"],
                "--target-connection-file", str(connection_path),
                "--conversion-policy-file", str(root / "policy.json"),
                "--schema-contract-file", str(root / "schema-contract.json"),
                "--schema-contract-sha256", _sha(root / "schema-contract.json"),
                "--intent-file", str(intent), "--intent-sha256", _sha(intent),
                "--confirm-candidate-database", third,
                "--journal", str(root / ("import-journal-" + tag + ".jsonl")),
                "--report", str(root / ("import-report-" + tag + ".json"))]
        with contextlib.redirect_stderr(stderr):
            code = import_main(argv)
        return tag, code, stderr.getvalue()

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = [future.result() for future in [pool.submit(attempt, tag) for tag in ("c1", "c2")]]
    successes = [tag for tag, code, _ in outcomes if code == 0]
    reasons = {tag: import_refusal_reason(root, text, "import-report-" + tag + ".json") for tag, code, text in outcomes if code != 0}
    counts_third = table_counts(root, connection_path)
    counts_first = table_counts(root)
    result = dict(result="passed" if len(successes) <= 1 and counts_third == counts_first else "failed",
                  applied=successes, refusals=reasons, rows_match_single_import=counts_third == counts_first,
                  rows=sum(counts_third.values()),
                  scope="concurrent-import admission on one owned candidate;NOT cutover approval")
    write_private(root / "concurrency-guard.json", result)
    if len(successes) > 1:
        raise GuardFailure("rehearsal_concurrent_imports_both_applied")
    if counts_third != counts_first:
        raise GuardFailure("rehearsal_concurrent_import_rows_differ")
    return result


def determinism_check(root, args, candidate):
    """A second independent import of the same snapshot must produce identical content digests."""
    second = candidate + "_b"
    if not DATABASE.fullmatch(second):
        raise GuardFailure("rehearsal_determinism_candidate_name_invalid")
    connection_path = create_candidate(root, second, args.schema_init, "candidate-connection-b.json")
    import_policy, import_contract = root / "policy.json", root / "schema-contract.json"
    source = inspect_snapshot(Path(args.source_snapshot), args.source_sha256, timeout=120)
    # A fresh intent is required: the first one is bound to candidate A's database and owner token.
    connection = json.loads(connection_path.read_text())
    policy = json.loads(import_policy.read_text())
    import_intent = root / "intent-b.json"
    write_private(import_intent, dict(
        version=1, scope="owned_candidate_import_v1", source_sha256=source["sha256"],
        policy_sha256=digest(policy), schema_contract_sha256=_sha(import_contract),
        target_shape_sha256=policy["target_shape_sha256"], target_database=second,
        target_owner_sha256=hashlib.sha256(connection["owner_token"].encode()).hexdigest(),
        expires_at=int(time.time()) + 3600, candidate_exclusive=True,
        source_is_final_cutover_snapshot=False, historical_audit_chain_certified=False,
        sequence_mode="pg_transactional_restart_v1"))
    stderr = io.StringIO()
    argv = ["--snapshot", args.source_snapshot, "--snapshot-sha256", source["sha256"],
            "--target-connection-file", str(connection_path),
            "--conversion-policy-file", str(import_policy),
            "--schema-contract-file", str(import_contract), "--schema-contract-sha256", _sha(import_contract),
            "--intent-file", str(import_intent), "--intent-sha256", _sha(import_intent),
            "--confirm-candidate-database", second,
            "--journal", str(root / "import-journal-b.jsonl"), "--report", str(root / "import-report-b.json")]
    with contextlib.redirect_stderr(stderr):
        code = import_main(argv)
    report_b = json.loads((root / "import-report-b.json").read_text()) if (root / "import-report-b.json").is_file() else {}
    if code != 0 or report_b.get("result") != "passed":
        raise GuardFailure("rehearsal_determinism_second_import_failed")
    report_a = json.loads((root / "import-report.json").read_text())
    left = {t["table"]: t.get("projected_content_sha256") for t in report_a["target_projection"]["tables"]}
    right = {t["table"]: t.get("projected_content_sha256") for t in report_b["target_projection"]["tables"]}
    differing = sorted(name for name in set(left) | set(right) if left.get(name) != right.get(name))
    result = dict(result="passed" if not differing else "failed", tables=len(left),
                  differing_tables=differing, second_candidate=second,
                  scope="cross-candidate determinism of the migrated projection;NOT cutover approval")
    write_private(root / "determinism.json", result)
    if differing:
        raise GuardFailure("rehearsal_determinism_projection_differs")
    return result


def native_history_tables(report):
    tables = {}
    for entry in report.get("native_history_after", {}).get("tables", []):
        name = entry.get("table", "")
        if name.startswith("schema_migrations"):
            tables[name] = entry.get("rows")
    return tables


def native_history_drift(root):
    """Runtime store migrations must not silently add native migration history rows."""
    report = json.loads((root / "import-report.json").read_text())
    recorded = native_history_tables(report)
    if not recorded:
        raise GuardFailure("rehearsal_native_history_missing_from_import_report")
    current = {name: scalar_int(psql_scalar(root, "SELECT count(*) FROM " + name + ";")) for name in sorted(recorded)}
    added = {name: current[name] - recorded[name] for name in recorded if current[name] != recorded[name]}
    result = dict(result="passed" if not added else "failed", recorded_rows=recorded, current_rows=current,
                  drift=added, scope="native migration history drift check;NOT cutover approval")
    write_private(root / "native-history-drift.json", result)
    if added:
        raise GuardFailure("rehearsal_native_history_drifted")
    return result


def psql_scalar(root, sql):
    connection = json.loads((root / "candidate-connection.json").read_text())
    argv, env = psql(connection)
    result = run_bounded(argv, 30, env=env, stdin=sql.encode())
    if result.returncode:
        raise GuardFailure("rehearsal_write_check_sql_failed")
    return result.stdout.decode().strip()


def scalar_int(text):
    for line in (text or "").splitlines():
        line = line.strip()
        if line:
            return int(line)
    raise GuardFailure("rehearsal_scalar_missing")


def write_check(root):
    """Insert one audit row and require the migrated sequence to advance past the historical floor.

    This mutates the disposable candidate on purpose; the report says so instead of
    pretending the rehearsal stayed read-only.
    """
    before = scalar_int(psql_scalar(root, "SELECT count(*) FROM audit_events;"))
    floor = scalar_int(psql_scalar(root, "SELECT coalesce(max(seq),0) FROM audit_events;"))
    # A CTE keeps the command tag off the stream: a bare INSERT ... RETURNING also emits
    # "INSERT 0 1", which made the scalar parse fail.
    seq = scalar_int(psql_scalar(
        root,
        "WITH ins AS (INSERT INTO audit_events (id,type,outcome,ts_unix_ns,tenant_id,server_version) "
        "VALUES ('rehearsal-write-check','rehearsal.write_check','success',"
        + str(time.time_ns()) + ",'','rehearsal') RETURNING seq) SELECT seq FROM ins;",
    ))
    after = scalar_int(psql_scalar(root, "SELECT count(*) FROM audit_events;"))
    advanced = seq > floor
    result = dict(result="passed" if advanced and after == before + 1 else "failed",
                  rows_before=before, rows_after=after, historical_max_seq=floor, inserted_seq=seq,
                  sequence_advanced=advanced, candidate_mutated=True,
                  mutation="one audit_events row written through the migrated sequence",
                  scope="write-path proof on a disposable candidate;NOT cutover approval")
    write_private(root / "write-check.json", result)
    if not advanced:
        raise GuardFailure("rehearsal_write_check_sequence_not_advanced")
    if after != before + 1:
        raise GuardFailure("rehearsal_write_check_row_count_mismatch")
    return result


def table_counts(root, connection_path=None):
    connection = json.loads(((connection_path or (root / "candidate-connection.json"))).read_text())
    argv, env = psql(connection)
    out = {}
    for name in business_tables():
        argv, env = psql(connection)
        result = run_bounded(argv, 30, env=env, stdin=("SELECT count(*) FROM " + name + ";").encode())
        if result.returncode:
            raise GuardFailure("rehearsal_replay_count_failed")
        out[name] = int(result.stdout.decode().strip() or 0)
    return out


def business_tables():
    # The closed set the migration guard itself treats as business content.
    from .target_content import verify_content  # noqa: F401 - kept for import parity
    return ["account_lockouts", "audit_checkpoints", "audit_events", "auth_codes", "clients",
            "password_credentials", "permissions_active_roles", "permissions_assignments",
            "permissions_conflict_sets", "permissions_menus", "permissions_resources",
            "permissions_roles", "refresh_rotation_windows", "refresh_token_families",
            "refresh_tokens", "revocations", "sessions", "users"]


def readpath_args(dsn_path, expect_path, report_path):
    # The store constructors migrate the candidate, so the acknowledgement flag is mandatory
    # and the report path is always explicit.
    return ["-dsn-file", str(dsn_path), "-expect", str(expect_path), "-allow-idempotent-migrations"]


def readpath_candidate(root, binary, expect_path):
    if not expect_path:
        raise GuardFailure("rehearsal_readpath_expectations_required")
    dsn_path = root / "probe.dsn"
    connection = json.loads((root / "candidate-connection.json").read_text())
    dsn = "postgres://%s:%s@%s:%d/%s?sslmode=disable&connect_timeout=5" % (
        connection["user"], connection["password"], connection["host"], connection["port"], connection["database"])
    dsn_path.write_text(dsn + "\n")
    os.chmod(dsn_path, 0o600)
    argv = [binary] + readpath_args(dsn_path, expect_path, root / "readpath-report.json")
    result = run_bounded(argv, 180, cwd=str(root))
    body = result.stdout.decode() if result.stdout else ""
    report = {}
    if body.strip():
        try:
            report = json.loads(body)
        except ValueError:
            raise GuardFailure("rehearsal_readpath_report_invalid")
    write_private(root / "readpath-report.json", report)
    dsn_path.unlink()
    if result.returncode or report.get("result") != "passed" or report.get("existing_rows_unchanged") is not True:
        raise GuardFailure("rehearsal_readpath_failed")
    return report


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def server_config(root, http_port, grpc_port):
    connection = json.loads((root / "candidate-connection.json").read_text())
    dsn = "postgres://%s:%s@%s:%d/%s?sslmode=disable&connect_timeout=5" % (
        connection["user"], connection["password"], connection["host"], connection["port"], connection["database"])
    issuer = "http://127.0.0.1:%d" % http_port
    return (
        "version: 1\n"
        "server:\n"
        "  issuer: %s\n"
        "  base_url: %s\n"
        '  listen: "127.0.0.1:%d"\n'
        "  topology:\n"
        "    mode: single\n"
        "    allow_per_pod_state: false\n"
        "identity:\n"
        "  backend: postgres\n"
        "  session_backend: postgres\n"
        "oauth:\n"
        "  backend: postgres\n"
        'postgres:\n'
        '  dsn: "%s"\n'
        "bootstrap:\n"
        "  disabled: true\n"
    ) % (issuer, issuer, http_port, dsn)


def http_probe(port, path, timeout=5):
    import urllib.error
    import urllib.request
    try:
        with urllib.request.urlopen("http://127.0.0.1:%d%s" % (port, path), timeout=timeout) as response:
            return response.status, response.read(65536)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(65536) or b""
    except urllib.error.URLError:
        return 0, b""


def smoke_candidate(root, server_binary, attempts=3):
    """Boot the real server against the imported candidate and probe public endpoints.

    Ports are chosen by binding and releasing, so another process can take one
    between the choice and the bind. A rejected preflight is retried with fresh
    ports a bounded number of times; every attempt is recorded.
    """
    history = []
    for attempt in range(1, attempts + 1):
        try:
            facts = smoke_attempt(root, server_binary)
        except GuardFailure as failure:
            history.append(dict(attempt=attempt, result="failed", reason=str(failure)))
            if str(failure) != "rehearsal_smoke_config_invalid" or attempt == attempts:
                write_private(root / "smoke-attempts.json", dict(attempts=history))
                raise
            continue
        history.append(dict(attempt=attempt, result="passed"))
        write_private(root / "smoke-attempts.json", dict(attempts=history))
        return facts
    raise GuardFailure("rehearsal_smoke_attempts_exhausted")


def smoke_env():
    """Scrubbed environment: the rehearsal's own variables must never become server config.

    The server maps SSO_* environment variables into its config tree, so passing
    the parent environment through turns e.g. SSO_SERVER=/path/to/binary into
    `server: /path/to/binary` and the config fails to parse.
    """
    return {key: os.environ[key] for key in ("PATH", "HOME", "LANG", "LC_ALL") if key in os.environ}


def smoke_attempt(root, server_binary):
    http_port, grpc_port = free_port(), free_port()
    env = smoke_env()
    config_path = root / "server-config.yaml"
    config_path.write_text(server_config(root, http_port, grpc_port))
    os.chmod(config_path, 0o600)
    validate = run_bounded([server_binary, "-config", str(config_path), "-validate-only",
                            "-grpc-listen", "127.0.0.1:%d" % grpc_port], 120, cwd=str(root), env=env)
    if validate.returncode:
        detail = (getattr(validate, "stderr", b"") or b"").decode(errors="replace")[-400:] + \
            (getattr(validate, "stdout", b"") or b"").decode(errors="replace")[-400:]
        write_private(root / "smoke-validate-failure.json",
                      dict(result="failed", exit_code=validate.returncode, detail=detail,
                           argv=[server_binary, "-config", "<private>", "-validate-only",
                                 "-grpc-listen", "127.0.0.1:%d" % grpc_port]))
        raise GuardFailure("rehearsal_smoke_config_invalid")
    log = (root / "server.log").open("wb")
    child = subprocess.Popen([server_binary, "-config", str(config_path),
                              "-grpc-listen", "127.0.0.1:%d" % grpc_port],
                             stdout=log, stderr=subprocess.STDOUT, cwd=str(root),
                             env=dict(env, PYTHONDONTWRITEBYTECODE="1"), start_new_session=True)
    facts = dict(http_port=http_port, grpc_port=grpc_port)
    try:
        deadline = time.monotonic() + 60
        status = 0
        while time.monotonic() < deadline and child.poll() is None:
            status, body = http_probe(http_port, "/health")
            if status == 200:
                facts["health_sha256"] = hashlib.sha256(body).hexdigest()
                break
            time.sleep(0.5)
        if status != 200:
            raise GuardFailure("rehearsal_smoke_health_never_ready")
        disc_status, disc_body = http_probe(http_port, "/.well-known/openid-configuration")
        jwks_status, jwks_body = http_probe(http_port, "/.well-known/jwks.json")
        facts.update(discovery_status=disc_status, discovery_sha256=hashlib.sha256(disc_body).hexdigest(),
                     jwks_status=jwks_status, jwks_sha256=hashlib.sha256(jwks_body).hexdigest())
        if disc_status != 200 or jwks_status != 200:
            raise GuardFailure("rehearsal_smoke_public_surface_incomplete")
    finally:
        if child.poll() is None:
            child.send_signal(subprocess.signal.SIGTERM)
        try:
            facts["server_exit"] = child.wait(timeout=30)
        except subprocess.TimeoutExpired:
            child.kill()
            facts["server_exit"] = child.wait(timeout=10)
        log.close()
    closed = http_probe(http_port, "/health")[0] == 0
    facts["port_closed_after_stop"] = closed
    write_private(root / "smoke-facts.json", facts)
    if facts["server_exit"] != 0 or not closed:
        raise GuardFailure("rehearsal_smoke_stop_unclean")
    return facts










def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def create_candidate(root, name, schema_init, connection_name="candidate-connection.json"):
    """Create one owned candidate database with its ownership row and canonical schema."""
    connection = dict(json.loads((root / "test-connection.json").read_text()))
    argv, env = psql(connection)
    execute_sql(argv, env, "CREATE DATABASE " + name + ";")
    token = os.urandom(24).hex()
    owned = dict(connection, database=name, owner_token=token)
    execute_sql(*psql(owned),
                "CREATE SCHEMA migration_guard;"
                "CREATE TABLE migration_guard.ownership(token TEXT PRIMARY KEY);"
                "INSERT INTO migration_guard.ownership VALUES('" + token + "');")
    path = root / connection_name
    write_private(path, owned)
    child = run_bounded([schema_init, str(path)], 300)
    if child.returncode:
        raise GuardFailure("rehearsal_schema_init_failed")
    return path


def initialise_candidate(root, database, schema_init):
    """Create the owned candidate database, its ownership row and the canonical schema."""
    receipt = json.loads((root / "fixture-receipt.json").read_text())
    connection = dict(json.loads((root / "test-connection.json").read_text()))
    if connection.get("database") != database:
        raise GuardFailure("rehearsal_root_connection_mismatch")
    candidate = candidate_name(database)
    create_candidate(root, candidate, schema_init)
    return receipt, candidate


def candidate_name(database):
    if not database.startswith("snaplink_mig_"):
        raise GuardFailure("rehearsal_dedicated_candidate_database_required")
    suffix = database.split("snaplink_mig_", 1)[1][:20]
    candidate = "snaplink_mig_" + suffix + "_cand"
    if not DATABASE.fullmatch(candidate):
        raise GuardFailure("rehearsal_candidate_name_invalid")
    return candidate


def psql(connection):
    return _psql(connection)


def execute_sql(argv, env, statement):
    return _sql(argv, env, statement)


def _psql(connection):
    argv = ["psql", "-h", connection["host"], "-p", str(connection["port"]), "-U", connection["user"],
            "-d", connection["database"], "-XAt", "-v", "ON_ERROR_STOP=1"]
    env = dict(PGPASSWORD=connection["password"])
    return argv, env


def _sql(argv, env, statement):
    result = run_bounded(argv, 30, env=env, stdin=statement.encode())
    if result.returncode:
        raise GuardFailure("rehearsal_sql_failed")


def parser():
    top = argparse.ArgumentParser(description=__doc__)
    subs = top.add_subparsers(dest="action", required=True)
    one = subs.add_parser("provision")
    one.add_argument("--root", required=True)
    one.add_argument("--container", required=True)
    one.add_argument("--label", required=True)
    one.add_argument("--database", required=True)
    one.add_argument("--user", default="migration_test")
    two = subs.add_parser("close")
    two.add_argument("--root", required=True)
    three = subs.add_parser("run")
    three.add_argument("--root", required=True)
    three.add_argument("--container", required=True)
    three.add_argument("--label", required=True)
    three.add_argument("--database", required=True)
    three.add_argument("--schema-init", required=True, help="prebuilt schema initializer for this revision")
    three.add_argument("--user", default="migration_test")
    three.add_argument("--evidence", required=True)
    three.add_argument("--source-snapshot")
    three.add_argument("--source-sha256")
    three.add_argument("--policy-template")
    three.add_argument("--base-commit", help="40-hex commit the reviewed schema was built from")
    three.add_argument("--sso-server", help="prebuilt sso-server binary to smoke against the candidate")
    three.add_argument("--concurrency-guard", action="store_true",
                       help="run two imports against one fresh candidate and require at most one to apply")
    three.add_argument("--determinism", action="store_true",
                       help="import the same snapshot into a second owned candidate and require identical projections")
    three.add_argument("--drift-check", action="store_true",
                       help="compare native migration history with what the import recorded")
    three.add_argument("--write-check", action="store_true",
                       help="after import, prove the migrated audit sequence accepts a new row above the historical floor")
    three.add_argument("--replay-guard", action="store_true",
                       help="after a successful import, prove a second import is refused and the candidate is unchanged")
    three.add_argument("--readpath", help="prebuilt migration-readpath binary")
    three.add_argument("--readpath-expect", help="expectation JSON for the read-path samples")
    return top


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.action == "provision":
            print(json.dumps(provision(args.root, args.container, args.label, args.database, args.user)))
            return 0
        root = private_dir(args.root)
        if args.action == "run":
            return run_command(args, root)
        receipt = json.loads((root / "fixture-receipt.json").read_text())
        inspected = run_bounded(["docker", "inspect", receipt["container_id"]], 20)
        if inspected.returncode:
            raise GuardFailure("rehearsal_inspect_failed")
        body = json.loads(inspected.stdout.decode())[0]
        close_receipt(root, inspect_body=body, remove=remove_container)
        print(json.dumps(dict(result="closed")))
        return 0
    except (GuardFailure, OSError, ValueError) as exc:
        reason = str(exc) if isinstance(exc, GuardFailure) else "rehearsal_failure_diagnostics_withheld"
        print(json.dumps(dict(result="failed", reason=reason, automatic_retry=False)), file=sys.stderr)
        return 1
