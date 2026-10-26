"""Owned, explicit, bounded rehearsal driver: provision, initialize, import, verify, close.

Every step is fail-closed and refuses to act on anything it cannot prove it owns:
a container is only removed when the receipt, the live inspect body, the image
digest, the loopback binding and the tmpfs-only layout all still match.
"""
import argparse
import json
import os
import re
import secrets
import socket
import stat
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
    template = json.loads(Path(args.policy_template).read_text())
    if template.get("version") != 2 or not isinstance(template.get("mappings"), list):
        raise GuardFailure("rehearsal_policy_template_invalid")
    policy = dict(template, source_sha256=source["sha256"], target_shape_sha256=target_shape_sha256(target))
    observed = inspect_native_schema(root / "candidate-connection.json", source, target, policy)
    contract = dict(version=1, algorithm="pg_native_schema_facets_v1", source_sha256=source["sha256"],
                    target_shape_sha256=target_shape_sha256(target),
                    schema_source=dict(base_commit="rehearsal", combination_sha256=digest(policy)),
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
    code = import_main(["--snapshot", args.source_snapshot, "--snapshot-sha256", source["sha256"],
                        "--target-connection-file", str(root / "candidate-connection.json"),
                        "--conversion-policy-file", str(policy_path),
                        "--schema-contract-file", str(contract_path), "--schema-contract-sha256", _sha(contract_path),
                        "--intent-file", str(intent_path), "--intent-sha256", _sha(intent_path),
                        "--confirm-candidate-database", candidate,
                        "--journal", str(root / "import-journal.jsonl"), "--report", str(root / "import-report.json")])
    report = json.loads((root / "import-report.json").read_text())
    if code != 0 or report.get("result") != "passed":
        raise GuardFailure("rehearsal_import_failed")
    return report


def verify_candidate(root, args):
    code = verify_main(["--snapshot", args.source_snapshot, "--snapshot-sha256", args.source_sha256,
                        "--target-connection-file", str(root / "candidate-connection.json"),
                        "--conversion-policy-file", str(root / "policy.json"),
                        "--report", str(root / "verify-report.json"), "--timeout", "60"])
    if code != 0:
        raise GuardFailure("rehearsal_verify_failed")
    report = json.loads((root / "verify-report.json").read_text())
    if report.get("result") != "passed":
        raise GuardFailure("rehearsal_verify_failed")
    return report


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def initialise_candidate(root, database, schema_init):
    """Create the owned candidate database, its ownership row and the canonical schema."""
    receipt = json.loads((root / "fixture-receipt.json").read_text())
    connection = dict(json.loads((root / "test-connection.json").read_text()))
    if connection.get("database") != database:
        raise GuardFailure("rehearsal_root_connection_mismatch")
    candidate = candidate_name(database)
    argv, env = psql(connection)
    execute_sql(argv, env, "CREATE DATABASE " + candidate + ";")
    token = os.urandom(24).hex()
    owned = dict(connection, database=candidate, owner_token=token)
    owned_argv, owned_env = psql(owned)
    execute_sql(owned_argv, owned_env,
                "CREATE SCHEMA migration_guard;"
                "CREATE TABLE migration_guard.ownership(token TEXT PRIMARY KEY);"
                "INSERT INTO migration_guard.ownership VALUES('" + token + "');")
    path = root / "candidate-connection.json"
    write_private(path, owned)
    child = run_bounded([schema_init, str(path)], 300)
    if child.returncode:
        raise GuardFailure("rehearsal_schema_init_failed")
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
