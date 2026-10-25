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

from .snapshot import GuardFailure

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
    mounts = body.get("Mounts") or []
    if not mounts or any(m.get("Type") != "tmpfs" for m in mounts):
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
    return top


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.action == "provision":
            print(json.dumps(provision(args.root, args.container, args.label, args.database, args.user)))
            return 0
        root = private_dir(args.root)
        receipt = json.loads((root / "fixture-receipt.json").read_text())
        inspected = run_bounded(["docker", "inspect", receipt["container_id"]], 20)
        if inspected.returncode:
            raise GuardFailure("rehearsal_inspect_failed")
        body = json.loads(inspected.stdout.decode())[0]

        def remove(cid):
            done = run_bounded(["docker", "rm", "-f", cid], 60)
            if done.returncode:
                raise GuardFailure("rehearsal_removal_failed")

        close_receipt(root, inspect_body=body, remove=remove)
        print(json.dumps(dict(result="closed")))
        return 0
    except (GuardFailure, OSError, ValueError) as exc:
        reason = str(exc) if isinstance(exc, GuardFailure) else "rehearsal_failure_diagnostics_withheld"
        print(json.dumps(dict(result="failed", reason=reason, automatic_retry=False)), file=sys.stderr)
        return 1
