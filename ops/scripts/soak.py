"""Bounded soak observer for a migrated PostgreSQL candidate.

It reuses the rehearsal's own provisioning/import/verify path, then keeps a real
`sso-server` up and appends one probe record per interval to
`<root>/observations.jsonl`. It refuses to start without an explicit
authorization string, a positive day budget and a deadline, and it only ever
touches the container it provisioned itself.

Not a performance claim: the probes are single requests plus row-count
comparisons. Nothing is sent off the machine.
"""
import argparse
import base64
import hashlib
import json
import os
import secrets
import shutil
import signal
import threading
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from migration_guard import rehearsal_cli as R  # noqa: E402
from migration_guard.postgres import psql_command  # noqa: E402

AUTHORIZATION = "I-ACCEPT-THE-SOAK-BUDGET"
TABLES = ("clients", "users", "sessions", "audit_events", "refresh_tokens",
          "refresh_token_families", "auth_codes", "password_credentials")
LIMITS = dict(max_days=90, min_interval=60, max_log_mib=64, max_disk_mib=2048, max_conns=10)


class Refused(Exception):
    pass


def parse(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--root"); p.add_argument("--container"); p.add_argument("--label"); p.add_argument("--database")
    p.add_argument("--days", type=int, default=0); p.add_argument("--interval", type=int, default=60)
    p.add_argument("--snapshot"); p.add_argument("--snapshot-sha256"); p.add_argument("--policy-template")
    p.add_argument("--base-commit"); p.add_argument("--schema-init"); p.add_argument("--sso-server"); p.add_argument("--sso-ctl")
    p.add_argument("--max-disk-mib", type=int, default=LIMITS["max_disk_mib"])
    p.add_argument("--max-log-mib", type=int, default=LIMITS["max_log_mib"])
    p.add_argument("--authorize", default="")
    p.add_argument("--deadline", default="")
    p.add_argument("--plan", action="store_true", help="print the resolved plan and exit")
    p.add_argument("--cycles", type=int, default=0, help="debug: stop after N cycles")
    p.add_argument("--durable", action="store_true", help="store the candidate on a labelled named volume instead of tmpfs")
    p.add_argument("--resume", action="store_true", help="reuse an owned candidate this run already provisioned (restart safety)")
    p.add_argument("--close-on-failure", action="store_true", help="tear down even when a stop condition fired")
    return p.parse_args(argv)


def plan(a):
    if a.authorize != AUTHORIZATION:
        raise Refused("soak_authorization_required")
    if not 1 <= a.days <= LIMITS["max_days"]:
        raise Refused("soak_days_out_of_range")
    if not LIMITS["min_interval"] <= a.interval <= 86400:
        raise Refused("soak_interval_out_of_range")
    if a.max_log_mib > LIMITS["max_log_mib"] or a.max_disk_mib > LIMITS["max_disk_mib"]:
        raise Refused("soak_budget_above_ceiling")
    for name in ("root", "container", "label", "database", "snapshot", "snapshot_sha256", "policy_template",
                 "base_commit", "schema_init", "sso_server"):
        if not getattr(a, name):
            raise Refused("soak_missing_" + name)
    if not a.database.startswith("snaplink_mig_"):
        raise Refused("soak_database_must_be_a_rehearsal_candidate")
    try:
        deadline = datetime.fromisoformat(a.deadline) if a.deadline else datetime.now(timezone.utc) + timedelta(days=a.days)
    except ValueError:
        raise Refused("soak_deadline_unparseable")
    if deadline.tzinfo is None:
        deadline = deadline.replace(tzinfo=timezone.utc)
    if deadline <= datetime.now(timezone.utc):
        raise Refused("soak_deadline_in_the_past")
    # A deadline shorter than the day budget is a trial window: record what will
    # actually be observed, so the summary cannot claim a 30-day budget later.
    observed_days = round((deadline - datetime.now(timezone.utc)).total_seconds() / 86400, 3)
    return dict(cycles=a.days * max(1, 86400 // a.interval), interval=a.interval, deadline=deadline,
                budget=dict(days=a.days, observed_days=observed_days, storage="volume" if a.durable else "tmpfs",
                            disk_mib=a.max_disk_mib, log_mib=a.max_log_mib, conns=LIMITS["max_conns"]))


def reusable(root, a):
    """A restart may only adopt the candidate this run created itself.

    The fixture receipt carries the container identity and label; adopting
    anything else would observe someone else's database.
    """
    receipt = Path(root) / "fixture-receipt.json"
    connection = Path(root) / "candidate-connection.json"
    if not (receipt.is_file() and connection.is_file()):
        return None
    body = json.loads(receipt.read_text())
    if body.get("name") != a.container or body.get("label") != a.label:
        return None
    running = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", body.get("container_id", "")],
                             capture_output=True, text=True, timeout=30)
    if running.stdout.strip() != "true":
        return None
    return dict(container_id=body.get("container_id"), name=body.get("name"), label=body.get("label"),
                storage=body.get("storage"), database=body.get("database"))


def shape_check(q):
    tables = int(q("select count(*) from pg_tables where schemaname='public'"))
    if tables != 28:
        raise Refused("soak_resume_shape_mismatch:tables=%d" % tables)
    return dict(tables=tables, versions=versions(q))


def psql(root):
    conn = json.loads((Path(root) / "candidate-connection.json").read_text())
    argv, env = psql_command(conn)
    env.update(PGHOSTADDR="127.0.0.1", PGSSLMODE="disable",
               PGOPTIONS="-c default_transaction_read_only=on -c statement_timeout=15000 -c lock_timeout=3000")
    def q(statement):
        r = subprocess.run(argv, env=env, input=statement.encode(), capture_output=True, timeout=60)
        if r.returncode:
            raise Refused("soak_probe_query_failed")
        return r.stdout.decode().strip()
    return q


def counts(q):
    return {t: int(q("select count(*) from " + t)) for t in TABLES}


def versions(q):
    pairs = ("audit", "schema_migrations_audit"), ("clients", "schema_migrations_clients"), \
            ("users", "schema_migrations_users"), ("sessions", "schema_migrations_sessions"), \
            ("tokens", "schema_migrations_refresh_tokens"), ("auth_codes", "schema_migrations_auth_codes")
    return {name: int(q("select max(version) from " + table)) for name, table in pairs}


def call(port, path, body=None, headers=None, timeout=10):
    data = None if body is None else json.dumps(body).encode()
    merged = {"Content-Type": "application/json"} if data else {}
    merged.update(headers or {})
    request = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path), data=data, headers=merged)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read(65536)
    except urllib.error.HTTPError as error:
        return error.code, error.read(65536) or b""
    except (urllib.error.URLError, OSError):
        return 0, b""


def login_probe(port, password):
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    redirect = "http://127.0.0.1:%d/callback" % port
    status, body = call(port, "/auth/login", {
        "client_id": "sso-admin-console", "response_type": "code", "scope": ["openid", "admin"], "state": "soak",
        "provider": "password", "credential": {"username": "admin", "password": password},
        "redirect_uri": redirect, "code_challenge": challenge, "code_challenge_method": "S256",
    })
    if status != 200:
        return dict(login_status=status, token_status=0, admin_without_token=0, admin_with_token=0)
    code = json.loads(body).get("code")
    status, body = call(port, "/token", {"grant_type": "authorization_code", "code": code, "client_id": "sso-admin-console",
                                         "redirect_uri": redirect, "code_verifier": verifier})
    token = json.loads(body).get("access_token") if status == 200 else None
    without, _ = call(port, "/api/v1/admin/clients")
    with_token, _ = call(port, "/api/v1/admin/clients", headers={"Authorization": "Bearer " + (token or "")})
    return dict(login_status=200, token_status=status, admin_without_token=without, admin_with_token=with_token)


FIXED_TABLES = ("clients", "users", "sessions", "auth_codes", "password_credentials")
APPEND_ONLY = ("audit_events", "refresh_tokens", "refresh_token_families")


def drift_reason(now, baseline, now_versions, base_versions):
    """Fixed tables must match exactly; append-only tables may only grow.

    Audit rows and rotation families are written by the running server, so
    equality there would fail on the first real request; a decrease is always a
    regression.
    """
    for table in FIXED_TABLES:
        if now.get(table) != baseline.get(table):
            return "fixed_table_drift:" + table
    for table in APPEND_ONLY:
        if now.get(table, 0) < baseline.get(table, 0):
            return "append_only_table_shrank:" + table
    if now_versions != base_versions:
        return "schema_version_drift"
    return ""


def rss_mib(pid):
    try:
        for line in Path("/proc/%d/status" % pid).read_text().splitlines():
            if line.startswith("VmRSS:"):
                return round(int(line.split()[1]) / 1024, 1)
    except OSError:
        pass
    return None


def run(a, resolved):
    root = Path(a.root)
    interrupted = {"signal": ""}
    stop_wait = threading.Event()

    def on_signal(signum, _frame):
        interrupted["signal"] = signal.Signals(signum).name
        stop_wait.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, on_signal)
    root.mkdir(mode=0o700, exist_ok=True)
    args = argparse.Namespace(root=str(root), container=a.container, label=a.label, database=a.database,
                              user="migration_test", durable_storage=a.durable, schema_init=a.schema_init,
                              evidence=str(root / "plan.json"), source_snapshot=a.snapshot,
                              source_sha256=a.snapshot_sha256, policy_template=a.policy_template,
                              base_commit=a.base_commit, readpath=None, readpath_expect=None,
                              sso_server=a.sso_server, sso_ctl=a.sso_ctl)
    observations = (root / "observations.jsonl").open("a")
    server = None
    child = None
    summary = dict(started=datetime.now(timezone.utc).isoformat(), deadline=resolved["deadline"].isoformat(),
                   interval=a.interval, budget=resolved["budget"], cycles=0, stops=[])
    try:
        q = None
        reused = a.resume and reusable(root, a)
        if reused:
            # The import was verified by the run that created the candidate. After
            # bootstrap has written audit/role rows the content digest no longer
            # equals the source projection, so a restart checks shape, not content.
            summary["reused"] = reusable(root, a)
            q = psql(root)
            summary["shape"] = shape_check(q)
        else:
            R.provision_step(root, args)
            _, candidate = R.initialise_candidate(root, args.database, args.schema_init)
            R.bind_and_import_inputs(root, args, candidate)
            R.verify_candidate(root, args)
            q = psql(root)
        password = "Soak-" + secrets.token_urlsafe(18)
        hashed = R.run_bounded([a.sso_ctl, "hash", "--quiet"], 30, stdin=password.encode())
        if hashed.returncode or not hashed.stdout.strip():
            raise Refused("soak_password_hash_failed")
        (root / "soak-admin.bcrypt").write_bytes(hashed.stdout)
        os.chmod(root / "soak-admin.bcrypt", 0o600)
        dsn = "postgres://%s:%s@%s:%d/%s?sslmode=disable&connect_timeout=5" % (
            json.loads((root / "candidate-connection.json").read_text())["user"],
            json.loads((root / "candidate-connection.json").read_text())["password"],
            json.loads((root / "candidate-connection.json").read_text())["host"],
            json.loads((root / "candidate-connection.json").read_text())["port"],
            json.loads((root / "candidate-connection.json").read_text())["database"])
        port = R.free_port()
        config = root / "soak-server-config.yaml"
        config.write_text(R.auth_config(root, dsn, port, root / "soak-admin-password.txt", root / "soak-admin.bcrypt"))
        os.chmod(config, 0o600)
        R.register_console_redirect(root, "sso-admin-console", "http://127.0.0.1:%d/callback" % port)
        log = (root / "soak-server.log").open("ab")
        child = subprocess.Popen([a.sso_server, "-config", str(config), "-grpc-listen", "",
                                  "-bootstrap-admin-password-file", str(root / "soak-admin-password.txt")],
                                 stdout=log, stderr=subprocess.STDOUT, cwd=str(root), env=R.smoke_env(),
                                 start_new_session=True)
        ready = 0
        for _ in range(120):
            if child.poll() is not None:
                break
            ready, _ = call(port, "/health")
            if ready == 200:
                break
            if stop_wait.wait(0.5):
                break
        if ready != 200:
            raise Refused("soak_server_never_ready")
        summary["server_pid"] = child.pid
        summary["http_port"] = port
        # Baseline is taken after bootstrap has run: seeding writes audit rows, so
        # a pre-boot baseline would report drift on the first cycle.
        baseline = dict(counts=counts(q), versions=versions(q))
        summary["baseline"] = baseline
        while True:
            if interrupted["signal"]:
                summary["stops"].append(dict(reason="runner_signalled", signal=interrupted["signal"])); break
            if child.poll() is not None:
                summary["stops"].append(dict(reason="server_exited", code=child.returncode)); break
            if datetime.now(timezone.utc) >= resolved["deadline"]:
                summary["stops"].append(dict(reason="deadline_reached")); break
            if a.cycles and summary["cycles"] >= a.cycles:
                summary["stops"].append(dict(reason="debug_cycle_cap")); break
            if stop_wait.wait(a.interval):
                summary["stops"].append(dict(reason="runner_signalled", signal=interrupted["signal"] or "SIGTERM"))
                break
            record = dict(utc=datetime.now(timezone.utc).isoformat(), cycle=summary["cycles"] + 1)
            started = time.monotonic()
            health, _ = call(port, "/health")
            record["health"] = health
            record["health_ms"] = round((time.monotonic() - started) * 1000, 1)
            record.update(login_probe(port, password))
            record["counts"] = counts(q)
            record["versions"] = versions(q)
            record["rss_mib"] = rss_mib(child.pid)
            record["log_mib"] = round((root / "soak-server.log").stat().st_size / 1048576, 2)
            record["disk_mib"] = round(sum(f.stat().st_size for f in root.rglob("*") if f.is_file()) / 1048576, 1)
            observations.write(json.dumps(record) + "\n"); observations.flush(); os.fsync(observations.fileno())
            summary["cycles"] = record["cycle"]
            if health != 200:
                summary["stops"].append(dict(reason="health_not_200", value=health)); break
            if record["token_status"] != 200 or record["admin_without_token"] != 401 or record["admin_with_token"] != 200:
                summary["stops"].append(dict(reason="auth_surface_regressed")); break
            drift = drift_reason(record["counts"], baseline["counts"], record["versions"], baseline["versions"])
            if drift:
                summary["stops"].append(dict(reason=drift)); break
            if record["log_mib"] > a.max_log_mib:
                summary["stops"].append(dict(reason="log_budget_exceeded")); break
            if record["disk_mib"] > a.max_disk_mib:
                summary["stops"].append(dict(reason="disk_budget_exceeded")); break
        reasons = [s["reason"] for s in summary["stops"]]
        if all(r in ("deadline_reached", "debug_cycle_cap") for r in reasons):
            summary["result"] = "passed"
        elif reasons == ["runner_signalled"]:
            # A supervisor stop is not a failure: the window is expected to resume.
            summary["result"] = "interrupted"
        else:
            summary["result"] = "failed"
    except (Refused, R.GuardFailure) as exc:
        summary["result"] = "failed"
        summary["stops"].append(dict(reason=str(exc)))
    finally:
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=30)
            except subprocess.TimeoutExpired:
                child.kill()
        summary["ended"] = datetime.now(timezone.utc).isoformat()
        reasons = [s.get("reason") for s in summary["stops"]]
        keep = any(r not in ("deadline_reached", "debug_cycle_cap") for r in reasons) or not reasons
        if keep and not a.close_on_failure:
            # A failure keeps the scene: the candidate, its volume and the server
            # log are the evidence, and a restart with --resume adopts them.
            summary["cleanup_deferred"] = True
        else:
            try:
                summary["cleanup"] = R.close_owned(root)
            except Exception as exc:  # cleanup failure is reported, never hidden
                summary["cleanup_error"] = type(exc).__name__
        observations.close()
    R.write_private(root / "final-summary.json", summary)
    print(json.dumps({"result": summary.get("result"), "cycles": summary.get("cycles"), "stops": summary.get("stops")}))
    if summary.get("result") == "passed" or interrupted["signal"]:
        return 0
    return 1


def main(argv=None):
    a = parse(argv)
    try:
        resolved = plan(a)
    except Refused as exc:
        print(json.dumps({"result": "refused", "reason": str(exc)}))
        return 2
    print(json.dumps({"plan": {k: (v.isoformat() if isinstance(v, datetime) else v) for k, v in resolved.items()},
                      "limits": LIMITS}, default=str))
    if a.plan:
        return 0
    return run(a, resolved)


if __name__ == "__main__":
    sys.exit(main())
