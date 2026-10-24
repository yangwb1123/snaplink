"""Read-only psql catalog queries, with private credentials and bounded pipes."""
import json
import os
import re
import selectors
import shutil
import subprocess
import time

from .snapshot import GuardFailure, METADATA_TABLES, identifier, private_file

CATALOG_SQL = """
SELECT coalesce(json_agg(t ORDER BY t."table"), '[]'::json) FROM (
 SELECT c.relname AS "table", c.relkind AS relkind,
   c.relrowsecurity AS rls_enabled, c.relforcerowsecurity AS force_rls,
   (SELECT json_agg(json_build_object('name',a.attname,'type',typ.typname,'type_namespace',typns.nspname,
      'not_null',a.attnotnull,'pk_order',coalesce(array_position(pk.conkey,a.attnum),0),
      'canonical_zero_default',coalesce(a.attidentity='' AND a.attgenerated='' AND pg_get_expr(ad.adbin,ad.adrelid)='0',false)) ORDER BY a.attnum)
    FROM pg_attribute a JOIN pg_type typ ON typ.oid=a.atttypid
    JOIN pg_namespace typns ON typns.oid=typ.typnamespace
    LEFT JOIN pg_attrdef ad ON ad.adrelid=a.attrelid AND ad.adnum=a.attnum
    LEFT JOIN pg_constraint pk ON pk.conrelid=c.oid AND pk.contype='p'
    WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped) AS columns
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relkind IN ('r','p')
 ORDER BY c.relname LIMIT 101
) t;
"""


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise GuardFailure("duplicate_connection_field")
        result[key] = value
    return result


def connection_file(path):
    data = json.loads(private_file(path, 16 << 10).read_text(), object_pairs_hook=unique_object)
    fields = {"host", "port", "user", "database", "password", "owner_token"}
    if not isinstance(data, dict) or set(data) != fields:
        raise GuardFailure("unknown_or_missing_connection_field")
    if data["host"] != "127.0.0.1" or type(data["port"]) is not int or not 1 <= data["port"] <= 65535:
        raise GuardFailure("owned_loopback_target_required")
    if not isinstance(data["database"], str) or not re.fullmatch(r"snaplink_mig_[a-z0-9_]{1,32}", data["database"]):
        raise GuardFailure("dedicated_candidate_database_required")
    if not isinstance(data["owner_token"], str) or not re.fullmatch(r"[0-9a-f]{48}", data["owner_token"]):
        raise GuardFailure("private_target_ownership_required")
    if any(not isinstance(data[key], str) or not data[key] or "\x00" in data[key] for key in ("user", "password")):
        raise GuardFailure("invalid_target_credentials")
    return data


def bounded_psql(argv, env, sql, timeout=15):
    if len(sql.encode()) > 4096:
        raise GuardFailure("target_query_input_budget_exceeded")
    deadline, output = time.monotonic() + timeout, [bytearray(), bytearray()]
    with subprocess.Popen(argv, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
        try:
            child.stdin.write(sql.encode())
            child.stdin.close()
            with selectors.DefaultSelector() as ready:
                for i, pipe in enumerate((child.stdout, child.stderr)):
                    ready.register(pipe, selectors.EVENT_READ, i)
                while ready.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise GuardFailure("target_query_timeout")
                    for event, _ in ready.select(remaining):
                        chunk = os.read(event.fileobj.fileno(), 65536)
                        if not chunk:
                            ready.unregister(event.fileobj)
                            continue
                        output[event.data].extend(chunk)
                        if len(output[0]) > 2 << 20 or len(output[1]) > 8 << 10:
                            raise GuardFailure("target_query_output_budget_exceeded")
            if child.wait(timeout=max(0.001, deadline - time.monotonic())):
                raise GuardFailure("target_query_failed_diagnostics_withheld")
        finally:
            if child.poll() is None:
                child.kill()  # This handle owns this subprocess; no PID guessing.
                child.wait()
    return bytes(output[0])


def psql_command(config):
    binary = shutil.which("psql")
    if not binary:
        raise GuardFailure("required_psql_missing")
    env = {key: value for key, value in os.environ.items() if not key.startswith("PG")}
    env.update(PGHOST=config["host"], PGPORT=str(config["port"]), PGDATABASE=config["database"],
               PGUSER=config["user"], PGPASSWORD=config["password"], PGCONNECT_TIMEOUT="5",
               PGCLIENTENCODING="UTF8", PGOPTIONS="-c default_transaction_read_only=on -c statement_timeout=5000 -c lock_timeout=2000")
    return [binary, "-X", "-qAt", "-v", "ON_ERROR_STOP=1"], env


def query_json(config, sql, timeout=15):
    argv, env = psql_command(config)
    script = "\\set VERBOSITY sqlstate\nBEGIN READ ONLY;\n" + sql + "\nCOMMIT;\n"
    raw = bounded_psql(argv, env, script, timeout)
    try:
        return json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise GuardFailure("invalid_target_query_reply") from exc


def verify_target_identity(config, timeout=15):
    owner = query_json(config, "SELECT json_build_object('database',current_database(),'user',current_user,"
                       "'read_only',current_setting('transaction_read_only'),'version',version(),"
                       "'owned',(SELECT count(*)=1 AND bool_and(token='" + config["owner_token"] + "') FROM migration_guard.ownership));", timeout=timeout)
    if owner.get("owned") is not True or owner.get("read_only") != "on":
        raise GuardFailure("target_ownership_or_readonly_not_verified")
    if owner.get("database") != config["database"] or owner.get("user") != config["user"]:
        raise GuardFailure("target_database_or_role_mismatch")
    return owner


def inspect_target(path, timeout=60):
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 60:
        raise GuardFailure("target_inspection_timeout_invalid")
    config = connection_file(path)
    deadline = time.monotonic() + timeout
    owner = verify_target_identity(config, timeout=min(15, timeout))
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise GuardFailure("target_inspection_window_exceeded")
    tables = query_json(config, CATALOG_SQL, min(15, remaining))
    if not isinstance(tables, list) or len(tables) > 100:
        raise GuardFailure("target_table_budget_exceeded")
    for table in tables:
        name = identifier(table["table"])
        if not isinstance(table["columns"], list) or len(table["columns"]) > 80:
            raise GuardFailure("target_column_budget_exceeded")
        for col in table["columns"]:
            identifier(col["name"])
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise GuardFailure("target_inspection_window_exceeded")
        table["rows"] = query_json(config, "SELECT to_json(count(*)) FROM public." + name + ";", min(15, remaining))
        table["metadata_only"] = table["table"] in METADATA_TABLES
    return {"identity": owner, "tables": tables, "read_only": True, "credentials_in_report": False}
