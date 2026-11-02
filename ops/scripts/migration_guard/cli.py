"""Evidence-only CLI. There is deliberately no apply, truncate, or cutover mode."""
import argparse
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile

from .compare import compare
from .conversion_policy import load_policy
from .postgres import inspect_target
from .row_projection import project_snapshot
from .sequence import inspect_audit_sequence
from .snapshot import GuardFailure, inspect_snapshot
from .target_content import verify_content
from .schema_contract import load_contract
from .source_relations import source_foreign_keys
from .target_schema import verify_schema
from .sequence_inventory import verify_sequences


def write_report(path, report):
    path = Path(path).absolute()
    parent = path.parent
    if parent.is_symlink() or parent.stat().st_uid != os.getuid() or parent.stat().st_mode & 0o777 != 0o700:
        raise GuardFailure("private_owned_report_directory_required")
    fd, temporary = tempfile.mkstemp(prefix=".migration-preflight-", dir=parent)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(report, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)  # Complete evidence only; fail rather than overwrite.
    finally:
        os.unlink(temporary)
    directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)  # Durable create-only evidence, not just durable temporary bytes.
    finally:
        os.close(directory)


def collect_row_evidence(args, report, policy):
    report["scope"] = "read_only_projection_and_audit_sequence_preflight"
    report["target_content_verified"] = False
    if report["result"] != "passed":
        report["row_evidence"] = dict(result="not_executed", reason="shape_preflight_failed")
        return
    plan = report["conversion_plan"]
    audit = next((m for m in plan["mappings"] if m["table"] == "audit_events"), None)
    if audit is None:
        raise GuardFailure("row_evidence_audit_mapping_required")
    report["source_projection"] = project_snapshot(args.snapshot, report["source"], report["target"], policy)
    sequence = inspect_audit_sequence(args.target_connection_file, audit["required_next_seq_floor"])
    report["audit_sequence"] = sequence
    report["blockers"].extend(sequence["blockers"])
    report["result"] = "failed" if report["blockers"] else "passed"


def collect_target_content(args, report, policy):
    report["scope"] = "read_only_target_content_and_audit_sequence_verification"
    if report["result"] != "passed":
        report["content_verification"] = dict(result="not_executed", reason="shape_preflight_failed")
        return
    audit = next((m for m in report["conversion_plan"]["mappings"] if m["table"] == "audit_events"), None)
    if audit is None:
        raise GuardFailure("target_content_audit_mapping_required")
    evidence = verify_content(args.snapshot, args.target_connection_file, report["source"], report["target"], policy)
    report["initial_target_observation"] = report["target"]
    report["target"] = evidence["target_snapshot"]
    report["content_verification"] = evidence
    report["target_content_verified"] = evidence["target_content_verified"]
    report["blockers"].extend(evidence["blockers"])
    sequence = inspect_audit_sequence(args.target_connection_file, audit["required_next_seq_floor"])
    report["audit_sequence"] = sequence
    report["blockers"].extend(sequence["blockers"])
    report["result"] = "failed" if report["blockers"] else "passed"


def collect_target_schema(args, report, policy, contract):
    report.update(scope="read_only_native_schema_contract_and_declared_foreign_keys",target_content_verified=False)
    if report["result"] != "passed":
        report["schema_verification"] = dict(result="not_executed",reason="shape_preflight_failed")
        return
    audit = next((m for m in report["conversion_plan"]["mappings"] if m["table"] == "audit_events"), None)
    if audit is None:
        raise GuardFailure("target_schema_audit_mapping_required")
    evidence = verify_schema(args.snapshot,args.target_connection_file,report["source"],report["target"],policy,contract)
    report["schema_verification"] = evidence
    report["schema_contract_sha256"] = args.schema_contract_sha256
    report["target_schema_contract_matched"] = evidence["target_schema_contract_matched"]
    report["source_declared_foreign_keys"] = source_foreign_keys(args.snapshot,report["source"])
    report["initial_target_observation"] = report["target"]
    report["target"] = evidence["target_snapshot"]
    report["blockers"].extend(evidence["blockers"])
    sequence = inspect_audit_sequence(args.target_connection_file,audit["required_next_seq_floor"])
    report["audit_sequence"] = sequence
    report["blockers"].extend(sequence["blockers"])
    report["result"] = "failed" if report["blockers"] else "passed"


def collect_target_sequences(args, report, policy):
    report.update(scope="read_only_supported_sequence_inventory_and_floors",target_content_verified=False)
    if report["result"] != "passed":
        report["sequence_inventory"] = dict(result="not_executed",reason="shape_preflight_failed")
        return
    evidence = verify_sequences(args.snapshot,args.target_connection_file,report["source"],report["target"],policy)
    report["initial_target_observation"] = report["target"]
    report["target"] = evidence["target_snapshot"]
    report["sequence_inventory"] = evidence
    report["blockers"].extend(evidence["blockers"])
    report["result"] = "failed" if report["blockers"] else "passed"


def verification_purpose(args):
    modes = [(args.verify_target_schema,"verify_schema"),(args.verify_target_content,"verify_content"),(args.verify_target_sequences,"verify_sequences")]
    return next((purpose for enabled,purpose in modes if enabled),"preflight")


def require_mode_policy(args):
    if args.conversion_policy_file is not None:
        return
    # Preserve rejection precedence independently of observer dispatch order.
    requirements = ((args.verify_target_sequences, "target_sequences_requires_conversion_policy"),
                    (args.verify_target_schema, "target_schema_requires_conversion_policy"),
                    (args.verify_target_content, "target_content_requires_conversion_policy"),
                    (args.row_evidence, "row_evidence_requires_conversion_policy"))
    for enabled, reason in requirements:
        if enabled:
            raise GuardFailure(reason)


def require_schema_contract(args):
    if args.verify_target_schema:
        if args.schema_contract_file is None or args.schema_contract_sha256 is None:
            raise GuardFailure("target_schema_requires_pinned_contract")
    elif args.schema_contract_file is not None or args.schema_contract_sha256 is not None:
        raise GuardFailure("schema_contract_requires_schema_mode")


def mode_inputs(args):
    require_mode_policy(args)
    require_schema_contract(args)
    policy = load_policy(args.conversion_policy_file) if args.conversion_policy_file is not None else None
    contract = load_contract(args.schema_contract_file,args.schema_contract_sha256) if args.verify_target_schema else None
    return policy,contract


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", required=True, help="private, journal-free SQLite online backup; never a live main file")
    parser.add_argument("--snapshot-sha256", required=True, help="SHA-256 from the separately retained online-backup receipt")
    parser.add_argument("--target-connection-file", required=True, help="0600 JSON inside 0700 directory; loopback candidate only")
    parser.add_argument("--report", required=True, help="new 0600 JSON evidence path inside an owned 0700 directory")
    parser.add_argument("--conversion-policy-file", help="optional private v1 source/target-shape-bound mapping plan; no apply authority")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--row-evidence", action="store_true", help="explicit-policy mapped PK/content digests plus read-only audit sequence checks; no import/reset")
    mode.add_argument("--verify-target-content", action="store_true", help="explicit-policy all-table PK/content comparison at one read-only target snapshot; no import/reset/cutover")
    mode.add_argument("--verify-target-schema", action="store_true", help="pinned native DDL facets and declared FK checks; not complete business-relationship or cutover proof")
    mode.add_argument("--verify-target-sequences", action="store_true", help="explicit-policy full supported sequence inventory, states and source/observed floors; no calibration, fencing or cutover")
    parser.add_argument("--schema-contract-file", help="private expected native-DDL facet hashes; no auto-baseline/export")
    parser.add_argument("--schema-contract-sha256", help="separately pinned SHA-256 of expected contract")
    args = parser.parse_args(argv)
    try:
        policy,contract = mode_inputs(args)
        source = inspect_snapshot(args.snapshot, args.snapshot_sha256)
        target = inspect_target(args.target_connection_file)
        report = compare(source, target, policy, purpose=verification_purpose(args))
        if args.row_evidence:
            collect_row_evidence(args, report, policy)
        if args.verify_target_content:
            collect_target_content(args, report, policy)
        if args.verify_target_schema:
            collect_target_schema(args, report, policy, contract)
        if args.verify_target_sequences:
            collect_target_sequences(args, report, policy)
        write_report(args.report, report)
    except (GuardFailure, OSError, ValueError, sqlite3.Error) as exc:
        reason = str(exc) if isinstance(exc, GuardFailure) else "preflight_input_query_or_evidence_failure"
        print(json.dumps({"result": "failed", "reason": reason, "target_changed": False}), file=sys.stderr)
        return 1
    print(json.dumps({key: report[key] for key in ("result", "scope", "source_business_tables", "source_business_rows", "target_business_tables", "blockers")}, indent=2))
    return 0 if report["result"] == "passed" else 1
