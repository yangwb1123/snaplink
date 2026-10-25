"""Read-only verification of a populated owned candidate; never writes to the target."""
import argparse
import json
import sys

from .cli import write_report
from .conversion_policy import load_policy
from .postgres import inspect_target
from .sequence_inventory import verify_sequences
from .snapshot import GuardFailure, inspect_snapshot
from .target_content import verify_content


def bounded_timeout(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 60:
        raise GuardFailure("verify_timeout_out_of_bounds")
    return value


def execute(args):
    timeout = bounded_timeout(args.timeout)
    policy = load_policy(args.conversion_policy_file)
    source = inspect_snapshot(args.snapshot, args.snapshot_sha256, timeout=timeout)
    target = inspect_target(args.target_connection_file)
    content = verify_content(args.snapshot, args.target_connection_file, source, target, policy, timeout=timeout)
    sequences = verify_sequences(args.snapshot, args.target_connection_file, source, target, policy, timeout=timeout)
    passed = content["result"] == "passed" and sequences["result"] == "passed"
    report = dict(
        version=1,
        scope="owned_candidate_read_only_verification_v1",
        result="passed" if passed else "failed",
        source_sha256=source["sha256"],
        target_tables=len(target["tables"]),
        content_result=content["result"],
        sequence_result=sequences["result"],
        sequence_blockers=sequences.get("blockers", []),
        verified_after_import=True,
        writes_performed=False,
        cutover_authorized=False,
        automatic_retry=False,
        engine_support_not_implied=True,
    )
    write_report(args.report, report)
    print(json.dumps({key: report[key] for key in ("result", "scope", "content_result", "sequence_result")}))
    return 0 if passed else 1


def parser():
    arg_parser = argparse.ArgumentParser(description=__doc__)
    arg_parser.add_argument("--snapshot", required=True)
    arg_parser.add_argument("--snapshot-sha256", required=True)
    arg_parser.add_argument("--target-connection-file", required=True)
    arg_parser.add_argument("--conversion-policy-file", required=True)
    arg_parser.add_argument("--report", required=True)
    arg_parser.add_argument("--timeout", type=int, default=60)
    return arg_parser


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        return execute(args)
    except (GuardFailure, OSError, ValueError) as exc:
        reason = str(exc) if isinstance(exc, GuardFailure) else "verify_input_or_evidence_failure_diagnostics_withheld"
        print(json.dumps(dict(result="failed", reason=reason, writes_performed=False,
                              cutover_authorized=False, automatic_retry=False)), file=sys.stderr)
        return 1
