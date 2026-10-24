"""Read-only native-PG restored-target evidence; never dump, restore, clean or calibrate."""
import argparse
import json
import sys

from .cli import write_report
from .recovery import verify_restored
from .snapshot import GuardFailure


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkpoint-file', required=True, help='private bounded prior native-PG observations; untrusted baseline, not authorization')
    parser.add_argument('--checkpoint-sha256', required=True, help='separately pinned checkpoint SHA-256')
    parser.add_argument('--archive-file', required=True, help='private custom PGDMP archive; hashed only, never executed')
    parser.add_argument('--archive-sha256', required=True, help='separately pinned exact archive SHA-256')
    parser.add_argument('--restored-connection-file', required=True, help='private distinct owned loopback candidate connection')
    parser.add_argument('--report', required=True, help='new evidence path inside owned 0700 directory; never overwrite')
    args = parser.parse_args(argv)
    try:
        report = verify_restored(args.checkpoint_file,args.checkpoint_sha256,args.archive_file,args.archive_sha256,args.restored_connection_file)
        write_report(args.report, report)
    except (GuardFailure,OSError,ValueError) as exc:
        reason = str(exc) if isinstance(exc, GuardFailure) else 'recovery_input_query_or_evidence_failure'
        print(json.dumps(dict(result='failed',reason=reason,target_changed=False)),file=sys.stderr)
        return 1
    print(json.dumps({k:report[k] for k in ('result','scope','blockers','migration_history_tables','migration_history_rows')}))
    return 0 if report['result'] == 'passed' else 1
