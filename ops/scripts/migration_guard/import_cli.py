"""Explicit candidate-only writer, separate from every read-only evidence entrypoint."""
import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import sys
import time

from .cli import write_report
from .compare import compare
from .conversion_policy import load_policy, target_shape_sha256
from .import_intent import bind_intent, load_intent
from .import_journal import ImportJournal
from .import_runner import ImportExecution, remaining
from .postgres import connection_file, inspect_target
from .row_projection import project_snapshot
from .schema_contract import load_contract
from .snapshot import GuardFailure, inspect_snapshot


def output_path(path):
    path=Path(path).absolute()
    parent=path.parent
    if parent.is_symlink() or parent.stat().st_uid!=os.getuid() or parent.stat().st_mode & 0o777 != 0o700 or os.path.lexists(path):
        raise GuardFailure('import_new_private_output_required')
    return path


def collect_inputs(args,deadline):
    intent=load_intent(args.intent_file,args.intent_sha256)
    policy=load_policy(args.conversion_policy_file)
    contract=load_contract(args.schema_contract_file,args.schema_contract_sha256)
    config=connection_file(args.target_connection_file)
    source=inspect_snapshot(args.snapshot,args.snapshot_sha256,timeout=remaining(deadline))
    bind_intent(intent,config,source,policy,args.schema_contract_sha256,policy['target_shape_sha256'],args.confirm_candidate_database)
    if contract['source_sha256']!=source['sha256'] or contract['target_shape_sha256']!=policy['target_shape_sha256']:
        raise GuardFailure('import_schema_source_or_shape_mismatch')
    target=inspect_target(args.target_connection_file,timeout=remaining(deadline))
    preflight=compare(source,target,policy)
    if preflight['result']!='passed':
        raise GuardFailure('import_empty_target_complete_shape_preflight_failed')
    if target_shape_sha256(target)!=intent['target_shape_sha256']:
        raise GuardFailure('import_intent_target_shape_mismatch')
    plan=preflight['conversion_plan']
    audit=next((m for m in plan['mappings'] if m['table']=='audit_events'),None)
    if audit is None:
        raise GuardFailure('import_explicit_audit_mapping_required')
    expected=project_snapshot(args.snapshot,source,target,policy,timeout=remaining(deadline))
    return dict(intent=intent,policy=policy,contract=contract,config=config,source=source,target=target,
                plan=plan,expected=expected,floor=audit['required_next_seq_floor'])


def execute(args):
    deadline=time.monotonic()+60
    output_path(args.report)
    output_path(args.journal)
    if Path(args.report).absolute()==Path(args.journal).absolute():
        raise GuardFailure('import_distinct_outputs_required')
    inputs=collect_inputs(args,deadline)
    with closing(ImportJournal(args.journal,inputs['source']['sha256'],args.intent_sha256)) as journal:
        execution=ImportExecution(args,inputs,journal,deadline)
        try:
            report=execution.run()
        except (GuardFailure,OSError,ValueError,sqlite3.Error) as exc:
            reason=str(exc) if isinstance(exc,GuardFailure) else 'import_execution_failure_diagnostics_withheld'
            report=dict(result='failed',reason=reason,scope='owned_candidate_transactional_import_only',
                        target_changed='unknown',commit_outcome='unknown' if execution.commit_requested else 'not_requested',
                        rollback_verified=False,automatic_retry=False,reconcile_before_replay=True,cutover_authorized=False)
            journal.append('failed_reconcile_before_replay',reason=reason,commit_outcome=report['commit_outcome'])
        report.update(attempt=journal.attempt,source_sha256=inputs['source']['sha256'],intent_sha256=args.intent_sha256,
                      intent_is_not_production_approval=True,source_is_final_cutover_snapshot=False,
                      inherited_mapping_plan_is_not_authority=True)
        write_report(args.report,report)
    print(json.dumps({key:report[key] for key in ('result','scope','target_changed','attempt')}))
    return 0 if report['result']=='passed' else 1


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('snapshot','snapshot-sha256','target-connection-file','conversion-policy-file',
                 'schema-contract-file','schema-contract-sha256','intent-file','intent-sha256',
                 'confirm-candidate-database','journal','report'):
        parser.add_argument('--'+name,required=True)
    args=parser.parse_args(argv)
    try:
        return execute(args)
    except (GuardFailure,OSError,ValueError,sqlite3.Error) as exc:
        reason=str(exc) if isinstance(exc,GuardFailure) else 'import_input_or_evidence_failure_diagnostics_withheld'
        print(json.dumps(dict(result='failed',reason=reason,target_changed='unknown',reconcile_before_replay=True,automatic_retry=False)),file=sys.stderr)
        return 1
