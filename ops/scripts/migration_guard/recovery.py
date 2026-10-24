"""Compare a distinct owned target to pinned prior native-PG observations, without writes."""
import hashlib
import time

from .postgres import connection_file
from .recovery_contract import ALGORITHM, archive_evidence, load_checkpoint, validate_checkpoint
from .recovery_observe import observe_native, remaining
from .schema_sql import FACETS
from .snapshot import GuardFailure, METADATA_TABLES
from .target_content import comparison_issues


def owner_digest(config):
    return hashlib.sha256(config['owner_token'].encode('ascii')).hexdigest()


def capture_checkpoint(connection_path, archive_path, archive_sha256):
    # Deliberately an explicit experimental API, not an auto-learning CLI or source approval.
    archive = archive_evidence(archive_path, archive_sha256)
    config = connection_file(connection_path)
    observed = observe_native(connection_path)
    data = dict(version=1,algorithm=ALGORITHM,archive=archive,
                source_identity=dict(database=config['database'],user=config['user'],owner_sha256=owner_digest(config)),
                **{k:observed[k] for k in ('target_shape_sha256','content','schema','audit_sequence')})
    if archive_evidence(archive_path, archive_sha256) != archive or connection_file(connection_path) != config:
        raise GuardFailure('recovery_pinned_inputs_changed_during_capture')
    return validate_checkpoint(data)


def recovery_issues(expected, actual):
    validate_checkpoint(expected)
    blockers = comparison_issues(expected['content'], actual['content'])
    if expected['target_shape_sha256'] != actual['target_shape_sha256']:
        blockers.append(dict(code='recovery_target_shape_mismatch'))
    if set(expected['schema']['tables']) != set(actual['schema']['tables']):
        raise GuardFailure('recovery_schema_table_coverage_mismatch')
    if expected['schema']['environment_sha256'] != actual['schema']['environment_sha256']:
        blockers.append(dict(code='recovery_environment_mismatch'))
    for name in sorted(expected['schema']['tables']):
        left, right = expected['schema']['tables'][name], actual['schema']['tables'][name]
        for facet in FACETS:
            if left['facets'][facet] != right['facets'][facet] or left['counts'][facet] != right['counts'][facet]:
                blockers.append(dict(code='recovery_schema_facet_mismatch',table=name,facet=facet))
    if expected['audit_sequence'] != actual['audit_sequence']:
        blockers.append(dict(code='recovery_audit_sequence_mismatch'))
    return blockers


def restore_boundary(config, expected):
    origin = expected['source_identity']
    if config['database'] == origin['database'] or owner_digest(config) == origin['owner_sha256']:
        raise GuardFailure('recovery_distinct_database_and_owner_required')
    if config['user'] != origin['user']:
        raise GuardFailure('recovery_declared_role_mismatch')


def verify_restored(checkpoint_path, checkpoint_sha256, archive_path, archive_sha256, connection_path):
    deadline = time.monotonic() + 60
    expected = load_checkpoint(checkpoint_path, checkpoint_sha256)
    archive = archive_evidence(archive_path, archive_sha256)
    if archive != expected['archive']:
        raise GuardFailure('recovery_checkpoint_archive_mismatch')
    config = connection_file(connection_path)
    restore_boundary(config, expected)
    observed = observe_native(connection_path, timeout=remaining(deadline))
    blockers = recovery_issues(expected, observed)
    if archive_evidence(archive_path, archive_sha256) != archive or load_checkpoint(checkpoint_path, checkpoint_sha256) != expected or connection_file(connection_path) != config:
        raise GuardFailure('recovery_pinned_inputs_changed')
    remaining(deadline)
    histories = [t for t in observed['content']['tables'] if t['table'] in METADATA_TABLES]
    return dict(result='failed' if blockers else 'passed',blockers=blockers,scope='distinct target matches pinned prior native PG public-table observations only',
                checkpoint_sha256=checkpoint_sha256,archive=archive,observed=observed,
                migration_history_tables=len(histories),migration_history_rows=sum(t['rows'] for t in histories),
                supported_recovery_observations_matched=not blockers,metadata_counts_tracked=True,
                raw_rows_ddl_credentials_in_report=False,target_changed=False,
                archive_consumption_provenance_verified=False,archive_format_fully_validated=False,backup_snapshot_correlation_verified=False,
                restore_execution_verified=False,cross_phase_atomic_snapshot=False,writer_fencing_verified=False,
                all_sequence_states_verified=False,audit_required_floor_certified=False,audit_chain_verified=False,
                full_ddl_certified=False,all_business_relationships_verified=False,external_keys_roles_grants_certified=False,
                production_recovery_certified=False,cutover_authorized=False)
