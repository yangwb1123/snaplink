"""SHA-pinned, short-lived, candidate-only intent; never production approval."""
import hashlib
import json
import re
import time

from .conversion_policy import digest, is_sha
from .postgres import unique_object
from .snapshot import GuardFailure, private_file

FIELDS = {'version','scope','source_sha256','policy_sha256','schema_contract_sha256',
          'target_shape_sha256','target_database','target_owner_sha256','expires_at',
          'candidate_exclusive','source_is_final_cutover_snapshot',
          'historical_audit_chain_certified','sequence_mode'}


def validate_intent(data):
    if not isinstance(data,dict) or set(data) != FIELDS:
        raise GuardFailure('import_intent_fields_invalid')
    expected = dict(version=1,scope='owned_candidate_import_v1',candidate_exclusive=True,
                    source_is_final_cutover_snapshot=False,historical_audit_chain_certified=False,
                    sequence_mode='pg_transactional_restart_v1')
    if any(type(data[k]) is not type(v) or data[k] != v for k,v in expected.items()):
        raise GuardFailure('import_candidate_only_intent_required')
    for key in ('source_sha256','policy_sha256','schema_contract_sha256','target_shape_sha256','target_owner_sha256'):
        if not is_sha(data[key]):
            raise GuardFailure('import_intent_digest_required')
    if not isinstance(data['target_database'],str) or not re.fullmatch(r'snaplink_mig_[a-z0-9_]{1,32}',data['target_database']):
        raise GuardFailure('import_dedicated_candidate_required')
    if type(data['expires_at']) is not int or not time.time() < data['expires_at'] <= time.time()+3600:
        raise GuardFailure('import_intent_expired_or_window_invalid')
    return data


def load_intent(path, expected_sha256):
    if not is_sha(expected_sha256):
        raise GuardFailure('import_intent_digest_required')
    raw=private_file(path,16<<10).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise GuardFailure('import_intent_sha256_mismatch')
    try:
        data=json.loads(raw.decode('utf-8',errors='strict'),object_pairs_hook=unique_object)
    except (ValueError,UnicodeError) as exc:
        raise GuardFailure('import_intent_json_invalid') from exc
    return validate_intent(data)


def bind_intent(intent, config, source, policy, schema_sha, shape_sha, confirmed_database):
    validate_intent(intent)
    expected=dict(source_sha256=source['sha256'],policy_sha256=digest(policy),
                  schema_contract_sha256=schema_sha,target_shape_sha256=shape_sha,
                  target_database=config['database'],
                  target_owner_sha256=hashlib.sha256(config['owner_token'].encode()).hexdigest())
    if confirmed_database != config['database'] or any(intent[k] != v for k,v in expected.items()):
        raise GuardFailure('import_intent_source_target_or_contract_mismatch')
