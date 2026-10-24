"""Inspect the audit BIGSERIAL dependency/config/state; never advance or reset it."""
import math
import time

from .conversion_policy import MAX_INT8
from .postgres import connection_file, query_json, verify_target_identity
from .snapshot import GuardFailure, identifier

SEQUENCE_SQL = """
SELECT coalesce((SELECT json_build_object(
 'schema',n.nspname,'name',s.relname,'type',typ.typname,
 'start',q.seqstart,'increment',q.seqincrement,'min',q.seqmin,
 'max',q.seqmax,'cache',q.seqcache,'cycle',q.seqcycle,
 'column_identity',a.attidentity,
 'owned_by_column',EXISTS(SELECT 1 FROM pg_depend d
   WHERE d.classid='pg_class'::regclass AND d.objid=s.oid AND d.objsubid=0
   AND d.refclassid='pg_class'::regclass AND d.refobjid=t.oid
   AND d.refobjsubid=a.attnum AND d.deptype='a'),
 'default_matches',pg_get_expr(ad.adbin,ad.adrelid)=
   format('%s(%L::regclass)','nextval',s.oid::regclass::text),
 'default_dependents',(SELECT count(*) FROM pg_depend d
   WHERE d.classid='pg_attrdef'::regclass AND d.refclassid='pg_class'::regclass
   AND d.refobjid=s.oid AND d.deptype='n'))
 FROM pg_class t JOIN pg_namespace tn ON tn.oid=t.relnamespace
 JOIN pg_attribute a ON a.attrelid=t.oid AND a.attname='seq'
   AND a.attnum>0 AND NOT a.attisdropped
 LEFT JOIN pg_attrdef ad ON ad.adrelid=t.oid AND ad.adnum=a.attnum
 JOIN pg_class s ON s.oid=pg_get_serial_sequence('public.audit_events','seq')::regclass
 JOIN pg_namespace n ON n.oid=s.relnamespace
 JOIN pg_sequence q ON q.seqrelid=s.oid JOIN pg_type typ ON typ.oid=q.seqtypid
 WHERE tn.nspname='public' AND t.relname='audit_events' AND t.relkind='r'), 'null'::json);
"""


def validate_descriptor(meta):
    if not isinstance(meta, dict):
        raise GuardFailure("audit_sequence_required")
    expected = dict(schema="public", type="int8", start=1, increment=1,
                    min=1, max=MAX_INT8, cache=1, cycle=False,
                    owned_by_column=True, default_matches=True,
                    default_dependents=1, column_identity="")
    if set(meta) != set(expected) | {"name"}:
        raise GuardFailure("audit_sequence_descriptor_fields_invalid")
    identifier(meta["name"])
    if any(type(meta[key]) is not type(value) or meta[key] != value for key, value in expected.items()):
        raise GuardFailure("audit_sequence_shape_or_configuration_unsupported")
    return meta


def sequence_evidence(meta, state, required_floor):
    validate_descriptor(meta)
    if type(required_floor) is not int or not 1 <= required_floor <= MAX_INT8:
        raise GuardFailure("audit_sequence_floor_invalid")
    if not isinstance(state, dict) or set(state) != {"last_value", "is_called"}:
        raise GuardFailure("audit_sequence_state_required")
    last, called = state["last_value"], state["is_called"]
    if type(last) is not int or not 1 <= last <= MAX_INT8 or type(called) is not bool:
        raise GuardFailure("audit_sequence_state_invalid")
    candidate = last + int(called)
    if candidate > MAX_INT8:
        raise GuardFailure("audit_sequence_exhausted")
    issues = [] if candidate >= required_floor else [dict(
        code="audit_sequence_below_required_floor", table="audit_events", column="seq")]
    return dict(result="failed" if issues else "passed", blockers=issues,
                descriptor=meta, state=state, next_candidate=candidate,
                required_next_seq_floor=required_floor, sequence_advanced_or_reset=False,
                writer_fencing_verified=False, cross_query_atomic_snapshot=False,
                scope="observed audit BIGSERIAL only; not sequence calibration or cutover authority")


def inspect_audit_sequence(path, required_floor, timeout=60):
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 60:
        raise GuardFailure("audit_sequence_inspection_timeout_invalid")
    deadline = time.monotonic() + timeout
    config = connection_file(path)
    verify_target_identity(config)
    def query(sql):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise GuardFailure("audit_sequence_inspection_window_exceeded")
        return query_json(config, sql, min(15, remaining))
    meta = validate_descriptor(query(SEQUENCE_SQL))
    sql = 'SELECT json_build_object(\'last_value\',last_value,\'is_called\',is_called) FROM ' + identifier(meta['schema']) + '.' + identifier(meta['name']) + ';'
    state = query(sql)
    evidence = sequence_evidence(meta, state, required_floor)
    if query(SEQUENCE_SQL) != meta or query(sql) != state:
        raise GuardFailure("audit_sequence_changed_during_inspection")
    evidence["stable_between_reads"] = True
    return evidence
