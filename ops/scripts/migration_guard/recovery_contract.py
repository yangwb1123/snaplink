"""Private pinned native-PG checkpoint and archive fingerprint; no restore authority."""
import hashlib
import json
import os
import re
import time

from .conversion_policy import target_shape_sha256
from .postgres import unique_object
from .recovery_records import audit_records, content_records, schema_records
from .schema_contract import digest_required
from .snapshot import GuardFailure, METADATA_TABLES, private_file

ALGORITHM = 'pg_readonly_recovery_checkpoint_v1'
MAX_ARCHIVE_BYTES = 64 << 20


def read_pinned(path, expected, limit, retain=False):
    digest_required(expected)
    path = private_file(path, limit)
    before = path.lstat()
    deadline, digest, chunks, size, header = time.monotonic()+15, hashlib.sha256(), [], 0, b''
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        if stream.fileno() < 0 or os.fstat(stream.fileno()) != before:
            raise GuardFailure('recovery_pinned_file_changed')
        while True:
            if time.monotonic() >= deadline:
                raise GuardFailure('recovery_pinned_file_window_exceeded')
            chunk = stream.read(65536)
            if not chunk:
                break
            size += len(chunk)
            if size > limit:
                raise GuardFailure('recovery_pinned_file_budget_exceeded')
            header = (header + chunk)[:5]
            digest.update(chunk)
            if retain:
                chunks.append(chunk)
        after = os.fstat(stream.fileno())
    # Reading may change atime; all relevant identity/permission/content-size facts must stay fixed.
    fields = ('st_dev','st_ino','st_uid','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
    if any(getattr(before,k) != getattr(after,k) or getattr(after,k) != getattr(path.lstat(),k) for k in fields):
        raise GuardFailure('recovery_pinned_file_changed')
    if digest.hexdigest() != expected:
        raise GuardFailure('recovery_pinned_file_sha256_mismatch')
    return dict(sha256=expected,bytes=size), b''.join(chunks), header


def archive_evidence(path, expected):
    try:
        evidence, _, header = read_pinned(path, expected, MAX_ARCHIVE_BYTES)
    except GuardFailure as exc:
        if str(exc) == 'recovery_pinned_file_sha256_mismatch':
            raise GuardFailure('recovery_archive_sha256_mismatch') from exc
        raise
    if header != b'PGDMP':
        raise GuardFailure('recovery_custom_archive_required')
    return evidence


def validate_archive_fingerprint(archive):
    if not isinstance(archive, dict) or set(archive) != {'sha256','bytes'} or type(archive['bytes']) is not int or not 5 <= archive['bytes'] <= MAX_ARCHIVE_BYTES:
        raise GuardFailure('recovery_checkpoint_archive_invalid')
    digest_required(archive['sha256'])


def validate_source_identity(source):
    if not isinstance(source, dict) or set(source) != {'database','user','owner_sha256'}:
        raise GuardFailure('recovery_checkpoint_identity_invalid')
    if not isinstance(source['database'], str) or not re.fullmatch(r'snaplink_mig_[a-z0-9_]{1,32}', source['database']):
        raise GuardFailure('recovery_checkpoint_identity_invalid')
    if not isinstance(source['user'], str) or not 1 <= len(source['user']) <= 256 or '\x00' in source['user']:
        raise GuardFailure('recovery_checkpoint_identity_invalid')
    digest_required(source['owner_sha256'])


def validate_checkpoint(data):
    fields = {'version','algorithm','archive','source_identity','target_shape_sha256','content','schema','audit_sequence'}
    if not isinstance(data, dict) or set(data) != fields or type(data['version']) is not int or data['version'] != 1 or data['algorithm'] != ALGORITHM:
        raise GuardFailure('recovery_checkpoint_fields_or_version_invalid')
    validate_archive_fingerprint(data['archive'])
    digest_required(data['target_shape_sha256'])
    validate_source_identity(data['source_identity'])
    names = content_records(data['content'])
    shapes = dict(tables=[dict(table=t['table'],columns=t['projected_columns'],metadata_only=t['table'] in METADATA_TABLES) for t in data['content']['tables']])
    if target_shape_sha256(shapes) != data['target_shape_sha256']:
        raise GuardFailure('recovery_checkpoint_shape_content_mismatch')
    schema_records(data['schema'], names)
    audit_records(data['audit_sequence'])
    return data


def load_checkpoint(path, expected):
    try:
        _, raw, _ = read_pinned(path, expected, 256 << 10, retain=True)
    except GuardFailure as exc:
        if str(exc) == 'recovery_pinned_file_sha256_mismatch':
            raise GuardFailure('recovery_checkpoint_sha256_mismatch') from exc
        raise
    try:
        data = json.loads(raw.decode('utf-8', errors='strict'), object_pairs_hook=unique_object)
    except (ValueError, UnicodeError) as exc:
        raise GuardFailure('recovery_checkpoint_json_invalid') from exc
    return validate_checkpoint(data)
