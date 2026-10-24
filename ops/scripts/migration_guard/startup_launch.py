"""Finite owned-rehearsal launch binding, not stock admission or execution."""
import hashlib
import json
import posixpath

from .snapshot import GuardFailure

_FIELDS = {'version', 'profile', 'config_path', 'argv', 'environment'}


def _config_path(path, profile):
    if type(path) is not str or not path.isascii() or len(path) > 1024:
        raise GuardFailure('startup_launch_config_path_invalid')
    if (not path.startswith('/') or path.startswith('//') or
            posixpath.normpath(path) != path or
            not path.endswith('/' + profile + '-config.json') or
            any(ord(char) < 32 or ord(char) == 127 for char in path)):
        raise GuardFailure('startup_launch_config_path_invalid')


def _argv(argv, path):
    if (type(argv) is not list or len(argv) != 4 or
            any(type(arg) is not str for arg in argv) or
            argv != ['-config', path, '-grpc-listen', '']):
        raise GuardFailure('startup_launch_argv_invalid')


def _environment(env, path):
    if (type(env) is not dict or len(env) != 2 or
            set(env) != {'GOMAXPROCS', 'TMPDIR'} or
            any(type(value) is not str for value in env.values()) or
            env['GOMAXPROCS'] != '4' or
            env['TMPDIR'] != posixpath.dirname(path) + '/tmp'):
        raise GuardFailure('startup_launch_environment_invalid')


def validate_launch(launch):
    """Validate supplied data only; caller must prove bytes, ownership and use.

    Only this exact argv and complete explicit child environment are supported.
    Never filter an inherited environment or repair a rejected input to pass.
    A digest does not establish config content, freshness, fencing or approval.
    """
    if type(launch) is not dict or len(launch) != 5 or set(launch) != _FIELDS:
        raise GuardFailure('startup_launch_fields_invalid')
    if type(launch['version']) is not int or launch['version'] != 1:
        raise GuardFailure('startup_launch_version_invalid')
    profile = launch['profile']
    if type(profile) is not str or profile not in ('off', 'on'):
        raise GuardFailure('startup_launch_profile_invalid')
    path = launch['config_path']
    _config_path(path, profile)
    _argv(launch['argv'], path)
    _environment(launch['environment'], path)
    digest = hashlib.sha256(json.dumps(launch, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=True).encode('ascii')).hexdigest()
    return dict(version=1, result='passed', scope='finite_stock_launch_binding_v1',
                profile=profile, launch_sha256=digest,
                file_environment_flag_chain_required=True,
                effective_config_verified=False,
                complete_startup_inventory_verified=False,
                stock_start_authorized=False, runtime_certified=False)
