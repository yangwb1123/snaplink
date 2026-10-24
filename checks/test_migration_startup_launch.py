"""Finite stock launch context: no implicit env/flag authority or execution."""
import copy
import hashlib
import importlib
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ops/scripts'))
from migration_guard.snapshot import GuardFailure

FIELDS = ('version', 'profile', 'config_path', 'argv', 'environment')


def fixture(profile='off'):
    path = '/tmp/owned-step/' + profile + '-config.json'
    return dict(version=1, profile=profile, config_path=path,
                argv=['-config', path, '-grpc-listen', ''],
                environment={'GOMAXPROCS': '4', 'TMPDIR': '/tmp/owned-step/tmp'})


def check(value):
    return importlib.import_module('migration_guard.startup_launch').validate_launch(value)


def reject(value, message):
    before = copy.deepcopy(value)
    with pytest.raises(GuardFailure) as error:
        check(value)
    assert str(error.value) == message
    assert value == before


@pytest.mark.parametrize('profile', ['off', 'on'])
def test_launch_valid_is_finite_non_authorizing_and_does_not_mutate(profile):
    value = fixture(profile)
    before = copy.deepcopy(value)
    result = check(value)
    digest = hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=True).encode('ascii')).hexdigest()
    assert result == dict(version=1, result='passed', scope='finite_stock_launch_binding_v1',
                          profile=profile, launch_sha256=digest,
                          file_environment_flag_chain_required=True,
                          effective_config_verified=False,
                          complete_startup_inventory_verified=False,
                          stock_start_authorized=False, runtime_certified=False)
    assert value == before
    assert '/tmp/' not in json.dumps(result)
    assert 'GOMAXPROCS' not in json.dumps(result)


@pytest.mark.parametrize('name', FIELDS)
def test_launch_every_field_is_required(name):
    value = fixture()
    del value[name]
    reject(value, 'startup_launch_fields_invalid')


@pytest.mark.parametrize('value', [None, [], (), '', 1, True, {}, {'version': 1}])
def test_launch_non_complete_plain_mapping_rejected(value):
    reject(value, 'startup_launch_fields_invalid')


@pytest.mark.parametrize('name', ['stock_start_authorized', 'effective_config_verified',
                                  'complete_startup_inventory_verified', 'result', 'extra'])
def test_launch_unknown_admission_claims_rejected(name):
    value = fixture()
    value[name] = True
    reject(value, 'startup_launch_fields_invalid')


@pytest.mark.parametrize('version', [True, False, None, 0, 2, -1, '1', 1.0, [], {}])
def test_launch_version_not_coerced(version):
    value = fixture()
    value['version'] = version
    reject(value, 'startup_launch_version_invalid')


@pytest.mark.parametrize('profile', [None, True, 0, '', 'OFF', 'on ', 'browser_on', [], {}])
def test_launch_profile_is_exact(profile):
    value = fixture()
    value['profile'] = profile
    reject(value, 'startup_launch_profile_invalid')


@pytest.mark.parametrize('path', [None, True, 1, '', 'off-config.json',
    '/tmp/../off-config.json', '/tmp/./off-config.json', '//tmp/off-config.json',
    '/tmp//off-config.json', '/tmp/off-config.json/', '/tmp/on-config.json',
    '/tmp/off-config.yaml', '/tmp/off-config.json\n', '/tmp/a\x00/off-config.json',
    '/tmp/é/off-config.json', '/tmp/' + 'a' * 1024 + '/off-config.json'])
def test_launch_config_path_is_bounded_canonical_profile_specific(path):
    value = fixture()
    value['config_path'] = path
    value['argv'][1] = path
    reject(value, 'startup_launch_config_path_invalid')


@pytest.mark.parametrize('argv', [None, [], (), 'sso-server -config file',
    ['-config', '/tmp/other/off-config.json', '-grpc-listen', ''],
    ['--config', '/tmp/owned-step/off-config.json', '-grpc-listen', ''],
    ['-config=/tmp/owned-step/off-config.json', '-grpc-listen='],
    ['-config', '/tmp/owned-step/off-config.json'],
    ['-grpc-listen', '', '-config', '/tmp/owned-step/off-config.json'],
    ['-config', '/tmp/owned-step/off-config.json', '-grpc-listen', ':8081']])
def test_launch_argv_no_alias_implicit_listener_or_path_mismatch(argv):
    value = fixture()
    value['argv'] = argv
    reject(value, 'startup_launch_argv_invalid')


@pytest.mark.parametrize('flag', ['-listen', '-log-level', '-bootstrap-restore-from',
    '-bootstrap-admin-password-file', '-etcd-endpoints', '-etcd-prefix',
    '-tls-cert', '-tls-key', '-grpc-tls-cert', '-grpc-tls-key',
    '-grpc-insecure', '-validate-only', '-version', '-unknown', '--'])
def test_launch_every_additional_flag_is_rejected_even_if_empty(flag):
    value = fixture()
    value['argv'].extend([flag, ''])
    reject(value, 'startup_launch_argv_invalid')


@pytest.mark.parametrize('env', [None, [], (), '', {}, {'GOMAXPROCS': '4'},
    {'TMPDIR': '/tmp/owned-step/tmp'},
    {'GOMAXPROCS': 4, 'TMPDIR': '/tmp/owned-step/tmp'},
    {'GOMAXPROCS': '04', 'TMPDIR': '/tmp/owned-step/tmp'},
    {'GOMAXPROCS': '8', 'TMPDIR': '/tmp/owned-step/tmp'},
    {'GOMAXPROCS': '4', 'TMPDIR': '/tmp/other'},
    {'GOMAXPROCS': '4', 'TMPDIR': '/tmp/owned-step/tmp/'}])
def test_launch_environment_must_be_exact_not_coerced(env):
    value = fixture()
    value['environment'] = env
    reject(value, 'startup_launch_environment_invalid')


@pytest.mark.parametrize('name', ['SSO_OAUTH__REFRESH_TOKEN__REAP_INTERVAL',
    'SSO_BOOTSTRAP__DISABLED', 'SSO_SERVER__LISTEN', 'SSO_UNKNOWN', 'SSO_',
    'PGHOST', 'PGSERVICEFILE', 'PGPASSWORD', 'GODEBUG', 'GOGC', 'GOMEMLIMIT',
    'GORACE', 'HTTP_PROXY', 'HTTPS_PROXY', 'HOME', 'PATH', 'LD_PRELOAD'])
@pytest.mark.parametrize('content', ['', 'private-value-must-not-appear'])
def test_launch_unreviewed_environment_rejected_without_value_disclosure(name, content):
    value = fixture()
    value['environment'][name] = content
    reject(value, 'startup_launch_environment_invalid')


def test_launch_mapping_and_sequence_subclasses_are_not_plain_inputs():
    class Mapping(dict):
        pass
    class Sequence(list):
        pass
    reject(Mapping(fixture()), 'startup_launch_fields_invalid')
    value = fixture()
    value['argv'] = Sequence(value['argv'])
    reject(value, 'startup_launch_argv_invalid')
    value = fixture()
    value['environment'] = Mapping(value['environment'])
    reject(value, 'startup_launch_environment_invalid')


def test_launch_validation_order_and_no_input_repair():
    value = fixture()
    value.update(version=True, profile='OFF', config_path='relative', argv=[], environment={})
    reject(value, 'startup_launch_version_invalid')
    value['version'] = 1
    reject(value, 'startup_launch_profile_invalid')
    value['profile'] = 'off'
    reject(value, 'startup_launch_config_path_invalid')
    value['config_path'] = fixture()['config_path']
    reject(value, 'startup_launch_argv_invalid')
    value['argv'] = fixture()['argv']
    reject(value, 'startup_launch_environment_invalid')


def test_launch_digest_binds_profile_path_and_every_allowed_input():
    first = check(fixture())
    other = fixture()
    other['config_path'] = '/tmp/other/off-config.json'
    other['argv'][1] = other['config_path']
    other['environment']['TMPDIR'] = '/tmp/other/tmp'
    assert first['launch_sha256'] != check(other)['launch_sha256']
    assert first['launch_sha256'] != check(fixture('on'))['launch_sha256']


def test_startup_launch_owner_budgets():
    import ast

    owner = importlib.import_module('migration_guard.startup_launch')
    tree = ast.parse(Path(owner.__file__).read_text())
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        branches = sum(isinstance(item, (ast.If, ast.For, ast.While, ast.IfExp,
                                         ast.ExceptHandler, ast.comprehension))
                       for item in ast.walk(node))
        branches += sum(len(item.values) - 1 for item in ast.walk(node)
                        if isinstance(item, ast.BoolOp))
        assert node.end_lineno - node.lineno + 1 <= 50, node.name
        assert 1 + branches <= 15, (node.name, 1 + branches)
