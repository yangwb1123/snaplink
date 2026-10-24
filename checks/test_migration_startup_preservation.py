"""Finite startup-preservation facts never authorize a stock process."""
import copy
import importlib
from pathlib import Path
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'ops/scripts'))
from migration_guard.snapshot import GuardFailure


def facts():
    return dict(version=1, revocation_rows=0, admin_role_present=True,
                admin_user_present=True, admin_seeded_password_present=False,
                admin_client_present=True, console_client_present=True,
                console_requires_pkce=True, console_has_secret=False)


def check(value):
    return importlib.import_module('migration_guard.startup_preservation').check_startup_preservation(value)


@pytest.mark.parametrize('pkce,secret', [(True,False),(False,True),(True,True)])
def test_complete_finite_prerequisites_do_not_authorize_startup(pkce,secret):
    value=facts();value.update(console_requires_pkce=pkce,console_has_secret=secret)
    before=copy.deepcopy(value)
    result=check(value)
    assert result==dict(version=1,result='passed',scope='finite_startup_preservation_prerequisites_v1',
                        revocation_load_prune_requires_empty_table=True,
                        bootstrap_original_row_mutation_expected=False,
                        complete_startup_inventory_verified=False,
                        stock_start_authorized=False,runtime_certified=False)
    assert value==before


@pytest.mark.parametrize('field', list(facts()))
def test_every_fact_is_required(field):
    value=facts();del value[field]
    with pytest.raises(GuardFailure,match='startup_preservation_fields_invalid'):
        check(value)


@pytest.mark.parametrize('value', [None,[],False,{},'passed'])
def test_absent_or_non_mapping_facts_reject(value):
    with pytest.raises(GuardFailure,match='startup_preservation_fields_invalid'):
        check(value)


@pytest.mark.parametrize('version', [True,False,0,2,1.0,'1',None])
def test_version_is_an_exact_supported_integer(version):
    value=facts();value['version']=version
    with pytest.raises(GuardFailure,match='startup_preservation_version_invalid'):
        check(value)


@pytest.mark.parametrize('count', [True,False,-1,0.0,'0',None,200001])
def test_row_count_never_coerces_unknown_or_boolean_to_empty(count):
    value=facts();value['revocation_rows']=count
    with pytest.raises(GuardFailure,match='startup_preservation_revocation_count_invalid'):
        check(value)


@pytest.mark.parametrize('count', [1,100000,200000])
def test_populated_revocations_need_a_separate_retention_policy_even_if_live(count):
    value=facts();value['revocation_rows']=count
    with pytest.raises(GuardFailure,match='startup_preservation_revocation_policy_required'):
        check(value)


@pytest.mark.parametrize('field', [key for key in facts() if key not in {'version','revocation_rows'}])
@pytest.mark.parametrize('unobserved', [None,0,1,'false','true',[]])
def test_all_presence_and_policy_facts_are_actual_booleans(field,unobserved):
    value=facts();value[field]=unobserved
    with pytest.raises(GuardFailure,match='startup_preservation_boolean_required'):
        check(value)


@pytest.mark.parametrize('field', ['admin_role_present','admin_user_present',
                                  'admin_client_present','console_client_present'])
def test_bootstrap_cannot_silently_add_historical_authority(field):
    value=facts();value[field]=False
    with pytest.raises(GuardFailure,match='startup_preservation_bootstrap_seed_policy_required'):
        check(value)


@pytest.mark.parametrize('field', ['admin_seeded_password_present','console_requires_pkce'])
def test_bootstrap_cannot_silently_rewrite_historical_users_or_clients(field):
    value=facts();value[field]=not value[field]
    with pytest.raises(GuardFailure,match='startup_preservation_bootstrap_rewrite_policy_required'):
        check(value)


def test_unknown_assertions_do_not_expand_admission():
    value=facts();value['complete_startup_inventory_verified']=True
    with pytest.raises(GuardFailure,match='startup_preservation_fields_invalid'):
        check(value)


def test_validation_order_and_input_are_preserved_on_failure():
    value=facts();value.update(version=2,revocation_rows=1,admin_user_present=False)
    before=copy.deepcopy(value)
    with pytest.raises(GuardFailure,match='startup_preservation_version_invalid'):
        check(value)
    assert value==before
    value=facts();value.update(revocation_rows=1,admin_user_present=False)
    with pytest.raises(GuardFailure,match='startup_preservation_revocation_policy_required'):
        check(value)
