"""Finite preservation prerequisites, not a complete inventory or execution grant.

Callers must obtain these facts from their pinned, complete read-only observation.
This helper opens no store and cannot establish fact provenance, configuration,
constructor coverage, fencing, preservation after startup, or runtime acceptance.
"""
from .snapshot import GuardFailure, MAX_ROWS

PRESENCE_FIELDS = frozenset({'admin_role_present', 'admin_user_present',
                             'admin_client_present', 'console_client_present'})
BOOLEAN_FIELDS = PRESENCE_FIELDS | {'admin_seeded_password_present',
                                   'console_requires_pkce', 'console_has_secret'}
FIELDS = BOOLEAN_FIELDS | {'version', 'revocation_rows'}


def validate_facts(facts):
    if type(facts) is not dict or facts.keys() != FIELDS:
        raise GuardFailure('startup_preservation_fields_invalid')
    if type(facts['version']) is not int or facts['version'] != 1:
        raise GuardFailure('startup_preservation_version_invalid')
    count = facts['revocation_rows']
    if type(count) is not int or not 0 <= count <= MAX_ROWS:
        raise GuardFailure('startup_preservation_revocation_count_invalid')
    if any(type(facts[key]) is not bool for key in BOOLEAN_FIELDS):
        raise GuardFailure('startup_preservation_boolean_required')


def check_startup_preservation(facts):
    validate_facts(facts)
    # Load prunes independently of cleanup intervals. v1 deliberately admits
    # only the empty case; it does not infer safety from a future expiry.
    if facts['revocation_rows'] != 0:
        raise GuardFailure('startup_preservation_revocation_policy_required')
    if not all(facts[key] for key in PRESENCE_FIELDS):
        raise GuardFailure('startup_preservation_bootstrap_seed_policy_required')
    # Bootstrap v6 removes an existing attribute; v7 changes an existing
    # public client's PKCE bit. Neither is historical-row preservation.
    if facts['admin_seeded_password_present'] or not (
            facts['console_requires_pkce'] or facts['console_has_secret']):
        raise GuardFailure('startup_preservation_bootstrap_rewrite_policy_required')
    return dict(version=1, result='passed',
                scope='finite_startup_preservation_prerequisites_v1',
                revocation_load_prune_requires_empty_table=True,
                bootstrap_original_row_mutation_expected=False,
                complete_startup_inventory_verified=False,
                stock_start_authorized=False, runtime_certified=False)
