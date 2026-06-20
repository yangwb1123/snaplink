#!/usr/bin/env python3
"""Gate: forbid business code files in root directory.

This check enforces the Root Directory Policy defined in AGENTS.md.
Root should only contain server composition files, not business logic.
"""
import sys
from pathlib import Path

# Files that SHOULD NOT be in root (business logic)
BANNED_PATTERNS = [
    "*_handler.go",      # HTTP handlers
    "*_service.go",      # Business services
    "*_store.go",        # Data stores
    "*_grant.go",        # OAuth grants
    "*_helpers.go",      # Helper functions (should be in domain packages)
    "*_bundle.go",       # Policy bundles
    "*_assertion.go",    # Assertions
    "*_cache.go",        # Caches (should be in domain packages)
    "*_rotation.go",     # Key rotation
    "*_revocation.go",   # Token revocation
    "*_aggregation.go",  # Key aggregation
    "*_configuration.go", # OIDC configuration
    "*_metadata.go",     # Metadata handlers
    "*_resolution.go",   # Resolution logic
]

# Specific files that are business logic and should move
BANNED_FILES = [
    # OAuth handlers
    "auth_code_handler.go",
    "ciba_handler.go",
    "device_code_handler.go",
    "token_handler.go",
    "token_exchange_handler.go",
    "refresh_token_grant.go",
    
    # OIDC handlers
    "backchannel_logout.go",
    "logout_handler.go",
    "userinfo_handler.go",
    "discovery_handler.go",
    "discovery_cache.go",
    "discovery_config.go",
    "oidc_configuration.go",
    
    # Login/Auth handlers
    "login_handler.go",
    "login_types.go",
    "finish_login.go",
    "resolve_login_request.go",
    "mfa_handler.go",
    
    # Self-service handlers
    "handle_signup.go",
    "handle_email_change.go",
    "handle_password_reset.go",
    "handle_data_export.go",
    "handle_native_sso.go",
    
    # Me endpoints
    "me_handler.go",
    "me_mfa.go",
    "me_security.go",
    "me_sessions.go",
    
    # Admin/B2B
    "handlers_admin.go",
    "handlers_b2b.go",
    
    # Audit/Authz
    "audit_helpers.go",
    "authz_policy_bundle.go",
    
    # Security (should be in security/)
    "dpop.go",
    "mtls.go",
    "jar_security.go",
    "pairwise_client_assertion.go",
    
    # Cluster (should be in cluster/)
    "coordinated_key_rotation.go",
    "cross_replica_revocation.go",
    "invalidation_bus.go",
    
    # Tenant (should be in tenant/)
    "tenant_metrics.go",
    "tenant_residency.go",
    "tenant_residency_grant_gate.go",
    "tenant_revoke.go",
    
    # Other business logic
    "client_store_cache.go",
    "federation_handler.go",
    "federation_options.go",
    "home_realm.go",
    "protected_resource_metadata.go",
    "logging.go",
]

# Files that ARE allowed in root (server composition)
EXEMPT = {
    # Core server
    "interfaces/sso/sso.go",                      # Server struct + routes
    "interfaces/sso/handler.go",                  # Login orchestrator
    "interfaces/sso/handlers.go",                 # Discovery delegators
    "interfaces/sso/server_extensions.go",        # DPoP, mTLS, JAR, JWE, BCL, FCL
    "interfaces/sso/mesh_authz.go",               # Mesh authorization
    "interfaces/sso/signing_key_aggregation.go",  # Key aggregation loop
    "storage_health.go",           # Storage health check
    
    # Accessors & aliases
    "interfaces/sso/accessors.go",                # Field accessors for Deps
    "interfaces/sso/aliases.go",                  # Re-exports
    
    # Options (server configuration)
    "interfaces/sso/options.go",
    "interfaces/sso/options_misc.go",
    "interfaces/sso/options_passwd.go",
    "interfaces/sso/options_security.go",
    
    # Server internals
    "interfaces/sso/server_routes.go",            # Route registration
    "interfaces/sso/server_helpers.go",           # Internal helpers
    "interfaces/sso/server_validation.go",        # Validation logic
    "interfaces/sso/server_health.go",            # Health endpoints
    
    # Constants & types
    "types.go",
    "consts.go",
}


def run() -> int:
    root = Path.cwd()
    violations = []
    
    # Check banned patterns
    for pattern in BANNED_PATTERNS:
        for f in root.glob(pattern):
            if not f.is_file():
                continue
            if f.name in EXEMPT:
                continue
            # Allow server_*.go pattern (hexagonal adapters)
            if f.name.startswith("server_") and f.name.endswith(".go"):
                continue
            violations.append(f"  {f.name} (matches pattern {pattern})")
    
    # Check specific banned files
    for filename in BANNED_FILES:
        f = root / filename
        if f.is_file() and filename not in EXEMPT:
            # Allow server_*.go pattern (hexagonal adapters)
            if filename.startswith("server_") and filename.endswith(".go"):
                continue
            violations.append(f"  {filename} (business logic)")
    
    if violations:
        print(f"FAIL: {len(violations)} business code file(s) in root")
        print("\n".join(sorted(set(violations))))
        print("\n" + "="*70)
        print("Root Directory Policy Violation")
        print("="*70)
        print("\nRoot should only contain server composition files:")
        print("  - sso.go, handler.go, handlers.go")
        print("  - server_extensions.go, server_routes.go, server_helpers.go")
        print("  - accessors.go, aliases.go")
        print("  - options*.go")
        print("\nBusiness logic MUST be in domain packages:")
        print("  - oauth/      → OAuth handlers, grants")
        print("  - oidc/       → OIDC handlers, discovery")
        print("  - security/   → DPoP, mTLS, JAR")
        print("  - cluster/    → Coordination, invalidation")
        print("  - tenant/     → Tenant logic")
        print("  - selfservice/ → Signup, password reset, etc.")
        print("\nMigration strategy:")
        print("  1. Extract logic to pure functions in target package")
        print("  2. Keep thin wrapper methods in root")
        print("  3. Update Deps interface if needed")
        print("\nSee AGENTS.md §0.6 Root Directory Policy")
        return 1
    
    print("PASS: no business code in root")
    return 0


if __name__ == "__main__":
    sys.exit(run())
