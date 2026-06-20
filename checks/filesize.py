#!/usr/bin/env python3
"""File size gate: .go files must be <= 500 lines."""
import sys
from pathlib import Path

MAX_LINES = 500

IGNORE_PATTERNS = (
    "_test.go", "gen/proto/", ".claude/", "kms/", "redis/",
    "saml/", "ldap/", "kerberos/", "radius/", "extauthz/", "examples/",
)

EXEMPTIONS = [
    "interfaces/sso/accessors.go", "interfaces/sso/sso.go", "login_handler.go",
    "interfaces/sso/signing_key_aggregation.go", "client_store_cache.go",
    "cmd/sso-server/main.go", "cmd/sso-import/main.go",
    "cmd/sso-server/webauthn.go", "cmd/sso-server/build_stores.go",
    "cmd/sso-server/webauthn_test.go", "cmd/sso-server/mfa_test.go",
    "config/config.go",
    "infrastructure/defaultimpl/ed25519_jwt_issuer.go", "infrastructure/defaultimpl/ecdsa_jwt_issuer.go",
    "infrastructure/defaultimpl/rsa_jwt_issuer.go", "infrastructure/defaultimpl/vaulttransit/signer.go",
    "infrastructure/defaultimpl/push_mfa_provider.go", "infrastructure/defaultimpl/sqlite/clients.go",
    "infrastructure/defaultimpl/sqlite/refresh_tokens.go",
    "infrastructure/defaultimpl/vaulttransit/signer_test.go", "infrastructure/defaultimpl/push_mfa_provider_test.go",
    "infrastructure/defaultimpl/sqlite/clients_test.go",
    "shared/core/types.go", "shared/core/consts.go",
    "platform/audit/recorder_events.go", "platform/audit/sqlite/sink.go",
    "platform/metrics/metrics.go", "domains/anomaly/runner.go", "interfaces/snapshot/restorer.go",
    "domains/authenticators/webauthn/webauthn.go", "domains/authenticators/authenticators_test.go",
    "domains/permissions/sqlite/sqlite.go", "platform/signingkeys/etcd/etcd.go",
    "domains/tenant/sqlite/sqlite.go",
    "domains/federation/entity_statement.go", "domains/federation/trust_chain.go",
    "domains/federation/trust_marks.go", "domains/federation/registration.go",
    "domains/federation/metadata_policy.go", "domains/federation/constraints.go",
    "domains/federation/trust_chain_test.go", "domains/federation/trust_marks_test.go",
    "domains/federation/trust_marks_resolved_test.go", "domains/federation/trust_marks_resolved_dos_test.go",
    "domains/federation/registration_test.go", "domains/federation/constraints_test.go",
    "protocols/caep/receiver.go", "protocols/caep/receiver_test.go",
    "protocols/scim/handler.go", "protocols/scim/handler_test.go",
    "kms/azurekeyvault/signer.go", "kms/azurekeyvault/signer_test.go",
    "kms/pkcs11/signer_test.go", "kms/gcpkms/signer_test.go",
    "test/*.go", "interfaces/grpcserver/admin_tenants_test.go",
]


def is_exempt(path: Path, rel: str) -> bool:
    for e in EXEMPTIONS:
        if e.endswith("/*"):
            base = e[:-2]
            if rel.startswith(base):
                return True
        if e == rel or rel.endswith("/" + e):
            return True
    return False


def check_file(path: Path, root: Path) -> bool:
    if path.suffix != ".go":
        return True
    rel = str(path.relative_to(root))
    for pat in IGNORE_PATTERNS:
        if pat in rel:
            return True
    if is_exempt(path, rel):
        return True
    lines = len(path.read_text().splitlines())
    if lines > MAX_LINES:
        print(f"  FAIL: {rel} ({lines} lines, max {MAX_LINES})")
        return False
    return True


def run(files: list[Path] | None = None) -> int:
    root = Path.cwd()
    if files:
        ok = all(check_file(f, root) for f in files)
    else:
        go_files = sorted(root.rglob("*.go"))
        ok = True
        for f in go_files:
            rel = str(f.relative_to(root))
            if "/.git/" in rel or "/.claude/" in rel:
                continue
            if not check_file(f, root):
                ok = False
    if ok:
        print("PASS: filesize")
        return 0
    print("FAIL: split before continuing")
    return 1


if __name__ == "__main__":
    args = [Path(a) for a in sys.argv[1:]] if len(sys.argv) > 1 else None
    sys.exit(run(args))
