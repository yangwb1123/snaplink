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
    "accessors.go", "sso.go", "login_handler.go",
    "signing_key_aggregation.go", "client_store_cache.go",
    "cmd/sso-server/main.go", "cmd/sso-import/main.go",
    "cmd/sso-server/webauthn.go", "cmd/sso-server/build_stores.go",
    "cmd/sso-server/webauthn_test.go", "cmd/sso-server/mfa_test.go",
    "config/config.go",
    "defaultimpl/ed25519_jwt_issuer.go", "defaultimpl/ecdsa_jwt_issuer.go",
    "defaultimpl/rsa_jwt_issuer.go", "defaultimpl/vaulttransit/signer.go",
    "defaultimpl/push_mfa_provider.go", "defaultimpl/sqlite/clients.go",
    "defaultimpl/sqlite/refresh_tokens.go",
    "defaultimpl/vaulttransit/signer_test.go", "defaultimpl/push_mfa_provider_test.go",
    "defaultimpl/sqlite/clients_test.go",
    "core/types.go", "core/consts.go",
    "audit/recorder_events.go", "audit/sqlite/sink.go",
    "metrics/metrics.go", "anomaly/runner.go", "snapshot/restorer.go",
    "authenticators/webauthn/webauthn.go", "authenticators/authenticators_test.go",
    "permissions/sqlite/sqlite.go", "signingkeys/etcd/etcd.go",
    "tenant/sqlite/sqlite.go",
    "federation/entity_statement.go", "federation/trust_chain.go",
    "federation/trust_marks.go", "federation/registration.go",
    "federation/metadata_policy.go", "federation/constraints.go",
    "federation/trust_chain_test.go", "federation/trust_marks_test.go",
    "federation/trust_marks_resolved_test.go", "federation/trust_marks_resolved_dos_test.go",
    "federation/registration_test.go", "federation/constraints_test.go",
    "caep/receiver.go", "caep/receiver_test.go",
    "scim/handler.go", "scim/handler_test.go",
    "kms/azurekeyvault/signer.go", "kms/azurekeyvault/signer_test.go",
    "kms/pkcs11/signer_test.go", "kms/gcpkms/signer_test.go",
    "test/*.go", "grpcserver/admin_tenants_test.go",
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
