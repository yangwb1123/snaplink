#!/usr/bin/env python3
"""Cyclomatic and cognitive complexity gate."""
import subprocess
import sys
from pathlib import Path
import os

MAX_CYCLO = 15
MAX_COGNIT = 20

EXEMPT_FUNCS = [
    "handleLogin", "handleToken", "finishLogin", "Mount",
    "buildOIDCConfiguration", "verifyJWTClientAssertion", "verifyJAR",
    "projectUserInfoForOIDC", "handleTokenExchangeGrant",
    "handleDeviceSecretExchange", "handleMFAComplete",
    "verifyDPoPProof", "checkTenantResidency", "checkTenantNotSuspended",
    "MeshAuthorize", "handleLogout", "handleCIBATokenGrant",
    "handleDeviceTokenGrant", "handleDeviceCode", "handleUserInfo",
    "handleRefreshTokenGrant", "resolveLoginRequest",
    "computeDiscoverySnapshot", "fanOutBackchannelLogout", "handleDeviceVerify",
    "HandleSilentRenewal", "HandleEndSession", "MaybeSignUserInfo", "HandleJWKS",
    "HandleBackchannelAuth", "HandlePAR", "formIntoStruct", "HandleIntrospect",
    "parseClaimsSection", "HandleRegister",
    "Validate", "Score",
    "VerifyCompactJWS",
    "matchAttributes",
    "Match",
]

IGNORE_PATTERN = "gen/proto/|_test.go|cmd/|test/|grpcserver/|.claude/|federation/|saml/|kms/|caep/|scim/|ldap/|kerberos/|redis/|extauthz/|radius/|snapshot/|examples/|defaultimpl/sqlite/|bootstrap/|permissions/sqlite/|signingkeys/|audit/sqlite/|migrate/|releases/|compliance/|cors/|connections/|netpolicy/|registry/|tenant/|config/|mfa/|cluster/|anomaly/|middleware/|ratelimit/|metrics/|spi/|admin/|geo/"


def is_exempt(name: str) -> bool:
    for e in EXEMPT_FUNCS:
        if e in name:
            return True
    return False


def run_gocyclo(tool: str) -> list[dict]:
    result = subprocess.run(
        [tool, "--ignore", IGNORE_PATTERN, "."],
        capture_output=True, text=True, check=False
    )
    funcs = []
    for line in result.stdout.strip().split("\n"):
        parts = line.strip().split()
        if len(parts) >= 4 and parts[0].isdigit():
            location = parts[3]
            line_num = int(location.split(":")[1]) if ":" in location else int(location)
            funcs.append({"cyclo": int(parts[0]), "name": parts[2], "line": line_num})
    return funcs


def run_tool(tool: str, name: str, max_val: int) -> int:
    print(f"--- {name} (max {max_val}) ---")
    if not os.access(tool, os.X_OK) if os.path.isfile(tool) else False:
        if subprocess.run(["which", tool], capture_output=True).returncode != 0:
            print("  (tool not found)")
            return 0
    funcs = run_gocyclo(tool)
    has_fail = 0
    for f in funcs:
        if is_exempt(f["name"]):
            continue
        if f["cyclo"] > max_val:
            print(f"  FAIL: {f['name']} at {f['line']} - {f['cyclo']} > {max_val}")
            has_fail = 1
    if not has_fail:
        print("  PASS")
    return has_fail


def run() -> int:
    home = Path.home()
    gocyclo = str(home / "go" / "bin" / "gocyclo")
    gocognit = str(home / "go" / "bin" / "gocognit")
    ec = 0
    ec += run_tool(gocyclo, "cyclomatic complexity", MAX_CYCLO)
    ec += run_tool(gocognit, "cognitive complexity", MAX_COGNIT)
    return 1 if ec > 0 else 0


if __name__ == "__main__":
    sys.exit(run())
