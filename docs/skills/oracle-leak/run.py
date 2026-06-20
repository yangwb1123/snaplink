#!/usr/bin/env python3
import argparse, re, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

LEAKS = {
    r"ErrNoSuch(AuthCode|RefreshToken|DeviceCode|PAR|Session)": "POTENTIAL LEAK: type-specific err reveals store",
    r"sql\.ErrNoRows": "POTENTIAL LEAK: raw sql err reveals missing row",
    r"errors\.New\(\"unknown (client|user|session)": "POTENTIAL LEAK: reveals unknown entity type",
}
REQUIRED = {
    r"tokenNoStoreHeaders": "REQUIRED: no-store headers on credential endpoint",
    r"setBearerChallenge": "REQUIRED: WWW-Authenticate on 401",
    r"SetMeta": "REQUIRED: use SetMeta for audit, not direct Metadata map",
}
ORACLE_SAFE = {
    r"invalid_grant": "Oracle-safe: unified error for unknown/expired/consumed",
    r"invalid_request_uri": "Oracle-safe: stale/missing PAR",
    r"mfa_invalid": "Oracle-safe: unknown/expired MFA",
    r"session_invalid": "Oracle-safe: unknown WebAuthn session",
}

def review(fp: Path):
    if not fp.exists():
        print(f"ERROR: {fp} not found", file=sys.stderr); return 1
    content = fp.read_text(); lines = content.split("\n"); findings = []
    for i, line in enumerate(lines, 1):
        s = line.strip()
        if not s or s.startswith("//") or s.startswith("/*"):
            continue
        for pat, reason in LEAKS.items():
            if re.search(pat, s): findings.append(("LEAK", i, s[:80], reason))
        for pat, reason in REQUIRED.items():
            if re.search(pat, s): findings.append(("GOOD", i, s[:80], reason))
        for pat, reason in ORACLE_SAFE.items():
            if re.search(pat, s): findings.append(("INFO", i, s[:80], reason))
    print(f"=== Oracle-Leak Review: {fp} ===")
    if not findings:
        print("No patterns found"); return 0
    icon = {"LEAK": chr(9888), "GOOD": chr(10003), "INFO": chr(8505)}
    for kind, line, text, reason in findings:
        print(f"  {icon[kind]} [{kind}] line {line}: {reason}")
        print(f"           {text}")
    leaks = [f for f in findings if f[0] == "LEAK"]
    if leaks:
        print(f"\nFAIL: {len(leaks)} potential oracle leak(s)"); return 1
    return 0

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("file", nargs="*", type=str)
    args = p.parse_args()
    if args.file:
        results = [review(Path(f)) for f in args.file]
    else:
        from shared.git import changed_files
        results = [review(f) for f in changed_files() if f.suffix == ".go"]
    sys.exit(1 if any(r != 0 for r in results) else 0)
