#!/usr/bin/env python3
import re, subprocess, sys

VIOLATION_FIXES = [
    (re.compile(r"oauth.*imports.*oidc"), "oidc", "Move shared type to core/, route via handlers.go"),
    (re.compile(r"oidc.*imports.*oauth"), "oauth", "Move shared type to core/, route via handlers.go"),
    (re.compile(r"security.*imports.*defaultimpl"), "defaultimpl", "Extract SPI to security/, pass via With*"),
    (re.compile(r"oidc.*imports.*defaultimpl"), "defaultimpl", "Extract SPI to oidc/, pass via With*"),
    (re.compile(r"cmd.*imports"), "cmd", "cmd/ must only be a main entry"),
]

def run():
    r = subprocess.run(["bash", ".check-architecture.sh"], capture_output=True, text=True, check=False)
    output = r.stdout + r.stderr
    violations = [l.strip() for l in output.split("\n") if "imports" in l.lower() and "FAIL" in l]
    violations += [l.strip() for l in output.split("\n") if "forbidden" in l.lower() and ":" in l]
    if not violations:
        print("No architecture violations detected"); return 0
    print(f"=== {len(violations)} Architecture Violation(s) ===")
    for v in violations:
        print(f"\n  VIOLATION: {v}")
        for pat, target, fix in VIOLATION_FIXES:
            if pat.search(v):
                print(f"  TARGET: {target}")
                print(f"  FIX:    {fix}")
                break
        else:
            print(f"  FIX:    (unknown -- check manually)")
    print("\nApproach: identify shared type -> move to core/ or extract SPI -> wire via With*")
    print("Then: bash .check-architecture.sh && make acceptance")
    return 1

if __name__ == "__main__":
    sys.exit(run())
