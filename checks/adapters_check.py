#!/usr/bin/env python3
"""Fail when the adapters delivery contract loses its executable evidence.

The contract lives in docs/adapters.md; its evidence is the routertest
conformance suite, the router-backend e2e matrix, and the embed examples.
This check pins all of them plus the line budgets, and runs the suite and
matrix behaviorally (no -race; race coverage lives in `make ci`'s race
target and `make test-e2e`).
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CONFORMANCE_FILE = ROOT / "interfaces/adapters/routertest/conformance.go"
GIN_CONFORMANCE = ROOT / "interfaces/adapters/gin/conformance_test.go"
ECHO_CONFORMANCE = ROOT / "interfaces/adapters/echo/conformance_test.go"
MATRIX_FILE = ROOT / "test/router_backend_matrix_test.go"
TESTKIT_FILE = ROOT / "test/testkit/testkit.go"
ADAPTERS_DOC = ROOT / "docs/adapters.md"
EMBED_DIRS = [ROOT / "docs/examples/embed-gin", ROOT / "docs/examples/embed-echo"]
ERROR_CODES_DOC = ROOT / "docs/error-codes.md"
STRIPE_ERROR_SECTION_HEADING = "## Stripe payment adapter"
WIRE_CODE_ANCHOR = "// Wire error codes are exported"
WIRE_CODE_MODEL = ROOT / "cmd/snaplink-stripe-adapter/model.go"
# Frozen floor: today's exported block size; shrink-only, never grows a name
# pin — the tenant-claim direction adds ErrTenantMismatch, so the floor
# exists only so an extraction regression that empties the block fails
# loudly instead of passing a vacuous subset check.
WIRE_CODE_FLOOR = 8
# Pinned, not @latest: a ci-blocking gate must not silently change behavior
# on a kin-openapi release (docs-validate may float — it is not in make ci).
KIN_OPENAPI_VALIDATE = "github.com/getkin/kin-openapi/cmd/validate@v0.146.0"
LINE_CAP = 500

# The routertest scenario inventory, pinned. Removing a scenario fails this
# check by design — changing the contract means changing this list AND
# docs/adapters.md §6 together.
CONFORMANCE_SCENARIOS = [
    "FiveMethodDispatch",
    "PathParamsAndQuery",
    "UnknownPath_ByteIdenticalToHTTPNotFound",
    "MethodMismatch_ByteIdenticalToHTTPNotFound",
    "HeadOnGetRoute_ByteIdenticalToHTTPNotFound",
    "OptionsOnKnownPath_ByteIdenticalToHTTPNotFound",
    "TrailingSlash_ByteIdenticalToHTTPNotFound",
    "MiddlewareOrderAndAbort_HandlerNotRun",
    "GroupPrefix_InheritsMiddleware",
    "UseAfterRegister_DoesNotAffectRegisteredRoutes",
    "GateOff_ByteIdenticalToNeverMounted",
    "GateOff_SkipsGlobalMiddleware_NoHeaderLeak",
    "GatedGroup_PreservesGate",
    "GateOn_ServesRoute",
]

# docs/adapters.md §1-§6 headings, pinned by the check so the declared
# contract cannot silently lose a section.
CONTRACT_SECTIONS = [
    "## 1. Supported backends",
    "## 2. Unmatched-response normalization",
    "## 3. `WithFrameworkNotFound` and embedder overrides",
    "## 4. `GatedRegistrar` / `RegisterGated`",
    "## 5. Capture primitives",
    "## 6. Enforcement",
]

SCENARIO_RE = re.compile(r'\{"([A-Za-z0-9_]+)",')

# Wire-code consts in the anchored block: Err<Name> = "<code>". Tolerates
# any whitespace around = (gofmt alignment churn).
WIRE_CONST_RE = re.compile(r"\bErr([A-Za-z0-9_]+)\s*=\s*\"([^\"]+)\"")


def wire_code_consts(source: str) -> list[tuple[str, str]] | None:
    """Extract (constName, wireCode) from the anchored wire-code const block.

    Fail-closed: returns None when the anchor comment or its const block is
    missing, so a refactor that renames/removes the registry fails the gate
    instead of passing on an empty extraction.
    """
    anchor = source.find(WIRE_CODE_ANCHOR)
    if anchor < 0:
        return None
    block_start = source.find("const (", anchor)
    if block_start < 0:
        return None
    block_end = source.find(")", block_start)
    if block_end < 0:
        return None
    return WIRE_CONST_RE.findall(source[block_start:block_end])


def stripe_error_rows(doc: str) -> set[str]:
    """Backticked codes from | code | rows inside the Stripe section only.

    Section = lines from the Stripe heading up to the next '## ' heading.
    A code mentioned in prose, or as a row in any other section, does not
    count — the row must live in the Stripe table.
    """
    lines = doc.splitlines()
    start = next(
        (i for i, line in enumerate(lines)
         if line.startswith(STRIPE_ERROR_SECTION_HEADING)),
        None,
    )
    if start is None:
        return set()
    rows: set[str] = set()
    for line in lines[start + 1:]:
        if line.startswith("## "):
            break
        match = re.match(r"\| `([^`]+)` \|", line)
        if match:
            rows.add(match.group(1))
    return rows


def missing_code_rows(codes: list[tuple[str, str]], rows: set[str]) -> list[str]:
    """Exported wire codes without a Stripe-section row. One-directional."""
    return [f"{name} ({code})" for name, code in codes if code not in rows]


def scenario_inventory(source: str) -> list[str]:
    """Extract the scenario names from the suite's scenario table literal.

    Fail-closed: a refactor that breaks the table shape yields an empty or
    partial list and fails the pinned comparison instead of passing.
    """
    return SCENARIO_RE.findall(source)


def run() -> int:
    """Static presence + budget checks. Returns 0 when the contract holds."""
    failures: list[str] = []

    # (a) conformance suite exists and its scenario inventory matches.
    if not CONFORMANCE_FILE.is_file():
        failures.append("routertest conformance.go missing")
    else:
        found = scenario_inventory(CONFORMANCE_FILE.read_text())
        if found != CONFORMANCE_SCENARIOS:
            failures.append(
                f"routertest scenario inventory drift: found {found}, want {CONFORMANCE_SCENARIOS}"
            )

    # (b) suite wired into gin AND echo via public constructors.
    for path, ctor in ((GIN_CONFORMANCE, "NewGinRouter("), (ECHO_CONFORMANCE, "NewEchoRouter(")):
        text = path.read_text() if path.is_file() else ""
        if "routertest.ConformanceSuite{" not in text or ctor not in text:
            failures.append(f"{path.name} does not wire ConformanceSuite via {ctor}")

    # (c) matrix e2e exists, names all three backends, and testkit passes
    # the injected router through to sso.NewServer.
    matrix = MATRIX_FILE.read_text() if MATRIX_FILE.is_file() else ""
    for token in ("TestRouterBackendMatrix", "NewStdRouter", "NewGinRouter", "NewEchoRouter"):
        if token not in matrix:
            failures.append(f"matrix missing {token}")
    if "WithRouter" not in TESTKIT_FILE.read_text():
        failures.append("testkit does not expose the WithRouter pass-through")
    if len(matrix.splitlines()) > LINE_CAP:
        failures.append(f"router_backend_matrix_test.go exceeds {LINE_CAP} lines")

    # (d) + (e) embed examples compile and use public constructors only.
    for d in EMBED_DIRS:
        if not d.is_dir():
            failures.append(f"{d.name} example missing")
            continue
        files = list(d.glob("*.go"))
        if sum(len(p.read_text().splitlines()) for p in files) > LINE_CAP:
            failures.append(f"{d.name} exceeds {LINE_CAP} lines total")
        src = "".join(p.read_text() for p in files)
        ctor = "NewGinRouter(" if d.name == "embed-gin" else "NewEchoRouter("
        if ctor not in src:
            failures.append(f"{d.name} does not use the public {ctor} constructor")
        if "WithFrameworkNotFound" in src:
            failures.append(f"{d.name} uses WithFrameworkNotFound (byte-identity opt-out)")

    # (f) docs/adapters.md exists and covers the contract sections + backends.
    doc = ADAPTERS_DOC.read_text() if ADAPTERS_DOC.is_file() else ""
    for section in CONTRACT_SECTIONS:
        if section not in doc:
            failures.append(f"docs/adapters.md missing section {section}")
    for token in ("std", "gin", "echo"):
        if token not in doc:
            failures.append(f"docs/adapters.md does not list backend {token}")

    # (g) every cmd/*/openapi.yaml must pass the same kin-openapi validation
    # that make docs-validate applies to docs/openapi.yaml — the adapter's
    # separate contract can no longer rot unnoticed.
    nested_openapi = sorted(ROOT.glob("cmd/*/openapi.yaml"))
    if not nested_openapi:
        failures.append("no cmd/*/openapi.yaml found (adapter OpenAPI contract missing)")
    for path in nested_openapi:
        result = subprocess.run(
            ["go", "run", KIN_OPENAPI_VALIDATE, str(path)],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        if result.returncode != 0:
            failures.append(
                f"{path.relative_to(ROOT)} fails kin-openapi validation:\n"
                + result.stderr.strip()
            )

    # (h) every exported wire-code const in the adapter's anchored block must
    # appear as a | code | row in the error-codes.md Stripe section.
    model = WIRE_CODE_MODEL.read_text() if WIRE_CODE_MODEL.is_file() else ""
    codes = wire_code_consts(model) if model else None
    if codes is None:
        failures.append("stripe adapter wire-code const block missing or unanchored")
    else:
        if len(codes) < WIRE_CODE_FLOOR:
            failures.append(
                f"wire-code const block shrank below {WIRE_CODE_FLOOR} entries"
            )
        doc = ERROR_CODES_DOC.read_text() if ERROR_CODES_DOC.is_file() else ""
        for entry in missing_code_rows(codes, stripe_error_rows(doc)):
            failures.append(
                f"exported wire code {entry} has no | code | row in the "
                f"error-codes.md Stripe section"
            )

    if failures:
        for f in failures:
            print(f"adapters-check: FAIL: {f}")
        return 1
    print("adapters-check: static contract OK")
    return 0


def run_behavioral() -> int:
    """(g) run the conformance suite and the matrix without -race."""
    cmds = [
        ["go", "test", "./interfaces/adapters/gin/", "./interfaces/adapters/echo/",
         "-run", "Conformance", "-count=1"],
        ["go", "test", "./test/", "-run", "TestRouterBackendMatrix", "-count=1"],
    ]
    for cmd in cmds:
        result = subprocess.run(cmd, cwd=ROOT)
        if result.returncode != 0:
            return result.returncode
    print("adapters-check: conformance suite + matrix green")
    return 0


if __name__ == "__main__":
    ec = run()
    if ec == 0:
        ec = run_behavioral()
    sys.exit(ec)
