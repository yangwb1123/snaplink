#!/usr/bin/env python3
"""Fail when a statically registered SSO route is absent from OpenAPI."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
ROUTE_DIR = Path("interfaces/sso")
OPENAPI_FILE = Path("docs/openapi.yaml")
METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
ROUTE_RECEIVERS = frozenset({"s.router", "api", "gr", "ssf", "selfServiceGR"})
ADMIN_PREFIX = "/api/v1"
ROUTE_CALL = re.compile(
    r"\b([A-Za-z_][\w.]*)\.(GET|POST|PUT|PATCH|DELETE)"
    r"\(\s*([^,\n]+)"
)
TEMPLATE_PARAM = re.compile(r"\{([^}]+)\}")

# Server.Handle accepts embedder-owned paths at runtime, so its local `path`
# argument cannot be represented in the stock server's static OpenAPI.
DYNAMIC_EXPRESSIONS = frozenset({"path"})

# These two intentionally remain private implementation constants. Their
# literal values are stable API paths and are included in the static contract.
PRIVATE_PATHS = {
    "pathAdminAPIDocs": "/admin/docs",
    "pathAdminAPIDocsSpec": "/admin/docs/openapi.json",
}

# Probes are mounted outside the SSO Router so kubelet traffic bypasses the
# rate-limit stack. Include them explicitly in the same contract gate.
OUT_OF_ROUTER_ROUTES = frozenset({
    ("GET", "/livez"),
    ("GET", "/readyz"),
})


@dataclass(frozen=True)
class RouteCall:
    source: str
    receiver: str
    method: str
    expression: str


def discover_route_calls(root: Path = ROOT) -> list[RouteCall]:
    """Collect static Router method calls from production SSO source files."""
    calls: list[RouteCall] = []
    route_dir = root / ROUTE_DIR
    for source in sorted(route_dir.glob("*.go")):
        if source.name.endswith("_test.go"):
            continue
        for match in ROUTE_CALL.finditer(source.read_text()):
            receiver, method, expression = match.groups()
            if receiver not in ROUTE_RECEIVERS:
                continue
            calls.append(RouteCall(
                source=source.name,
                receiver=receiver,
                method=method,
                expression=expression.strip(),
            ))
    return calls


def _go_reference(expression: str) -> str:
    if "." not in expression:
        if not expression.startswith("Path"):
            raise ValueError(f"unsupported route expression {expression!r}")
        return f"sso.{expression}"
    package, _, name = expression.partition(".")
    if package not in {"core", "oauth"} or not name.startswith("Path"):
        raise ValueError(f"unsupported route expression {expression!r}")
    return expression


def _resolver_source(expressions: set[str]) -> str:
    entries = [
        f"{json.dumps(expression)}: {_go_reference(expression)},"
        for expression in sorted(expressions)
    ]
    return "\n".join([
        "package main",
        "",
        "import (",
        '\t"encoding/json"',
        '\t"os"',
        "",
        '\tsso "github.com/yangwb1123/snaplink/interfaces/sso"',
        '\tcore "github.com/yangwb1123/snaplink/shared/core"',
        '\toauth "github.com/yangwb1123/snaplink/protocols/oauth"',
        ")",
        "",
        "func main() {",
        "\tvalues := map[string]string{",
        *[f"\t\t{entry}" for entry in entries],
        "\t}",
        "\t_ = json.NewEncoder(os.Stdout).Encode(values)",
        "}",
    ])


def resolve_route_expressions(
    calls: list[RouteCall],
    root: Path = ROOT,
) -> dict[str, str]:
    """Compile route constants so aliases and concatenations cannot drift."""
    expressions = {
        call.expression
        for call in calls
        if call.expression not in DYNAMIC_EXPRESSIONS
        and call.expression not in PRIVATE_PATHS
    }
    source = _resolver_source(expressions)
    with tempfile.TemporaryDirectory(prefix="snaplink-route-contract-") as tmp:
        helper = Path(tmp) / "main.go"
        helper.write_text(source)
        result = subprocess.run(
            ["go", "run", str(helper)],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
    if result.returncode != 0:
        raise RuntimeError(
            "route constant resolver failed:\n" + result.stderr.strip()
        )
    values = json.loads(result.stdout)
    values.update(PRIVATE_PATHS)
    return values


def runtime_routes(
    calls: list[RouteCall],
    values: dict[str, str],
) -> dict[tuple[str, str], set[str]]:
    """Return route keys with every source file that registers each one."""
    routes: dict[tuple[str, str], set[str]] = {
        route: {"probe mux"} for route in OUT_OF_ROUTER_ROUTES
    }
    for call in calls:
        if call.expression in DYNAMIC_EXPRESSIONS:
            continue
        path = values[call.expression]
        if call.receiver == "api":
            path = ADMIN_PREFIX + path
        routes.setdefault((call.method, path), set()).add(call.source)
    return routes


def _normalize_openapi_path(path: str) -> str:
    return TEMPLATE_PARAM.sub(lambda match: ":" + match.group(1), path)


def openapi_operations(
    root: Path = ROOT,
) -> tuple[set[tuple[str, str]], list[str]]:
    """Load documented operations and return operation-id contract errors."""
    document = yaml.safe_load((root / OPENAPI_FILE).read_text())
    operations: set[tuple[str, str]] = set()
    operation_ids: dict[str, tuple[str, str]] = {}
    errors: list[str] = []
    for path, item in document.get("paths", {}).items():
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            upper = method.upper()
            if upper not in METHODS:
                continue
            key = (upper, _normalize_openapi_path(path))
            operations.add(key)
            operation_id = operation.get("operationId") if operation else None
            if not operation_id:
                errors.append(f"{upper} {path}: missing operationId")
                continue
            previous = operation_ids.get(operation_id)
            if previous:
                errors.append(
                    f"duplicate operationId {operation_id!r}: "
                    f"{previous[0]} {previous[1]} and {upper} {path}"
                )
            operation_ids[operation_id] = (upper, path)
    return operations, errors


def missing_route_errors(
    routes: dict[tuple[str, str], set[str]],
    documented: set[tuple[str, str]],
) -> list[str]:
    errors = []
    for method, path in sorted(set(routes) - documented):
        sources = ", ".join(sorted(routes[(method, path)]))
        errors.append(f"{method} {path}: undocumented (registered in {sources})")
    return errors


def contract_errors(root: Path = ROOT) -> tuple[list[str], int, int]:
    calls = discover_route_calls(root)
    values = resolve_route_expressions(calls, root)
    routes = runtime_routes(calls, values)
    documented, errors = openapi_operations(root)
    errors.extend(missing_route_errors(routes, documented))
    return errors, len(routes), len(documented)


def run() -> int:
    try:
        errors, route_count, operation_count = contract_errors(ROOT)
    except (OSError, RuntimeError, ValueError, yaml.YAMLError) as exc:
        print(f"FAIL: route/OpenAPI contract check could not run: {exc}")
        return 1
    if errors:
        print("FAIL: route/OpenAPI contract drift")
        for error in errors:
            print(f"  - {error}")
        return 1
    print(
        "PASS: route/OpenAPI contract "
        f"({route_count} runtime routes, {operation_count} documented operations)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(run())
