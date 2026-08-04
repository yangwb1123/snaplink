from pathlib import Path

import yaml

from checks.route_contract import (
    RouteCall,
    discover_route_calls,
    missing_route_errors,
    openapi_operations,
    runtime_routes,
)


def test_discover_route_calls_uses_production_sso_files_only(tmp_path: Path):
    route_dir = tmp_path / "interfaces" / "sso"
    route_dir.mkdir(parents=True)
    (route_dir / "routes.go").write_text(
        "package sso\nfunc mount() { s.router.GET(PathHealth, handler) }\n"
    )
    (route_dir / "routes_test.go").write_text(
        "package sso\nfunc testMount() { s.router.POST(PathToken, handler) }\n"
    )

    calls = discover_route_calls(tmp_path)

    assert calls == [
        RouteCall("routes.go", "s.router", "GET", "PathHealth"),
    ]


def test_runtime_routes_applies_admin_prefix_and_skips_extensions():
    calls = [
        RouteCall("admin.go", "api", "GET", "PathAdminUsers"),
        RouteCall("routes.go", "s.router", "POST", "PathToken"),
        RouteCall("routes.go", "s.router", "GET", "path"),
    ]
    values = {
        "PathAdminUsers": "/admin/users",
        "PathToken": "/token",
    }

    routes = runtime_routes(calls, values)

    assert ("GET", "/api/v1/admin/users") in routes
    assert ("POST", "/token") in routes
    assert all(path != "path" for _, path in routes)


def test_openapi_operations_rejects_missing_and_duplicate_ids(tmp_path: Path):
    docs = tmp_path / "docs"
    docs.mkdir()
    spec = {
        "paths": {
            "/users/{id}": {
                "get": {"operationId": "getUser"},
                "delete": {},
            },
            "/accounts/{id}": {
                "get": {"operationId": "getUser"},
            },
        },
    }
    (docs / "openapi.yaml").write_text(yaml.safe_dump(spec))

    operations, errors = openapi_operations(tmp_path)

    assert ("GET", "/users/:id") in operations
    assert any("missing operationId" in error for error in errors)
    assert any("duplicate operationId" in error for error in errors)


def test_missing_route_errors_names_registration_source():
    routes = {
        ("GET", "/documented"): {"routes.go"},
        ("POST", "/missing"): {"admin.go"},
    }

    errors = missing_route_errors(routes, {("GET", "/documented")})

    assert errors == ["POST /missing: undocumented (registered in admin.go)"]


def test_repository_runtime_routes_are_documented():
    from checks.route_contract import contract_errors

    errors, route_count, operation_count = contract_errors()

    assert route_count >= 220
    assert operation_count >= route_count
    assert errors == []
