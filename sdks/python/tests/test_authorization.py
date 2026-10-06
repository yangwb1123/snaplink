"""Cross-language conformance for the permission-holding rule.

The cases in ``ops/build/sdk-conformance/authorization.json`` are the shared
contract. A client rule that disagrees with the server is worse than no rule at
all: it hides controls the server would grant and shows controls it would deny,
so the rule is implemented once here and asserted against one fixture.
"""

from __future__ import annotations

import json
import pathlib
import unittest
from typing import Any, Dict, List

from snaplink_sso import Authorization, MenuNode, SSOClient, holds, read_authorization

FIXTURE = (
    pathlib.Path(__file__).resolve().parents[3]
    / "ops"
    / "build"
    / "sdk-conformance"
    / "authorization.json"
)


def fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class HoldsRuleTest(unittest.TestCase):
    def test_fixture_is_reachable_and_populated(self) -> None:
        self.assertTrue(fixture()["cases"])

    def test_every_rule_case_matches_the_contract(self) -> None:
        for case in fixture()["cases"]:
            with self.subTest(case=case["id"]):
                self.assertEqual(
                    case["expect"],
                    holds(case["held"], case["required"]),
                    f"{case['id']}: holds({case['held']!r}, {case['required']!r})",
                )

    def test_the_fixture_is_exhaustive_about_the_wildcard_boundary(self) -> None:
        """These are the cases a hand-rolled rule gets wrong."""
        ids = {case["id"] for case in fixture()["cases"]}
        for required in (
            "exact_match",
            "absent_permission_is_denied",
            "domain_wildcard_does_not_match_a_similar_looking_domain",
            "a_bare_star_grants_everything",
            "an_unqualified_permission_is_never_a_prefix",
            "an_empty_requirement_is_always_granted",
        ):
            self.assertIn(required, ids)


class MenuProjectionTest(unittest.TestCase):
    def _node(self, permission: str, children: List[MenuNode] = None, buttons=None) -> MenuNode:
        return MenuNode(
            id=f"n-{permission or 'none'}",
            name=permission,
            permission=permission,
            children=tuple(children or ()),
            buttons=tuple(buttons or ()),
        )

    def test_a_node_with_no_permission_is_always_visible(self) -> None:
        self.assertTrue(MenuNode().is_visible([]))
        self.assertTrue(MenuNode(permission="").is_visible([]))

    def test_a_node_is_visible_when_its_permission_is_held(self) -> None:
        self.assertTrue(self._node("panel:read").is_visible(["panel:read"]))
        self.assertTrue(self._node("panel:config:apply").is_visible(["panel:*"]))
        self.assertFalse(self._node("panel:write").is_visible(["panel:read"]))

    def test_buttons_are_filtered_by_the_same_rule(self) -> None:
        from snaplink_sso import MenuButton

        node = MenuNode(
            id="users",
            name="Users",
            buttons=(
                MenuButton(code="create", name="New", permission="panel:inbound:write"),
                MenuButton(code="delete", name="Delete", permission="panel:*"),
                MenuButton(code="help", name="Help"),
            ),
        )
        codes = lambda permissions: [b.code for b in node.actions(permissions)]
        self.assertEqual(["create", "help"], codes(["panel:inbound:write"]))
        self.assertEqual(["create", "delete", "help"], codes(["panel:*"]))
        self.assertEqual(["help"], codes([]))

    def test_a_hidden_parent_takes_its_children_with_it(self) -> None:
        tree = (
            self._node("panel:*", children=[self._node("panel:read")]),
            self._node("", children=[self._node("")]),
        )
        authorization = Authorization(subject="u", permissions=(), menus=tree)
        self.assertEqual(
            ["n-none"], [node.id for node in authorization.visible_menus()],
            "a parent whose own permission is denied is dropped with its children",
        )
        granted = Authorization(subject="u", permissions=("panel:*",), menus=tree)
        visible = granted.visible_menus()
        self.assertEqual(["n-panel:*", "n-none"], [node.id for node in visible])
        self.assertEqual(["n-panel:read"], [child.id for child in visible[0].children])

    def test_surviving_buttons_are_narrowed(self) -> None:
        from snaplink_sso import MenuButton

        tree = (
            MenuNode(
                id="users",
                name="Users",
                buttons=(
                    MenuButton(code="create", permission="panel:inbound:write"),
                    MenuButton(code="help"),
                ),
            ),
        )
        authorization = Authorization(subject="u", permissions=("panel:read",), menus=tree)
        self.assertEqual(["help"], [b.code for b in authorization.visible_menus()[0].buttons])

    def test_allows_uses_the_same_rule(self) -> None:
        authorization = Authorization(subject="u", permissions=("panel:*",))
        self.assertTrue(authorization.allows("panel:config:apply"))
        self.assertFalse(authorization.allows("other:read"))
        self.assertTrue(authorization.allows(""), "an empty requirement is always granted")


class _StubClient(SSOClient):
    """A generated client whose four reads are asserted rather than sent."""

    def __init__(self, bodies: Dict[str, Any]) -> None:
        self.bodies = bodies
        self.calls: List[Dict[str, Any]] = []

    def get_userinfo(self, query=None) -> Any:  # type: ignore[override]
        self.calls.append({"path": "/userinfo", "query": query})
        return self.bodies["/userinfo"]

    def get_my_permissions(self, query=None) -> Any:  # type: ignore[override]
        self.calls.append({"path": "/permissions/me", "query": query})
        return self.bodies["/permissions/me"]

    def get_my_roles(self, query=None) -> Any:  # type: ignore[override]
        self.calls.append({"path": "/roles/me", "query": query})
        return self.bodies["/roles/me"]

    def get_my_menus(self, query=None) -> Any:  # type: ignore[override]
        self.calls.append({"path": "/menus/me", "query": query})
        return self.bodies["/menus/me"]


class ReadAuthorizationTest(unittest.TestCase):
    def _bodies(self) -> Dict[str, Any]:
        return {
            "/userinfo": {"sub": "user-alice", "email": "alice@example.test", "name": "Alice"},
            "/permissions/me": {
                "permissions": [{"code": "panel:read"}, "panel:config:apply", {"code": ""}]
            },
            "/roles/me": {"roles": [{"code": "panel-viewer"}]},
            "/menus/me": {"menus": [{"id": "m", "name": "Inbounds", "permission": "panel:read"}]},
        }

    def test_identity_permissions_roles_and_menus_are_read_together(self) -> None:
        client = _StubClient(self._bodies())
        authorization = read_authorization(client, "singbox-panel")

        self.assertEqual("user-alice", authorization.subject)
        self.assertEqual("alice@example.test", authorization.email)
        self.assertEqual(("panel:read", "panel:config:apply"), authorization.permissions)
        self.assertEqual(("panel-viewer",), authorization.roles)
        self.assertEqual(1, len(authorization.menus))

    def test_every_projection_is_scoped_to_the_application(self) -> None:
        """Otherwise one subject's grants for another application are read silently."""
        client = _StubClient(self._bodies())
        read_authorization(client, "singbox-panel")
        for call in client.calls:
            if call["path"] == "/userinfo":
                self.assertIsNone(call["query"])
                continue
            self.assertEqual({"client_id": "singbox-panel"}, call["query"], call["path"])
        self.assertEqual(
            ["/menus/me", "/permissions/me", "/roles/me", "/userinfo"],
            sorted(call["path"] for call in client.calls),
        )

    def test_a_response_with_no_subject_is_rejected(self) -> None:
        bodies = self._bodies()
        bodies["/userinfo"] = {"email": "nobody@example.test"}
        with self.assertRaises(ValueError):
            read_authorization(_StubClient(bodies), "app")

    def test_an_unreadable_list_is_empty_rather_than_a_grant(self) -> None:
        bodies = self._bodies()
        bodies["/permissions/me"] = None
        bodies["/roles/me"] = None
        bodies["/menus/me"] = None
        authorization = read_authorization(_StubClient(bodies), "app")
        self.assertEqual((), authorization.permissions)
        self.assertEqual((), authorization.roles)
        self.assertEqual((), authorization.menus)

    def test_an_entry_with_no_code_is_dropped_rather_than_matching_empty(self) -> None:
        bodies = self._bodies()
        bodies["/permissions/me"] = {"permissions": [{"code": ""}, {"description": "no code"}]}
        authorization = read_authorization(_StubClient(bodies), "app")
        self.assertEqual((), authorization.permissions)
        # holds("") is always true by design, so an empty *grant* retained in
        # the list would be indistinguishable from a real one. It is dropped.
        self.assertNotIn("", authorization.permissions)


if __name__ == "__main__":
    unittest.main()