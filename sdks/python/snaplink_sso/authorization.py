"""Who Snaplink says the bearer is, and what that subject may do.

This is the read side of an authorization decision: identity from
``/userinfo``, and the permission, role, and menu projections from the
``/permissions/me``, ``/roles/me``, and ``/menus/me`` family.

The server remains the authority for every decision. This exists so a caller can
render a navigation and hide a control it knows will be refused, without
hand-rolling an OAuth path it should not own. The permission rule that decides
``panel:*`` versus ``panel:read`` lives in :func:`holds` so every consumer
applies the same one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Mapping, Optional, Sequence

from .client import SSOClient


@dataclass(frozen=True)
class MenuButton:
    """A per-node action the subject may take."""

    code: str = ""
    name: str = ""
    #: The permission this button requires; empty means always shown.
    permission: str = ""


@dataclass(frozen=True)
class MenuNode:
    """One node of the navigation tree the subject may see."""

    id: str = ""
    name: str = ""
    #: Route this node opens, relative to the application root.
    path: str = ""
    icon: str = ""
    #: The permission this node requires; empty means always shown.
    permission: str = ""
    buttons: Sequence[MenuButton] = field(default_factory=tuple)
    children: Sequence["MenuNode"] = field(default_factory=tuple)

    @classmethod
    def from_wire(cls, value: Mapping[str, Any]) -> "MenuNode":
        if not isinstance(value, Mapping):
            return cls()
        return cls(
            id=str(value.get("id", "")),
            name=str(value.get("name", "")),
            path=str(value.get("path", "")),
            icon=str(value.get("icon", "")),
            permission=str(value.get("permission", "")),
            buttons=tuple(
                MenuButton(
                    code=str(button.get("code", "")),
                    name=str(button.get("name", "")),
                    permission=str(button.get("permission", "")),
                )
                for button in value.get("buttons") or []
                if isinstance(button, Mapping)
            ),
            children=tuple(
                cls.from_wire(child)
                for child in value.get("children") or []
                if isinstance(child, Mapping)
            ),
        )

    def is_visible(self, permissions: Sequence[str]) -> bool:
        """Whether this node's own permission is held, ignoring children."""
        return self.permission == "" or holds(permissions, self.permission)

    def actions(self, permissions: Sequence[str]) -> List[MenuButton]:
        """The buttons on this node the subject may use."""
        return [
            button
            for button in self.buttons
            if button.permission == "" or holds(permissions, button.permission)
        ]


@dataclass(frozen=True)
class Authorization:
    """Identity, permissions, roles, and menus for one bearer and one application."""

    #: The authenticated subject. This is the only identity worth trusting.
    subject: str
    email: Optional[str] = None
    name: Optional[str] = None
    #: Roles held for the requested client.
    roles: Sequence[str] = field(default_factory=tuple)
    #: Flat permission codes held for the requested client.
    permissions: Sequence[str] = field(default_factory=tuple)
    #: The navigation tree the subject is authorized to see.
    menus: Sequence[MenuNode] = field(default_factory=tuple)

    def allows(self, required: str) -> bool:
        """Whether the subject holds a permission."""
        return holds(self.permissions, required)

    def visible_menus(self) -> List[MenuNode]:
        """The nodes the subject may see, with denied subtrees removed.

        A parent whose own permission is denied takes its children with it,
        because a child route under a hidden parent is not reachable. Surviving
        buttons are narrowed to the ones the subject may actually use.
        """
        return _visible_menus(self.menus, self.permissions)


def _visible_menus(nodes: Sequence[MenuNode], permissions: Sequence[str]) -> List[MenuNode]:
    """Drop denied nodes recursively, narrowing the buttons that survive."""
    return [
        MenuNode(
            id=node.id,
            name=node.name,
            path=node.path,
            icon=node.icon,
            permission=node.permission,
            buttons=tuple(node.actions(permissions)),
            children=tuple(_visible_menus(node.children, permissions)),
        )
        for node in nodes
        if node.is_visible(permissions)
    ]


def holds(permissions: Sequence[str], required: str) -> bool:
    """Whether the subject holds a permission.

    Mirrors the server's ``permissions.Matches`` exactly, because a client rule
    that disagrees with the server is worse than no rule at all: it hides
    controls the server would grant and shows controls it would deny.

    - an exact code match grants;
    - ``domain:*`` is a **prefix** rule, so ``panel:*`` grants
      ``panel:config:write`` and ``a:*`` grants ``a:b:c``;
    - a bare ``*`` grants everything, including a single-segment code;
    - an empty requirement is always granted, which is what an empty permission
      on a menu node means;
    - an unqualified permission is exact only: holding ``panel`` does not grant
      ``panel:read``.
    """
    if required == "":
        return True
    return any(
        held == "*" or held == required or _matches_domain_wildcard(held, required)
        for held in permissions
    )


def _matches_domain_wildcard(held: str, required: str) -> bool:
    """Whether a held code of the form ``domain:*`` covers ``required``."""
    if not held.endswith(":*"):
        return False
    domain = held[:-2]
    # The colon is part of the prefix, which is what stops ``panel:*`` from
    # reaching a hypothetical ``panelx:read``.
    return required.startswith(f"{domain}:")


def _mapping(value: Any) -> Mapping[str, Any]:
    """Normalize an unreadable response body to an empty mapping.

    A malformed list must degrade to "grants nothing", never crash and never
    raise into a path a caller might treat as an authorization failure with a
    different meaning.
    """
    return value if isinstance(value, Mapping) else {}


def _codes(value: Any) -> List[str]:
    """Read a permission or role list.

    The contract sends objects, but a bare string is accepted so a caller that
    only projects codes is not forced to reshape them. An entry with no readable
    code can grant nothing, so it is dropped rather than surfaced as an empty
    string that might look like a match.
    """
    if not isinstance(value, list):
        return []
    codes: List[str] = []
    for entry in value:
        code = entry if isinstance(entry, str) else (entry or {}).get("code")
        if isinstance(code, str) and code != "":
            codes.append(code)
    return codes


def read_authorization(api: SSOClient, client_id: str) -> Authorization:
    """Read identity, permissions, roles, and menus for the current bearer.

    ``client_id`` selects the application the permission and menu projection is
    read for, which is why it is required rather than defaulted: one subject can
    hold different grants for different applications, and guessing would silently
    read the wrong set.

    All four are fetched together because they are always wanted together and a
    navigation tree that disagrees with the enforced permission set is worse than
    one extra round trip.
    """
    scope = {"client_id": client_id}
    userinfo = _mapping(api.get_userinfo())
    subject = str(userinfo.get("sub", "")).strip()
    if not subject:
        raise ValueError("/userinfo returned no subject")
    email = userinfo.get("email")
    name = userinfo.get("name")
    menus = _mapping(api.get_my_menus(scope)).get("menus") or []
    return Authorization(
        subject=subject,
        email=email if isinstance(email, str) else None,
        name=name if isinstance(name, str) else None,
        roles=tuple(_codes(_mapping(api.get_my_roles(scope)).get("roles"))),
        permissions=tuple(
            _codes(_mapping(api.get_my_permissions(scope)).get("permissions"))
        ),
        menus=tuple(
            MenuNode.from_wire(node) for node in menus if isinstance(node, Mapping)
        ),
    )