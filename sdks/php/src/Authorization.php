<?php

declare(strict_types=1);

namespace Snaplink;

/**
 * Who Snaplink says the bearer is, and what that subject may do.
 *
 * This is the read side of an authorization decision: identity from /userinfo,
 * and the permission, role, and menu projections from the /permissions/me,
 * /roles/me, and /menus/me family.
 *
 * The server remains the authority for every decision. This exists so a caller
 * can render a navigation and hide a control it knows will be refused, without
 * hand-rolling an OAuth path it should not own. The permission rule that decides
 * panel:* versus panel:read lives in Authorization::holds() so every consumer
 * applies the same one.
 */
final class Authorization
{
    /**
     * Whether the subject holds a permission.
     *
     * Mirrors the server's permissions.Matches exactly, because a client rule
     * that disagrees with the server is worse than no rule at all: it hides
     * controls the server would grant and shows controls it would deny.
     *
     * - an exact code match grants;
     * - domain:* is a prefix rule, so panel:* grants panel:config:write and a:*
     *   grants a:b:c;
     * - a bare * grants everything, including a single-segment code;
     * - an empty requirement is always granted, which is what an empty
     *   permission on a menu node means;
     * - an unqualified permission is exact only: holding panel does not grant
     *   panel:read.
     *
     * @param list<string> $permissions
     */
    public static function holds(array $permissions, string $required): bool
    {
        if ($required === '') {
            return true;
        }
        foreach ($permissions as $held) {
            if ($held === '*' || $held === $required || self::matchesDomainWildcard($held, $required)) {
                return true;
            }
        }
        return false;
    }

    /** Whether a held code of the form domain:* covers $required. */
    private static function matchesDomainWildcard(string $held, string $required): bool
    {
        // The wildcard is the whole ":*" suffix, not just the asterisk, and the
        // colon is part of the prefix: that colon is what stops panel:* from
        // reaching a hypothetical panelx:read.
        return str_starts_with($required, substr($held, 0, -2) . ':');
    }

    /**
     * Read a permission or role list.
     *
     * The contract sends objects, but a bare string is accepted so a caller that
     * only projects codes is not forced to reshape them. An entry with no
     * readable code can grant nothing, so it is dropped rather than surfaced as
     * an empty string that might look like a match.
     *
     * @return list<string>
     */
    public static function codes(mixed $value): array
    {
        if (!is_array($value)) {
            return [];
        }
        $codes = [];
        foreach ($value as $entry) {
            $code = is_string($entry) ? $entry : (is_array($entry) ? ($entry['code'] ?? null) : null);
            if (is_string($code) && $code !== '') {
                $codes[] = $code;
            }
        }
        return $codes;
    }

    /**
     * Read identity, permissions, roles, and menus for the current bearer.
     *
     * $request performs one authenticated GET and returns the decoded body;
     * $clientId selects the application the permission and menu projection is
     * read for, which is why it is required rather than defaulted: one subject
     * can hold different grants for different applications, and guessing would
     * silently read the wrong set.
     *
     * All four are fetched together because they are always wanted together and
     * a navigation tree that disagrees with the enforced permission set is
     * worse than one extra round trip.
     *
     * @param callable(string):array<string,mixed> $request
     */
    public static function read(callable $request, string $clientId): self
    {
        if (trim($clientId) === '') {
            throw new SSOError(0, 'invalid_request', 'client_id is required');
        }
        $scope = 'client_id=' . rawurlencode($clientId);
        $userinfo = $request('/userinfo');
        $subject = is_string($userinfo['sub'] ?? null) ? trim($userinfo['sub']) : '';
        if ($subject === '') {
            throw new SSOError(0, 'invalid_response', '/userinfo returned no subject');
        }
        $permissions = $request('/permissions/me?' . $scope);
        $roles = $request('/roles/me?' . $scope);
        $menus = $request('/menus/me?' . $scope);

        return new self(
            $subject,
            is_string($userinfo['email'] ?? null) ? $userinfo['email'] : null,
            is_string($userinfo['name'] ?? null) ? $userinfo['name'] : null,
            self::codes($roles['roles'] ?? null),
            self::codes($permissions['permissions'] ?? null),
            MenuNode::tree($menus['menus'] ?? null),
        );
    }

    /**
     * @param list<string> $roles
     * @param list<string> $permissions
     * @param list<MenuNode> $menus
     */
    public function __construct(
        public readonly string $subject,
        public readonly ?string $email = null,
        public readonly ?string $name = null,
        public readonly array $roles = [],
        public readonly array $permissions = [],
        public readonly array $menus = [],
    ) {
    }

    /** Whether the subject holds a permission. */
    public function allows(string $required): bool
    {
        return self::holds($this->permissions, $required);
    }

    /**
     * The nodes the subject may see, with denied subtrees removed and surviving
     * buttons narrowed.
     *
     * A parent whose own permission is denied takes its children with it,
     * because a child route under a hidden parent is not reachable.
     *
     * @return list<MenuNode>
     */

    /**
     * @param list<MenuNode> $nodes
     * @param list<string> $permissions
     * @return list<MenuNode>
     */
    public static function visibleChildren(array $nodes, array $permissions): array
    {
        $visible = [];
        foreach ($nodes as $node) {
            if (!$node->isVisible($permissions)) {
                continue;
            }
            $visible[] = $node->withVisibleChildren($permissions);
        }
        return $visible;
    }

    /**
     * @return list<MenuNode>
     */
    public function visibleMenus(): array
    {
        return self::visibleChildren($this->menus, $this->permissions);
    }
}

/**
 * A per-node action the subject may take.
 */
final class MenuButton
{
    public function __construct(
        public readonly string $code = '',
        public readonly string $name = '',
        /** The permission this button requires; empty means always shown. */
        public readonly string $permission = '',
    ) {
    }
}

/**
 * One node of the navigation tree the subject may see.
 */
final class MenuNode
{
    /**
     * @param list<MenuButton> $buttons
     * @param list<MenuNode> $children
     */
    public function __construct(
        public readonly string $id = '',
        public readonly string $name = '',
        /** Route this node opens, relative to the application root. */
        public readonly string $path = '',
        public readonly string $icon = '',
        /** The permission this node requires; empty means always shown. */
        public readonly string $permission = '',
        public readonly array $buttons = [],
        public readonly array $children = [],
    ) {
    }

    /**
     * @return list<MenuNode>
     */
    public static function tree(mixed $value): array
    {
        if (!is_array($value)) {
            return [];
        }
        $nodes = [];
        foreach ($value as $entry) {
            if (is_array($entry)) {
                $nodes[] = self::fromWire($entry);
            }
        }
        return $nodes;
    }

    /**
     * @param array<string,mixed> $value
     */
    public static function fromWire(array $value): self
    {
        $buttons = [];
        foreach (($value['buttons'] ?? []) as $button) {
            if (is_array($button)) {
                $buttons[] = new MenuButton(
                    (string) ($button['code'] ?? ''),
                    (string) ($button['name'] ?? ''),
                    (string) ($button['permission'] ?? ''),
                );
            }
        }
        return new self(
            (string) ($value['id'] ?? ''),
            (string) ($value['name'] ?? ''),
            (string) ($value['path'] ?? ''),
            (string) ($value['icon'] ?? ''),
            (string) ($value['permission'] ?? ''),
            $buttons,
            self::tree($value['children'] ?? null),
        );
    }

    /** Whether this node's own permission is held, ignoring its children. */
    public function isVisible(array $permissions): bool
    {
        return $this->permission === '' || Authorization::holds($permissions, $this->permission);
    }

    /**
     * The buttons on this node the subject may use.
     *
     * @param list<string> $permissions
     * @return list<MenuButton>
     */
    public function actions(array $permissions): array
    {
        return array_values(array_filter(
            $this->buttons,
            static fn (MenuButton $button): bool =>
                $button->permission === '' || Authorization::holds($permissions, $button->permission),
        ));
    }

    /**
     * A copy with its buttons narrowed and its children projected.
     *
     * @param list<string> $permissions
     */
    public function withVisibleChildren(array $permissions): self
    {
        return new self(
            $this->id,
            $this->name,
            $this->path,
            $this->icon,
            $this->permission,
            $this->actions($permissions),
            Authorization::visibleChildren($this->children, $permissions),
        );
    }
}