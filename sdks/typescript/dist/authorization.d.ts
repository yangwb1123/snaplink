/** A per-node action the subject may take. */
export interface MenuButton {
    code: string;
    name: string;
    /** The permission this button requires; empty means always shown. */
    permission?: string;
}
/** One node of the navigation tree the subject may see. */
export interface MenuNode {
    id: string;
    name: string;
    /** Route this node opens, relative to the application root. */
    path?: string;
    icon?: string;
    /** The permission this node requires; empty means always shown. */
    permission?: string;
    buttons?: MenuButton[];
    children?: MenuNode[];
}
/** Whether a node's own permission is held, ignoring its children. */
export declare function isNodeVisible(node: MenuNode, permissions: readonly string[]): boolean;
/** Whether this node and every button on it are permitted. */
export declare function permittedActions(node: MenuNode, permissions: readonly string[]): MenuButton[];
/**
 * Whether the subject holds a permission.
 *
 * Mirrors the server's `permissions.Matches` exactly, because a client rule
 * that disagrees with the server is worse than no rule at all: it hides controls
 * the server would grant and shows controls it would deny.
 *
 * - an exact code match grants;
 * - `domain:*` is a **prefix** rule, so `panel:*` grants `panel:config:write`
 *   and `a:*` grants `a:b:c`;
 * - a bare `*` grants everything, including a single-segment code;
 * - an empty requirement is always granted, which is what an empty permission on
 *   a menu node means;
 * - an unqualified permission is exact only: holding `panel` does not grant
 *   `panel:read`.
 */
export declare function holds(permissions: readonly string[], required: string): boolean;
/** Identity, permissions, roles, and menus for one bearer and one application. */
export interface Authorization {
    /** The authenticated subject. This is the only identity worth trusting. */
    subject: string;
    email?: string;
    name?: string;
    /** Roles held for the requested client. */
    roles: string[];
    /** Flat permission codes held for the requested client. */
    permissions: string[];
    /** The navigation tree the subject is authorized to see. */
    menus: MenuNode[];
}
/**
 * Read identity, permissions, roles, and menus for a bearer.
 *
 * `clientId` selects the application the permission and menu projection is read
 * for, which is why it is required rather than defaulted: one subject can hold
 * different grants for different applications, and guessing would silently read
 * the wrong set.
 *
 * All four are fetched together because they are always wanted together and a
 * navigation tree that disagrees with the enforced permission set is worse than
 * one extra round trip.
 *
 * `request` is expected to attach the bearer itself; the SDK only decides the
 * paths and the `client_id` scope.
 */
export declare function readAuthorization(request: (path: string, query?: Record<string, string>) => Promise<unknown>, clientId: string): Promise<Authorization>;
/**
 * Drop the nodes the subject may not see, recursively.
 *
 * A parent whose own permission is denied takes its children with it, because a
 * child route under a hidden parent is not reachable.
 */
export declare function visibleMenus(nodes: readonly MenuNode[], permissions: readonly string[]): MenuNode[];
