// Who Snaplink says the bearer is, and what that subject may do.
//
// This is the read side of an authorization decision: identity from
// `/userinfo`, and the permission, role, and menu projections from the
// `/permissions/me`, `/roles/me`, and `/menus/me` family.
//
// The server remains the authority for every decision. This exists so a caller
// can render a navigation and hide a control it knows will be refused, without
// hand-rolling an OAuth path it should not own. The permission rule that decides
// `panel:*` versus `panel:read` lives in `holds` so every consumer applies the
// same one.
/** Whether a node's own permission is held, ignoring its children. */
export function isNodeVisible(node, permissions) {
    const required = node.permission ?? "";
    return required === "" || holds(permissions, required);
}
/** Whether this node and every button on it are permitted. */
export function permittedActions(node, permissions) {
    return (node.buttons ?? []).filter((button) => {
        const required = button.permission ?? "";
        return required === "" || holds(permissions, required);
    });
}
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
export function holds(permissions, required) {
    if (required === "")
        return true;
    return permissions.some((held) => held === "*" || held === required || matchesDomainWildcard(held, required));
}
/** Whether a held code of the form `domain:*` covers `required`. */
function matchesDomainWildcard(held, required) {
    if (!held.endsWith(":*"))
        return false;
    const domain = held.slice(0, -2);
    // The colon is part of the prefix, which is what stops `panel:*` from
    // reaching a hypothetical `panelx:read`.
    return required.startsWith(`${domain}:`);
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
export async function readAuthorization(request, clientId) {
    const scope = { client_id: clientId };
    const [userinfo, permissions, roles, menus] = await Promise.all([
        request("/userinfo"),
        request("/permissions/me", scope),
        request("/roles/me", scope),
        request("/menus/me", scope),
    ]);
    const subject = readSubject(userinfo);
    if (subject === "") {
        throw new Error("sdk-paradigm: /userinfo returned no subject");
    }
    return {
        subject,
        email: readOptionalString(userinfo, "email"),
        name: readOptionalString(userinfo, "name"),
        roles: readCodes(roles),
        permissions: readCodes(permissions),
        menus: readMenus(menus),
    };
}
function asRecord(value) {
    if (typeof value !== "object" || value === null)
        return {};
    return value;
}
function readSubject(value) {
    const record = asRecord(value);
    const sub = record.sub ?? record.user_id;
    return typeof sub === "string" ? sub.trim() : "";
}
function readOptionalString(value, key) {
    const found = asRecord(value)[key];
    return typeof found === "string" && found !== "" ? found : undefined;
}
/**
 * Read a `permissions` or `roles` list.
 *
 * The contract sends objects, but a bare string is accepted so a caller that
 * only projects codes is not forced to reshape them. An entry with no readable
 * code can grant nothing, so it is dropped rather than surfaced as an empty
 * string that might look like a match.
 */
function readCodes(value) {
    const list = asRecord(value)[Array.isArray(asRecord(value).permissions)
        ? "permissions"
        : "roles"];
    if (!Array.isArray(list))
        return [];
    const codes = [];
    for (const entry of list) {
        const code = typeof entry === "string" ? entry : asRecord(entry).code;
        if (typeof code === "string" && code !== "")
            codes.push(code);
    }
    return codes;
}
function readMenus(value) {
    const list = asRecord(value).menus;
    return Array.isArray(list) ? list : [];
}
/**
 * Drop the nodes the subject may not see, recursively.
 *
 * A parent whose own permission is denied takes its children with it, because a
 * child route under a hidden parent is not reachable.
 */
export function visibleMenus(nodes, permissions) {
    return nodes
        .filter((node) => isNodeVisible(node, permissions))
        .map((node) => ({ ...node, children: visibleMenus(node.children ?? [], permissions) }));
}
