package com.snaplink.sso

/** Display-only permission rule, matching domains/permissions/matcher.go. */
public object SnaplinkPermissions {
    public fun holds(permissions: List<String>, required: String): Boolean =
        required.isEmpty() || permissions.any { held ->
            held == "*" || held == required ||
                (held.endsWith(":*") && required.startsWith(held.removeSuffix(":*") + ":"))
        }
}

/** A menu action. Missing permission means unrestricted display, not server access. */
public data class SnaplinkMenuButton(
    val code: String,
    val name: String? = null,
    val permission: String = "",
)

/** One navigation node returned by the server, not a client authorization grant. */
public data class SnaplinkMenuNode(
    val id: String,
    val name: String,
    val path: String? = null,
    val icon: String? = null,
    val permission: String = "",
    val buttons: List<SnaplinkMenuButton> = emptyList(),
    val children: List<SnaplinkMenuNode> = emptyList(),
) {
    public fun isVisible(permissions: List<String>): Boolean = SnaplinkPermissions.holds(permissions, permission)

    public fun actions(permissions: List<String>): List<SnaplinkMenuButton> =
        buttons.filter { SnaplinkPermissions.holds(permissions, it.permission) }
}

/**
 * Current bearer's identity and the configured application's permission projection.
 *
 * A point-in-time read assembled from four endpoints, not an atomic server
 * snapshot. It is not cached or persisted by the SDK. The server must still
 * authorize every business request; menus and allows() only guide presentation.
 */
public data class SnaplinkAuthorization(
    val subject: String,
    val clientId: String,
    val email: String?,
    val name: String?,
    val roles: List<String>,
    val permissions: List<String>,
    val menus: List<SnaplinkMenuNode>,
) {
    public fun allows(required: String): Boolean = SnaplinkPermissions.holds(permissions, required)

    public fun hasRole(role: String): Boolean = role in roles

    /** Denying a parent removes its subtree; surviving buttons are filtered too. */
    public fun visibleMenus(): List<SnaplinkMenuNode> = visible(menus)

    private fun visible(nodes: List<SnaplinkMenuNode>): List<SnaplinkMenuNode> =
        nodes.filter { it.isVisible(permissions) }.map { node ->
            node.copy(buttons = node.actions(permissions), children = visible(node.children))
        }
}
