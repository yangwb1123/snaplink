package com.snaplink.sso

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Reads only existing /userinfo and /permissions|roles|menus/me contracts. */
internal class HttpAuthorizationTransport(
    private val config: SnaplinkConfiguration,
    private val http: SnaplinkHttpTransport = SnaplinkOkHttpTransport(),
) {
    suspend fun read(bearer: String, ensureSession: () -> Unit = {}): SnaplinkAuthorization {
        val identity = readObject("userinfo", bearer, ensureSession, scoped = false)
        val subject = identity.requiredString("sub").takeIf(String::isNotBlank) ?: invalid()
        val permissions = readObject("permissions/me", bearer, ensureSession).codes("permissions")
        val roles = readObject("roles/me", bearer, ensureSession).codes("roles")
        val menus = readObject("menus/me", bearer, ensureSession).array("menus")
        return SnaplinkAuthorization(
            subject = subject,
            clientId = config.clientId,
            email = identity.optionalString("email"),
            name = identity.optionalString("name"),
            permissions = permissions,
            roles = roles,
            menus = readMenus(menus, 1),
        )
    }

    private suspend fun readObject(
        path: String,
        bearer: String,
        ensureSession: () -> Unit,
        scoped: Boolean = true,
    ): JsonObject {
        ensureSession()
        val body = SnaplinkHttp.read(
            http,
            SnaplinkRequestFactory.bearerRead(
                baseURL = config.issuerBaseUrl,
                path = path,
                query = if (scoped) SnaplinkRequestFactory.query("client_id" to config.clientId) else null,
                bearer = bearer,
            ),
        )
        ensureSession()
        val result = try {
            SnaplinkHttp.json.parseToJsonElement(body) as? JsonObject ?: invalid()
        } catch (error: Exception) {
            throw SnaplinkAuthException("invalid_response", "Snaplink returned an invalid authorization projection", cause = error)
        }
        if (scoped && result.requiredString("client_id") != config.clientId) invalid()
        return result
    }

    private fun JsonObject.codes(field: String): List<String> = array(field).map { entry ->
        val code = when (entry) {
            is JsonObject -> entry.requiredString("code")
            else -> entry.stringValue()
        }
        if (code.isBlank()) invalid()
        code
    }

    private fun readMenus(nodes: JsonArray, depth: Int): List<SnaplinkMenuNode> {
        if (depth > MAX_MENU_DEPTH) invalid()
        return nodes.map { element ->
            val node = element as? JsonObject ?: invalid()
            val id = node.requiredString("id").takeIf(String::isNotBlank) ?: invalid()
            SnaplinkMenuNode(
                id = id,
                name = node.requiredString("name"),
                path = node.optionalString("path"),
                icon = node.optionalString("icon"),
                permission = node.permission(),
                buttons = node.optionalArray("buttons").map(::readButton),
                children = node.optionalArray("children").let {
                    if (it.isEmpty()) emptyList() else readMenus(it, depth + 1)
                },
            )
        }
    }

    private fun readButton(element: JsonElement): SnaplinkMenuButton {
        val button = element as? JsonObject ?: invalid()
        return SnaplinkMenuButton(
            code = button.requiredString("code").takeIf(String::isNotBlank) ?: invalid(),
            name = button.optionalString("name"),
            permission = button.permission(),
        )
    }

    private fun JsonObject.permission(): String =
        if (containsKey("permission")) requiredString("permission") else ""

    private fun JsonObject.array(field: String): JsonArray = this[field] as? JsonArray ?: invalid()

    private fun JsonObject.optionalArray(field: String): JsonArray =
        if (containsKey(field)) array(field) else JsonArray(emptyList())

    private fun JsonObject.requiredString(field: String): String = this[field]?.stringValue() ?: invalid()

    private fun JsonObject.optionalString(field: String): String? =
        this[field]?.takeUnless { it is JsonNull }?.stringValue()

    private fun JsonElement.stringValue(): String =
        (this as? JsonPrimitive)?.takeIf { it.isString }?.content ?: invalid()

    private fun invalid(): Nothing =
        throw SnaplinkAuthException("invalid_response", "Snaplink returned an invalid authorization projection")

    private companion object {
        const val MAX_MENU_DEPTH = 32
    }
}
