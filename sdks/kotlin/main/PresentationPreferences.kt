package com.snaplink.sso

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

/** Why a preference value was rejected. */
public class SnaplinkPreferenceException(message: String) : Exception(message)

/**
 * Application-facing presentation preferences.
 *
 * Wire keys deliberately do not appear in these types; the mapping to the
 * hosted-login query fields and the legacy `sverp:theme_mode` alias lives in
 * [SnaplinkPresentationPreferencesCodec], so a protocol rename stays a one-line
 * change there instead of rippling through call sites.
 */
public data class SnaplinkPresentationPreferences(
    /** BCP 47 language tag, null when unset. */
    val locale: String? = null,
    /** Theme selection, null when unset. */
    val themeMode: SnaplinkThemeMode? = null,
)

/**
 * A partial update.
 *
 * An empty [locale] removes the stored value. [themeMode] has no empty value, so
 * removal is expressed by omitting the field.
 */
public data class SnaplinkPresentationPreferencesPatch(
    val locale: String? = null,
    val themeMode: SnaplinkThemeMode? = null,
)

/**
 * Maps between presentation preferences and the Snaplink wire shapes.
 */
public object SnaplinkPresentationPreferencesCodec {
    /** The longest locale the server accepts, matching the OpenAPI `maxLength`. */
    public const val MAX_LOCALE_LENGTH: Int = 32

    private val json = Json { ignoreUnknownKeys = true }

    /**
     * Maps a stored preference response to application fields.
     *
     * A response whose two theme aliases disagree is refused rather than
     * resolved by precedence: picking one silently would hide a server that
     * still has a stale alias in the profile.
     */
    public fun fromStored(raw: String): SnaplinkPresentationPreferences {
        val fields = runCatching { json.parseToJsonElement(raw).jsonObject }.getOrElse {
            throw SnaplinkPreferenceException("the preferences response is not a readable object")
        }
        val locale = (fields["locale"] as? JsonPrimitive)?.takeIf { it.isString }?.content
        locale?.let { validate(it, allowEmpty = false) }
        val current = theme(fields["theme_mode"])
        val legacy = theme(fields["sverp:theme_mode"])
        if (current != null && legacy != null && current != legacy) {
            throw SnaplinkPreferenceException("conflicting theme preference aliases")
        }
        return SnaplinkPresentationPreferences(locale = locale, themeMode = current ?: legacy)
    }

    /** Maps a patch to the `PUT /me/preferences` request body. */
    public fun toUpdateRequest(patch: SnaplinkPresentationPreferencesPatch): Map<String, String> = buildMap {
        patch.locale?.let {
            validate(it, allowEmpty = true)
            put("locale", it)
        }
        patch.themeMode?.let { put("theme_mode", it.wireValue) }
    }

    /**
     * Builds the hosted-login handoff: only explicitly changed, non-empty
     * values, keyed by the login query field that carries them.
     *
     * A handoff is a presentation hint, not an authorization or tenant
     * parameter: the server persists it as the authenticated user's allowlisted
     * preference only after a successful authentication. Absent fields are
     * omitted rather than sent empty, so a handoff never clears a preference the
     * application did not mean to touch.
     */
    public fun buildLoginHandoff(patch: SnaplinkPresentationPreferencesPatch): Map<String, String> = buildMap {
        patch.locale?.let {
            validate(it, allowEmpty = false)
            put("presentation_locale", it)
        }
        patch.themeMode?.let { put("presentation_theme_mode", it.wireValue) }
    }

    private fun theme(value: Any?): SnaplinkThemeMode? {
        val primitive = value as? JsonPrimitive ?: return null
        if (!primitive.isString) throw SnaplinkPreferenceException("theme_mode must be light, dark, or auto")
        return SnaplinkThemeMode.parse(primitive.content)
            ?: throw SnaplinkPreferenceException("theme_mode must be light, dark, or auto")
    }

    /**
     * A pragmatic BCP 47 subset: a 2-3 letter primary subtag followed by
     * alphanumeric subtags of 2-8 characters. This mirrors the server's own
     * pattern and is deliberately not a full RFC 5646 parser.
     */
    public fun validate(locale: String, allowEmpty: Boolean) {
        if (allowEmpty && locale.isEmpty()) return
        if (locale.isEmpty() || locale.length > MAX_LOCALE_LENGTH) {
            throw SnaplinkPreferenceException("locale must be a valid BCP 47 language tag")
        }
        val parts = locale.split("-")
        val primary = parts.first()
        if (primary.length !in 2..3 || !primary.all { it.isLetter() && it.code < 128 }) {
            throw SnaplinkPreferenceException("locale must be a valid BCP 47 language tag")
        }
        for (part in parts.drop(1)) {
            if (part.length !in 2..8 || !part.all { (it.isLetter() || it.isDigit()) && it.code < 128 }) {
                throw SnaplinkPreferenceException("locale must be a valid BCP 47 language tag")
            }
        }
    }
}

/**
 * A commerce transport for a client built without one.
 *
 * The public constructor always wires the OkHttp implementation; this exists so
 * a caller that supplies its own OAuth transport does not silently gain a
 * commerce surface it never asked for, and a commercial call fails loudly
 * instead of appearing to succeed.
 */
internal object FailingCommerceTransport : SnaplinkCommerceTransport {
    private fun unsupported(): SnaplinkAuthException =
        SnaplinkAuthException("unsupported_operation", "this client was built without a commerce transport")

    override suspend fun prepareActivation(request: SnaplinkActivationPrepareRequest): SnaplinkActivationPreparation =
        throw unsupported()

    override suspend fun claimActivation(ticket: String, productId: String, bearer: String): SnaplinkAccountContext =
        throw unsupported()

    override suspend fun accountContext(productId: String, bearer: String): SnaplinkAccountContext =
        throw unsupported()

    override suspend fun myPreferences(bearer: String): String = throw unsupported()

    override suspend fun putMyPreferences(fields: Map<String, String>, bearer: String) {
        throw unsupported()
    }
}
