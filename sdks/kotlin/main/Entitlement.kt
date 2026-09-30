package com.snaplink.sso

import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull
import java.time.Instant
import java.time.format.DateTimeParseException

/**
 * A theme selection shared by Snaplink-hosted applications.
 */
public enum class SnaplinkThemeMode(public val wireValue: String) {
    LIGHT("light"),
    DARK("dark"),

    /** Follow the operating system. */
    AUTO("auto");

    public companion object {
        private val byWire = entries.associateBy(SnaplinkThemeMode::wireValue)

        /** Parses a wire value, rejecting anything outside the allowlist. */
        public fun parse(value: String): SnaplinkThemeMode? = byWire[value]
    }
}

/**
 * Why an entitlement is present but not usable.
 *
 * Presentation only. It must never drive retry or authorization behaviour: the
 * server collapses distinct internal causes into one wire code, and a client
 * that branched on the reason would leak the distinction the server hides.
 */
public enum class SnaplinkInactiveReason(public val wireValue: String) {
    NOT_YET_EFFECTIVE("not_yet_effective"),
    EXPIRED("expired"),
    SUSPENDED("suspended"),
}

/**
 * Which of the three licence states applies.
 *
 * A two-state optional cannot tell "never activated" from "activated once but
 * lapsed", and those need different copy and different follow-up actions.
 */
public enum class SnaplinkLicenseStateKind(public val wireValue: String) {
    NOT_ACTIVATED("not_activated"),
    INACTIVE("inactive"),
    ACTIVE("active"),
}

/** A soft threshold and a hard safety limit. */
@Serializable
public data class SnaplinkLimitGrant(
    val soft: Long,
    val hard: Long,
    /** Defaults to false on the wire, so an omitted field is not an error. */
    @SerialName("unlimited") val unlimited: Boolean = false,
)

/** A plan identifier and its immutable published version. */
@Serializable
public data class SnaplinkPlanRef(
    val id: String,
    val version: Long,
)

/** The classified state of a product licence. */
public data class SnaplinkLicenseState(
    val kind: SnaplinkLicenseStateKind,
    val reason: SnaplinkInactiveReason? = null,
    val until: Instant? = null,
    val entitlement: SnaplinkEntitlement? = null,
) {
    /** Whether grants are live. This is the only question a feature gate asks. */
    public val isActive: Boolean get() = kind == SnaplinkLicenseStateKind.ACTIVE
}

/**
 * A server-derived commercial entitlement snapshot.
 *
 * The server remains the authority on every authorization decision; this
 * snapshot exists for user experience only.
 */
@Serializable
public data class SnaplinkEntitlement(
    @SerialName("tenant_id") val tenantId: String,
    @SerialName("subscription_id") val subscriptionId: String,
    val plan: SnaplinkPlanRef,
    val revision: Long,
    val active: Boolean,
    val features: Map<String, Boolean> = emptyMap(),
    val limits: Map<String, SnaplinkLimitGrant> = emptyMap(),
    @Serializable(with = WireInstantSerializer::class)
    @SerialName("effective_at") val effectiveAt: Instant? = null,
    @Serializable(with = WireInstantSerializer::class)
    @SerialName("expires_at") val expiresAt: Instant? = null,
    @Serializable(with = WireInstantSerializer::class)
    @SerialName("generated_at") val generatedAt: Instant? = null,
) {
    /**
     * Classifies the entitlement at [now].
     *
     * Mirrors `commerce.EntitlementSnapshot.effective` exactly: the expiry
     * boundary is exclusive, so an entitlement whose window closes at [now] is
     * already inactive at [now].
     */
    public fun stateAt(now: Instant): SnaplinkLicenseState = when {
        !active -> SnaplinkLicenseState(
            kind = SnaplinkLicenseStateKind.INACTIVE,
            reason = SnaplinkInactiveReason.SUSPENDED,
            until = expiresAt,
        )
        effectiveAt != null && now.isBefore(effectiveAt) -> SnaplinkLicenseState(
            kind = SnaplinkLicenseStateKind.INACTIVE,
            reason = SnaplinkInactiveReason.NOT_YET_EFFECTIVE,
        )
        expiresAt != null && !now.isBefore(expiresAt) -> SnaplinkLicenseState(
            kind = SnaplinkLicenseStateKind.INACTIVE,
            reason = SnaplinkInactiveReason.EXPIRED,
            until = expiresAt,
        )
        else -> SnaplinkLicenseState(kind = SnaplinkLicenseStateKind.ACTIVE, entitlement = this)
    }

    /**
     * Whether [feature] is granted at [now].
     *
     * False for an inactive entitlement regardless of what the map says.
     */
    public fun has(feature: SnaplinkFeature, now: Instant): Boolean =
        stateAt(now).isActive && features[feature.wireValue] == true

    /**
     * The grant for [limit] at [now], or null when inactive, absent, or
     * unrecognised.
     */
    public fun limit(limit: SnaplinkLimit, now: Instant): SnaplinkLimitGrant? =
        if (stateAt(now).isActive) limits[limit.wireValue] else null

    /**
     * Feature keys the server sent that this build does not recognise, so an
     * operator can see a plan grants something the SDK cannot yet gate instead
     * of silently ignoring it.
     */
    public val unknownFeatures: List<String>
        get() = features.keys.filterNot { SnaplinkFeature.isKnown(it) }.sorted()
}

/** Server-derived product, tenant, entitlement, and quota information. */
@Serializable
public data class SnaplinkAccountContext(
    @SerialName("product_id") val productId: String,
    @SerialName("tenant_id") val tenantId: String,
    val entitlement: SnaplinkEntitlement? = null,
) {
    /**
     * Classifies the context's entitlement, treating an absent one as
     * not-activated.
     *
     * This is the single entry point the shared entitlement contract expects: a
     * context with no entitlement and a context whose entitlement is unusable
     * are different states, and both are reachable without the caller
     * branching on null first.
     */
    public fun licenseStateAt(now: Instant): SnaplinkLicenseState =
        entitlement?.stateAt(now) ?: SnaplinkLicenseState(kind = SnaplinkLicenseStateKind.NOT_ACTIVATED)
}

/**
 * Decodes a timestamp that may arrive as RFC 3339 text or Unix seconds.
 *
 * Snaplink fixtures and hand-written entitlement files use Unix seconds while
 * the live API uses RFC 3339, so one format would be wrong half the time. An
 * unparsable value decodes as absent rather than being guessed, and a missing
 * field stays null instead of defaulting to the epoch.
 */
internal object WireInstantSerializer : KSerializer<Instant?> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("SnaplinkWireInstant", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: Instant?) {
        encoder.encodeString(value?.toString() ?: "")
    }

    override fun deserialize(decoder: Decoder): Instant? {
        // The live API sends RFC 3339 text while fixtures and hand-written
        // entitlement files send Unix seconds, so a bare number is accepted
        // too rather than being a parse failure.
        val primitive = if (decoder is JsonDecoder) {
            decoder.decodeJsonElement() as? JsonPrimitive
        } else {
            null
        }
        if (primitive != null && !primitive.isString) {
            return primitive.longOrNull?.let(Instant::ofEpochSecond)
        }
        val text = (primitive?.content ?: decoder.decodeString()).trim()
        if (text.isEmpty()) return null
        text.toLongOrNull()?.let { return Instant.ofEpochSecond(it) }
        return try {
            Instant.parse(text)
        } catch (_: DateTimeParseException) {
            null
        }
    }
}

/** A stable product capability identifier, mirroring `commerce.FeatureKey`. */
public enum class SnaplinkFeature(public val wireValue: String) {
    CORE_SSO("core_sso"),
    MULTI_TENANT("multi_tenant"),
    AUDIT_GOVERNANCE("audit_governance"),
    NOTIFICATIONS("notifications"),
    IM("im"),
    ACCOUNT("account"),
    VAULT("vault"),
    SCIM("scim"),
    FEDERATION("federation"),
    HIGH_AVILABILITY("high_availability");

    public companion object {
        private val byWire = entries.associateBy(SnaplinkFeature::wireValue)

        public fun parse(value: String): SnaplinkFeature? = byWire[value]

        internal fun isKnown(wireValue: String): Boolean = byWire.containsKey(wireValue)
    }
}

/** A stable quota dimension, mirroring `commerce.LimitKey`. */
public enum class SnaplinkLimit(public val wireValue: String) {
    USERS("users"),
    CLIENTS("clients"),
    SESSIONS("sessions"),
    TOKEN_RATE("token_rate"),
    STORAGE_BYTES("storage_bytes"),
    STORAGE_OBJECTS("storage_objects");

    public companion object {
        private val byWire = entries.associateBy(SnaplinkLimit::wireValue)

        public fun parse(value: String): SnaplinkLimit? = byWire[value]
    }
}

/**
 * Decodes a Snaplink entitlement document.
 *
 * Timestamps accept either RFC 3339 text or Unix seconds: fixtures and
 * hand-written entitlement files use Unix seconds while the live API uses
 * RFC 3339. An unparsable value decodes as absent rather than being guessed.
 */
internal object EntitlementJson {
    private val json = Json { ignoreUnknownKeys = true }

    fun decode(raw: String): SnaplinkEntitlement = json.decodeFromString(SnaplinkEntitlement.serializer(), raw)

}
