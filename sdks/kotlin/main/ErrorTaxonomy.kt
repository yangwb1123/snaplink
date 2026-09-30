package com.snaplink.sso

/**
 * The class of an error code, from the shared taxonomy in
 * `ops/build/sdk-conformance/errors.json`.
 *
 * The class is what a caller branches on for behaviour; the code is what it
 * logs. A server code is carried verbatim, so this SDK never invents a local
 * variant for one.
 */
public enum class SnaplinkErrorClass {
    OAUTH,
    ACTIVATION,
    AUTHORIZATION,
    AUTHENTICATION,
    COMMERCE,
    LICENSE,

    /** A code this SDK originated, never one the server sent. */
    SDK,
}

/** What a caller should do about a code. */
public enum class SnaplinkErrorRecovery {
    /** Terminal for this operation; do not retry. */
    TERMINAL,

    /** Transient server-side failure; bounded retry with backoff. */
    RETRY_WITH_BACKOFF,

    /** The grant or token is gone; authenticate again. */
    REAUTHENTICATE,

    /** The ceremony must be re-run, such as a new WebAuthn or MFA step. */
    RECREATE_CEREMONY,

    /** The request will never be issuable as written. */
    FIX_REQUEST,
}

/** One entry in the controlled code vocabulary. */
public data class SnaplinkErrorEntry(
    val code: String,
    val errorClass: SnaplinkErrorClass,
    val recovery: SnaplinkErrorRecovery,
)

/**
 * The controlled code vocabulary and its classification.
 *
 * The vocabulary is sourced from `docs/error-codes.md` plus the SDK-originated
 * license class. A code the server sends that is not in this table is still
 * surfaced verbatim through [SnaplinkErrorClassification.code]; it simply
 * carries no known class, so a caller cannot mistake an unknown code for a
 * known one.
 */
public object SnaplinkErrorCatalog {
    private val table: Map<String, SnaplinkErrorEntry> = buildMap {
        fun entry(code: String, errorClass: SnaplinkErrorClass, recovery: SnaplinkErrorRecovery) {
            put(code, SnaplinkErrorEntry(code, errorClass, recovery))
        }
        // Oracle-safe collapsing is preserved end to end: each wire code appears
        // once, with no per-cause variant.
        entry("activation_invalid", SnaplinkErrorClass.ACTIVATION, SnaplinkErrorRecovery.TERMINAL)
        entry("activation_not_found", SnaplinkErrorClass.ACTIVATION, SnaplinkErrorRecovery.FIX_REQUEST)
        entry("activation_unavailable", SnaplinkErrorClass.ACTIVATION, SnaplinkErrorRecovery.RETRY_WITH_BACKOFF)
        entry("invalid_grant", SnaplinkErrorClass.OAUTH, SnaplinkErrorRecovery.REAUTHENTICATE)
        entry("invalid_client", SnaplinkErrorClass.OAUTH, SnaplinkErrorRecovery.TERMINAL)
        entry("invalid_scope", SnaplinkErrorClass.OAUTH, SnaplinkErrorRecovery.FIX_REQUEST)
        entry("insufficient_scope", SnaplinkErrorClass.AUTHORIZATION, SnaplinkErrorRecovery.FIX_REQUEST)
        entry("invalid_token", SnaplinkErrorClass.AUTHENTICATION, SnaplinkErrorRecovery.REAUTHENTICATE)
        entry("session_invalid", SnaplinkErrorClass.AUTHENTICATION, SnaplinkErrorRecovery.RECREATE_CEREMONY)
        entry("mfa_invalid", SnaplinkErrorClass.AUTHENTICATION, SnaplinkErrorRecovery.RECREATE_CEREMONY)
        entry("commerce_entitlement_not_found", SnaplinkErrorClass.COMMERCE, SnaplinkErrorRecovery.FIX_REQUEST)
        entry("commerce_tenant_subscribed", SnaplinkErrorClass.COMMERCE, SnaplinkErrorRecovery.FIX_REQUEST)
        SnaplinkLicenseErrorCode.entries.forEach { code ->
            entry(code.wireValue, SnaplinkErrorClass.LICENSE, SnaplinkErrorRecovery.TERMINAL)
        }
    }

    /** The entry for a code, or null when the server sent one this build does not recognise. */
    public fun entryFor(code: String): SnaplinkErrorEntry? = table[code]

    /** Every classified code, sorted. */
    public fun entries(): List<SnaplinkErrorEntry> = table.values.sortedBy { it.code }
}

/**
 * A code, its class, and the recovery a caller should take.
 *
 * [code] is always the verbatim value: the server's code for a protocol failure,
 * or this SDK's own namespaced code otherwise. Nothing is remapped.
 */
public data class SnaplinkErrorClassification(
    val code: String,
    val status: Int?,
    val errorClass: SnaplinkErrorClass,
    val recovery: SnaplinkErrorRecovery,
) {
    public companion object {
        /** Classifies a code, preferring the server's status. */
        public fun of(code: String, status: Int?): SnaplinkErrorClassification {
            val entry = SnaplinkErrorCatalog.entryFor(code)
            return if (entry == null) {
                // An unrecognised code stays verbatim and is reported as
                // SDK-originated rather than forced into a known class.
                SnaplinkErrorClassification(code, status, SnaplinkErrorClass.SDK, SnaplinkErrorRecovery.TERMINAL)
            } else {
                SnaplinkErrorClassification(code, status, entry.errorClass, entry.recovery)
            }
        }
    }
}

/**
 * One shape a caller can catch for every SDK failure, so auth, commerce, and
 * license errors are handled through a single `catch`.
 */
public interface SnaplinkClassifiedError {
    /**
     * The verbatim code: the server's for a protocol failure, or this SDK's own
     * namespaced value otherwise.
     *
     * Named for the wire value rather than `code` so a strongly typed error
     * code member can coexist with it.
     */
    public val wireCode: String

    /** The HTTP status when the failure came from the server; null when local. */
    public val status: Int?

    public val classification: SnaplinkErrorClassification
}
