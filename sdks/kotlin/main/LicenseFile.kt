package com.snaplink.sso

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.util.Base64

/**
 * The only algorithm and envelope version this build accepts.
 */
public object SnaplinkLicenseEnvelope {
    public const val ALGORITHM: String = "Ed25519"
    public const val VERSION: Int = 1
}

/**
 * A stable code for an entitlement-file failure.
 *
 * These originate in this SDK, never on the wire, and are namespaced so a
 * caller cannot confuse them with a network failure. None is recoverable by
 * retrying.
 */
public enum class SnaplinkLicenseErrorCode(public val wireValue: String) {
    MALFORMED("license_malformed"),
    ALGORITHM_UNSUPPORTED("license_algorithm_unsupported"),
    SIGNATURE_INVALID("license_signature_invalid"),
    UNTRUSTED_KEY("license_untrusted_key"),
    TRUST_UNCONFIGURED("license_trust_unconfigured"),

    /**
     * The platform has no Ed25519 verifier, so a signature cannot be checked.
     *
     * Android only exposes Ed25519 through the platform provider from API 33;
     * an older device fails closed here rather than accepting an unverified
     * file. This code is beyond the shared fixture's 13 cases, which pin the
     * server vocabulary plus the common license codes; it is namespaced and
     * license-classed like the rest.
     */
    VERIFIER_UNAVAILABLE("license_verifier_unavailable"),
}

/** An entitlement-file verification failure. */
public class SnaplinkLicenseException(
    public val code: SnaplinkLicenseErrorCode,
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause), SnaplinkClassifiedError {
    override val wireCode: String get() = code.wireValue

    /** Always null: a local verification failure has no HTTP status. */
    override val status: Int? get() = null
    override val classification: SnaplinkErrorClassification
        get() = SnaplinkErrorClassification.of(code.wireValue, null)
}

/**
 * A set of public keys an entitlement file may be signed by.
 *
 * A file names the `key_id` it was signed with, so a deployment can hold a
 * current and a next key during rotation without weakening verification. A trust
 * root is always supplied by the caller, which is what makes OEM and private-CA
 * deployments possible.
 */
public class SnaplinkLicenseTrust private constructor(private val keys: Map<String, ByteArray>) {

    /** Whether any key is trusted. */
    public val isEmpty: Boolean get() = keys.isEmpty()

    /** The trusted key identifiers, sorted, for diagnostics. */
    public val keyIds: List<String> get() = keys.keys.sorted()

    /** Returns a copy of this trust root with an additional raw 32-byte key. */
    public fun withKey(keyId: String, publicKey: ByteArray): SnaplinkLicenseTrust {
        require(keyId.isNotEmpty()) { "a trusted key needs an id" }
        require(publicKey.size == PUBLIC_KEY_BYTES) { "key $keyId is not $PUBLIC_KEY_BYTES bytes" }
        return SnaplinkLicenseTrust(keys + (keyId to publicKey.copyOf()))
    }

    /** Returns a copy of this trust root with an additional base64 key. */
    public fun withBase64Key(keyId: String, encoded: String): SnaplinkLicenseTrust {
        val raw = try {
            Base64.getDecoder().decode(encoded)
        } catch (error: IllegalArgumentException) {
            throw SnaplinkLicenseException(SnaplinkLicenseErrorCode.MALFORMED, "key $keyId is not base64", error)
        }
        return withKey(keyId, raw)
    }

    internal fun keyFor(keyId: String): ByteArray? = keys[keyId]

    public companion object {
        private const val PUBLIC_KEY_BYTES = 32

        /** An empty trust root. Every file is rejected until a key is added. */
        public fun empty(): SnaplinkLicenseTrust = SnaplinkLicenseTrust(emptyMap())

        /** A trust root for a single base64-encoded key. */
        public fun ofKey(keyId: String, base64Encoded: String): SnaplinkLicenseTrust =
            empty().withBase64Key(keyId, base64Encoded)
    }
}

/** A verified commercial entitlement read from a local file. */
public data class SnaplinkLicenseFile(
    val entitlement: SnaplinkEntitlement,
    val keyId: String,
) {
    /**
     * Classifies the file's entitlement at [now].
     *
     * The three-state classification is identical to the online path, so a
     * deployment moving between the two does not change behaviour.
     */
    public fun stateAt(now: Instant): SnaplinkLicenseState = entitlement.stateAt(now)
}

/**
 * Verifies a signed entitlement file entirely locally.
 *
 * `docs/commercial-model.md` requires that offline and private deployments gate
 * paid features from a signed file and that authentication never calls a vendor
 * licensing service on a login path. That second clause is only satisfiable
 * because this function performs no network I/O on any path, including login.
 *
 * The declared algorithm and version are checked before any signature work, so
 * `none` and friends are refused rather than tolerated. Any failure throws:
 * this never returns an inactive or free-tier entitlement in place of a
 * rejected file.
 */
public object SnaplinkLicenseFileVerifier {
    private const val SIGNATURE_BYTES = 64

    /** DER prefix of a SubjectPublicKeyInfo carrying an Ed25519 key (OID 1.3.101.112). */
    private val SPKI_PREFIX = byteArrayOf(
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ).map { it.toByte() }.toByteArray()

    /** Whether this platform can verify an Ed25519 signature at all. */
    public fun isSupported(): Boolean = try {
        Signature.getInstance(SnaplinkLicenseEnvelope.ALGORITHM)
        KeyFactory.getInstance(SnaplinkLicenseEnvelope.ALGORITHM)
        true
    } catch (_: Exception) {
        false
    }

    /** Verifies [raw] against [trust] and decodes the entitlement it carries. */
    public fun verify(raw: String, trust: SnaplinkLicenseTrust?): SnaplinkLicenseFile {
        if (trust == null || trust.isEmpty) {
            throw SnaplinkLicenseException(
                SnaplinkLicenseErrorCode.TRUST_UNCONFIGURED,
                "no trust root was supplied",
            )
        }
        val envelope = parse(raw)
        val key = trust.keyFor(envelope.keyId)
            ?: throw SnaplinkLicenseException(
                SnaplinkLicenseErrorCode.UNTRUSTED_KEY,
                "no trusted key is configured for ${envelope.keyId}",
            )
        val payload = decodeBase64(envelope.payload, "payload")
        val signature = decodeBase64(envelope.signature, "signature")
        if (signature.size != SIGNATURE_BYTES) {
            throw SnaplinkLicenseException(
                SnaplinkLicenseErrorCode.MALFORMED,
                "the signature is not $SIGNATURE_BYTES bytes",
            )
        }
        if (!verifySignature(key, payload, signature)) {
            throw SnaplinkLicenseException(
                SnaplinkLicenseErrorCode.SIGNATURE_INVALID,
                "the signature did not verify",
            )
        }
        val entitlement = try {
            EntitlementJson.decode(payload.toString(Charsets.UTF_8))
        } catch (error: Exception) {
            throw SnaplinkLicenseException(
                SnaplinkLicenseErrorCode.MALFORMED,
                "the payload is not an entitlement",
                error,
            )
        }
        return SnaplinkLicenseFile(entitlement, envelope.keyId)
    }

    private fun verifySignature(publicKey: ByteArray, payload: ByteArray, signature: ByteArray): Boolean = try {
        val key = KeyFactory.getInstance(SnaplinkLicenseEnvelope.ALGORITHM)
            .generatePublic(X509EncodedKeySpec(ed25519SubjectPublicKeyInfo(publicKey)))
        Signature.getInstance(SnaplinkLicenseEnvelope.ALGORITHM).run {
            initVerify(key)
            update(payload)
            verify(signature)
        }
    } catch (error: SnaplinkLicenseException) {
        throw error
    } catch (error: Exception) {
        // A platform without Ed25519 fails closed: an unverifiable file is
        // never treated as verified.
        if (!isSupported()) {
            throw SnaplinkLicenseException(
                SnaplinkLicenseErrorCode.VERIFIER_UNAVAILABLE,
                "this platform cannot verify ${SnaplinkLicenseEnvelope.ALGORITHM} signatures",
                error,
            )
        }
        throw SnaplinkLicenseException(
            SnaplinkLicenseErrorCode.SIGNATURE_INVALID,
            "the signature did not verify",
            error,
        )
    }

    /**
     * Wraps a raw 32-byte Ed25519 public key in the fixed SubjectPublicKeyInfo
     * DER for OID 1.3.101.112.
     *
     * Building the key from DER rather than [java.security.spec.EdECPoint]
     * keeps this working on the platform, whose EdECPoint takes x/y BigIntegers
     * and so needs Ed25519 little-endian decoding that the JDK hides.
     */
    private fun ed25519SubjectPublicKeyInfo(raw: ByteArray): ByteArray =
        SPKI_PREFIX + raw

    private fun decodeBase64(value: String, field: String): ByteArray = try {
        Base64.getDecoder().decode(value)
    } catch (error: IllegalArgumentException) {
        throw SnaplinkLicenseException(SnaplinkLicenseErrorCode.MALFORMED, "the $field is not base64", error)
    }

    private data class Envelope(
        val version: Int,
        val algorithm: String,
        val keyId: String,
        val payload: String,
        val signature: String,
    )

    private val envelopeJson = Json { ignoreUnknownKeys = true }

    /**
     * Decodes the envelope and applies the version and algorithm gate.
     *
     * A structurally incomplete envelope is malformed rather than silently
     * reading as version 0 with an empty algorithm: every SDK reports a missing
     * field the same way, and the shared fixture holds them to one answer.
     */
    private fun parse(raw: String): Envelope {
        val fields = runCatching { envelopeJson.parseToJsonElement(raw).jsonObject }
            .getOrElse {
                throw SnaplinkLicenseException(
                    SnaplinkLicenseErrorCode.MALFORMED,
                    "the license file is not a readable envelope",
                    it,
                )
            }
        fun string(name: String): String = (fields[name] as? JsonPrimitive)
            ?.takeIf { it.isString }
            ?.content
            ?: throw SnaplinkLicenseException(
                SnaplinkLicenseErrorCode.MALFORMED,
                "the license envelope is missing $name",
            )
        val version = (fields["version"] as? JsonPrimitive)
            ?.content?.toIntOrNull()
            ?: throw SnaplinkLicenseException(
                SnaplinkLicenseErrorCode.MALFORMED,
                "the license envelope is missing version",
            )
        val envelope = Envelope(
            version = version,
            algorithm = string("algorithm"),
            keyId = string("key_id"),
            payload = string("payload"),
            signature = string("signature"),
        )
        if (envelope.version != SnaplinkLicenseEnvelope.VERSION) {
            throw SnaplinkLicenseException(
                SnaplinkLicenseErrorCode.ALGORITHM_UNSUPPORTED,
                "envelope version ${envelope.version} is not supported",
            )
        }
        if (envelope.algorithm != SnaplinkLicenseEnvelope.ALGORITHM) {
            throw SnaplinkLicenseException(
                SnaplinkLicenseErrorCode.ALGORITHM_UNSUPPORTED,
                "algorithm ${envelope.algorithm} is not supported",
            )
        }
        return envelope
    }
}
