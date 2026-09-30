package com.snaplink.sso

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.time.Instant
import java.util.Base64

/**
 * Cross-language conformance for entitlement-file verification.
 *
 * The cases in `ops/build/sdk-conformance/license_file.json` are the shared
 * contract. The signing key below is a test fixture generated for this suite and
 * is deliberately not a vendor key: the point of these tests is the verification
 * outcome, not the provenance of the trust root.
 */
class LicenseFileConformanceTest {
    private val referenceNow = Instant.ofEpochSecond(1_700_000_000)
    private val vendorKeyId = "vendor-2026"
    private val untrustedKeyId = "untrusted-2026"

    private val vendorKeyPair: java.security.KeyPair by lazy { keyPair() }
    private val untrustedKeyPair: java.security.KeyPair by lazy { keyPair() }

    @Test
    fun `valid signature verifies offline and grants the entitlement`() {
        val file = verify(makeFile())
        assertEquals(vendorKeyId, file.keyId)
        assertTrue(file.entitlement.has(SnaplinkFeature.SCIM, referenceNow))
        assertTrue(file.stateAt(referenceNow).isActive)
    }

    @Test
    fun `a tampered payload does not verify`() {
        val original = payload()
        val tampered = original.copyOf().also { it[0] = (it[0] + 1).toByte() }
        val fields = decodeEnvelope(makeFile())
        fields["payload"] = base64(tampered)
        val error = assertLicenseFails { verify(encodeEnvelope(fields)) }
        assertEquals(SnaplinkLicenseErrorCode.SIGNATURE_INVALID, error.code)
    }

    @Test
    fun `a signature from an untrusted key does not verify`() {
        val fields = decodeEnvelope(makeFile(signer = untrustedKeyPair))
        val error = assertLicenseFails { verify(encodeEnvelope(fields)) }
        assertEquals(SnaplinkLicenseErrorCode.SIGNATURE_INVALID, error.code)
    }

    @Test
    fun `a caller pinned key is accepted`() {
        val file = verify(
            makeFile(signer = untrustedKeyPair, keyId = untrustedKeyId),
            trust = SnaplinkLicenseTrust.ofKey(untrustedKeyId, publicKeyBase64(untrustedKeyPair)),
        )
        assertEquals(untrustedKeyId, file.keyId)
        assertTrue(file.stateAt(referenceNow).isActive)
    }

    @Test
    fun `an expired entitlement is inactive rather than an error`() {
        val file = verify(makeFile())
        val afterExpiry = referenceNow.plusSeconds(40L * 24 * 3600)
        val state = file.stateAt(afterExpiry)
        assertEquals(SnaplinkLicenseStateKind.INACTIVE, state.kind)
        assertEquals(SnaplinkInactiveReason.EXPIRED, state.reason)
        assertFalse(file.entitlement.has(SnaplinkFeature.SCIM, afterExpiry))
    }

    @Test
    fun `a malformed envelope is an error not an empty entitlement`() {
        val error = assertLicenseFails { verify("not json at all") }
        assertEquals(SnaplinkLicenseErrorCode.MALFORMED, error.code)
    }

    @Test
    fun `a missing envelope field is malformed`() {
        val fields = decodeEnvelope(makeFile())
        fields.remove("key_id")
        val error = assertLicenseFails { verify(encodeEnvelope(fields)) }
        assertEquals(SnaplinkLicenseErrorCode.MALFORMED, error.code)
    }

    @Test
    fun `an unsupported algorithm is refused before signature work`() {
        val fields = decodeEnvelope(makeFile())
        fields["algorithm"] = "none"
        val error = assertLicenseFails { verify(encodeEnvelope(fields)) }
        assertEquals(SnaplinkLicenseErrorCode.ALGORITHM_UNSUPPORTED, error.code)
    }

    @Test
    fun `an unsupported envelope version is refused`() {
        val fields = decodeEnvelope(makeFile())
        fields["version"] = "2"
        val error = assertLicenseFails { verify(encodeEnvelope(fields)) }
        assertEquals(SnaplinkLicenseErrorCode.ALGORITHM_UNSUPPORTED, error.code)
    }

    @Test
    fun `an unknown key id is untrusted`() {
        val error = assertLicenseFails { verify(makeFile(keyId = "rotated-away")) }
        assertEquals(SnaplinkLicenseErrorCode.UNTRUSTED_KEY, error.code)
    }

    @Test
    fun `an empty trust root refuses every file`() {
        for (trust in listOf(null, SnaplinkLicenseTrust.empty())) {
            val error = assertLicenseFails { verify(makeFile(), trust) }
            assertEquals(SnaplinkLicenseErrorCode.TRUST_UNCONFIGURED, error.code)
        }
    }

    @Test
    fun `malformed key material is rejected at trust construction`() {
        val failure = runCatching { SnaplinkLicenseTrust.ofKey("k", "not base64!") }.exceptionOrNull()
        assertTrue(failure is SnaplinkLicenseException)
        assertEquals(SnaplinkLicenseErrorCode.MALFORMED, (failure as SnaplinkLicenseException).code)

        val shortKey = runCatching { SnaplinkLicenseTrust.empty().withKey("k", byteArrayOf(1, 2, 3)) }.exceptionOrNull()
        assertTrue(shortKey is IllegalArgumentException)
    }

    @Test
    fun `a trust root reports its key identifiers`() {
        val trust = SnaplinkLicenseTrust.empty()
            .withBase64Key("b", publicKeyBase64(vendorKeyPair))
            .withBase64Key("a", publicKeyBase64(untrustedKeyPair))
        assertTrue(trust.keyIds == listOf("a", "b"))
        assertFalse(trust.isEmpty)
        assertTrue(SnaplinkLicenseTrust.empty().isEmpty)
    }

    @Test
    fun `the platform verifier is reported rather than assumed`() {
        // On a JVM host Ed25519 is present; on older Android it is not. The SDK
        // must say which, and must fail closed when it is absent.
        assertTrue(
            "the JVM host must support Ed25519 for this suite",
            SnaplinkLicenseFileVerifier.isSupported(),
        )
        assumeTrue(SnaplinkLicenseFileVerifier.isSupported())
    }

    @Test
    fun `verification never returns an active entitlement for a rejected file`() {
        val cases = listOf<() -> SnaplinkLicenseFile>(
            { verify("not json at all") },
            { verify(makeFile(keyId = "rotated-away")) },
            { verify(makeFile(algorithm = "none")) },
            { verify(makeFile(), SnaplinkLicenseTrust.empty()) },
        )
        for (case in cases) {
            val failure = runCatching(case).exceptionOrNull()
            assertTrue("a rejected file must throw, never return an entitlement", failure is SnaplinkLicenseException)
        }
    }

    // MARK: - Fixture plumbing

    /**
     * A signing keypair for this run.
     *
     * The shared fixture's bytes are placeholders, so the key is generated
     * rather than pinned: the trust root below is built from the same pair, and
     * what is under test is the verification outcome, not key provenance.
     */
    private fun keyPair(): java.security.KeyPair =
        KeyPairGenerator.getInstance("Ed25519").generateKeyPair()

    private fun publicKeyBase64(keyPair: java.security.KeyPair): String =
        base64(keyPair.public.encoded.copyOfRange(12, 44))

    /** The entitlement payload: active from the reference epoch, expiring 30 days later. */
    private fun payload(): ByteArray = """
        {"tenant_id":"tenant-1","subscription_id":"sub-1","plan":{"id":"pro","version":1},
         "revision":1,"active":true,"features":{"scim":true,"core_sso":true},
         "limits":{"users":{"soft":5,"hard":10,"unlimited":false}},
         "effective_at":1699999940,"expires_at":1702591940,"generated_at":1699999940}
    """.trimIndent().toByteArray()

    private fun makeFile(
        signer: java.security.KeyPair = vendorKeyPair,
        keyId: String? = null,
        algorithm: String = SnaplinkLicenseEnvelope.ALGORITHM,
    ): String {
        val payload = payload()
        val signature = Signature.getInstance("Ed25519").run {
            initSign(signer.private)
            update(payload)
            sign()
        }
        return encodeEnvelope(
            linkedMapOf(
                "version" to SnaplinkLicenseEnvelope.VERSION.toString(),
                "algorithm" to algorithm,
                "key_id" to (keyId ?: vendorKeyId),
                "payload" to base64(payload),
                "signature" to base64(signature),
            ),
        )
    }

    private fun verify(
        raw: String,
        trust: SnaplinkLicenseTrust? = SnaplinkLicenseTrust.ofKey(
            vendorKeyId,
            publicKeyBase64(vendorKeyPair),
        ),
    ): SnaplinkLicenseFile = SnaplinkLicenseFileVerifier.verify(raw, trust)

    private fun assertLicenseFails(body: () -> SnaplinkLicenseFile): SnaplinkLicenseException {
        val failure = runCatching(body).exceptionOrNull()
        assertNotNull("verification must not succeed", failure)
        assertTrue("expected a SnaplinkLicenseException, got $failure", failure is SnaplinkLicenseException)
        return failure as SnaplinkLicenseException
    }

    private fun base64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

    private fun encodeEnvelope(fields: Map<String, String?>): String =
        fields.entries.joinToString(",", "{", "}") { (key, value) ->
            if (value == null) "" else "\"$key\":\"$value\""
        }

    private fun decodeEnvelope(raw: String): LinkedHashMap<String, String?> {
        val fields = LinkedHashMap<String, String?>()
        for (match in Regex("\"([a-z_]+)\":\"?([^\",}]*)\"?}?").findAll(raw.substringBeforeLast('}'))) {
            fields[match.groupValues[1]] = match.groupValues[2]
        }
        return fields
    }

    @Test
    fun `shared fixture case identifiers are all implemented here`() {
        val cases = sharedFixture("license_file.json")["cases"] as List<Map<String, Any?>>
        val implemented = setOf(
            "valid_signature",
            "tampered_payload",
            "signature_from_wrong_key",
            "caller_pinned_key",
            "expired_entitlement",
            "malformed_envelope",
            "unsupported_algorithm",
        )
        val documented = cases.mapNotNull { it["id"] as? String }.toSet()
        for (id in implemented) {
            assertTrue("fixture case $id disappeared", documented.contains(id))
        }
    }

    @Test
    fun `the verified entitlement agrees with the online classification`() {
        val file = verify(makeFile())
        val online = SnaplinkAccountContext("pro", "tenant-1", file.entitlement)
        assertEquals(online.licenseStateAt(referenceNow).kind, file.stateAt(referenceNow).kind)
    }

    @Test
    fun `an empty payload signature length is reported as malformed`() {
        val fields = decodeEnvelope(makeFile())
        fields["signature"] = base64(ByteArray(10))
        val error = assertLicenseFails { verify(encodeEnvelope(fields)) }
        assertEquals(SnaplinkLicenseErrorCode.MALFORMED, error.code)
    }
}
