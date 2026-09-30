package com.snaplink.sso

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.doubleOrNull
import java.io.File
import java.time.Instant

/**
 * Cross-language conformance for the error taxonomy.
 *
 * The cases in `ops/build/sdk-conformance/errors.json` are the shared contract.
 */
class ErrorTaxonomyConformanceTest {
    private val cases: List<Map<String, Any?>> = sharedFixture("errors.json")["cases"] as List<Map<String, Any?>>

    @Test
    fun `every shared case is classified with its documented class`() {
        assertTrue("the shared error fixture must not be empty", cases.isNotEmpty())
        for (case in cases) {
            val code = case["code"] as String
            val expectedClass = case["class"] as String
            val entry = SnaplinkErrorCatalog.entryFor(code)
            assertNotNull("the controlled vocabulary is missing $code", entry)
            assertEquals("case $code is classified wrongly", expectedClass, entry!!.errorClass.name.lowercase())
        }
    }

    @Test
    fun `server code is carried verbatim and never rewritten`() {
        for (case in cases) {
            val code = case["code"] as String
            val status = (case["status"] as? Number)?.toInt()
            val error = SnaplinkAuthException(code, "server said so", status)
            assertEquals(code, error.wireCode)
            assertEquals(status, error.status)
            assertEquals(code, error.classification.code)
            assertEquals(
                (case["class"] as String),
                error.classification.errorClass.name.lowercase(),
            )
        }
    }

    @Test
    fun `unknown server code stays verbatim without being forced into a class`() {
        val error = SnaplinkAuthException("some_future_code", "x", 418)
        assertEquals("some_future_code", error.classification.code)
        assertEquals(418, error.classification.status)
        assertEquals(SnaplinkErrorClass.SDK, error.classification.errorClass)
        assertNull(SnaplinkErrorCatalog.entryFor("some_future_code"))
    }

    @Test
    fun `license codes are never remapped onto a network error`() {
        for (code in SnaplinkLicenseErrorCode.entries) {
            val error = SnaplinkLicenseException(code, "local failure")
            assertEquals(code.wireValue, error.classification.code)
            assertEquals(SnaplinkErrorClass.LICENSE, error.classification.errorClass)
            assertNull("a local verification failure has no HTTP status", error.status)
            assertEquals(SnaplinkErrorRecovery.TERMINAL, error.classification.recovery)
        }
    }

    @Test
    fun `recovery guidance matches the documented responses`() {
        val expected = mapOf(
            "activation_unavailable" to SnaplinkErrorRecovery.RETRY_WITH_BACKOFF,
            "activation_invalid" to SnaplinkErrorRecovery.TERMINAL,
            "invalid_grant" to SnaplinkErrorRecovery.REAUTHENTICATE,
            "invalid_client" to SnaplinkErrorRecovery.TERMINAL,
            "invalid_scope" to SnaplinkErrorRecovery.FIX_REQUEST,
            "insufficient_scope" to SnaplinkErrorRecovery.FIX_REQUEST,
            "invalid_token" to SnaplinkErrorRecovery.REAUTHENTICATE,
            "session_invalid" to SnaplinkErrorRecovery.RECREATE_CEREMONY,
            "mfa_invalid" to SnaplinkErrorRecovery.RECREATE_CEREMONY,
        )
        for ((code, recovery) in expected) {
            assertEquals("$code recovery guidance drifted", recovery, SnaplinkErrorCatalog.entryFor(code)!!.recovery)
        }
    }

    @Test
    fun `invalid grant is never instructed to retry refresh forever`() {
        val entry = SnaplinkErrorCatalog.entryFor("invalid_grant")!!
        assertFalse(entry.recovery == SnaplinkErrorRecovery.RETRY_WITH_BACKOFF)
    }

    @Test
    fun `insufficient scope is distinct from invalid scope`() {
        assertEquals(SnaplinkErrorClass.AUTHORIZATION, SnaplinkErrorCatalog.entryFor("insufficient_scope")!!.errorClass)
        assertEquals(SnaplinkErrorClass.OAUTH, SnaplinkErrorCatalog.entryFor("invalid_scope")!!.errorClass)
    }

    @Test
    fun `every error type is catchable through one shape`() {
        val errors = listOf<SnaplinkClassifiedError>(
            SnaplinkAuthException("invalid_grant", "denied", 400),
            SnaplinkLicenseException(SnaplinkLicenseErrorCode.SIGNATURE_INVALID, "local failure"),
        )
        assertEquals(
            listOf(SnaplinkErrorClass.OAUTH, SnaplinkErrorClass.LICENSE),
            errors.map { it.classification.errorClass },
        )
        for (error in errors) {
            assertTrue(error.wireCode.isNotEmpty())
        }
    }

    @Test
    fun `the catalog is a superset of the shared vocabulary`() {
        // This SDK adds one namespaced license code for a platform that cannot
        // verify Ed25519; the shared fixture pins the rest.
        for (entry in SnaplinkErrorCatalog.entries()) {
            assertNotNull(entry.code)
        }
        assertEquals(SnaplinkErrorClass.LICENSE, SnaplinkErrorCatalog.entryFor("license_verifier_unavailable")!!.errorClass)
    }
}

/** Cross-language conformance for entitlement semantics. */
class EntitlementConformanceTest {
    private val document = sharedFixture("entitlement.json")
    private val cases = document["cases"] as List<Map<String, Any?>>
    private val referenceNow: Instant = Instant.ofEpochSecond((document["reference_now"] as Number).toLong())

    @Test
    fun `every shared case is classified identically`() {
        for (case in cases) {
            val id = case["id"] as String
            val entitlement = decode(case["entitlement"])
            val now = (case["now"] as? Number)?.let { Instant.ofEpochSecond(it.toLong()) } ?: referenceNow
            val state = context(entitlement).licenseStateAt(now)

            assertEquals("case $id classified as ${state.kind}", case["expect_state"] as String, state.kind.wireValue)
            val expectedReason = case["expect_inactive_reason"] as String?
            if (expectedReason != null) {
                assertEquals("case $id inactive reason", expectedReason, state.reason?.wireValue)
            } else {
                assertNull("case $id must not report an inactive reason", state.reason)
            }
        }
    }

    @Test
    fun `feature lookups match the shared expectation`() {
        @Suppress("UNCHECKED_CAST")
        for (case in cases) {
            val id = case["id"] as String
            val expected = case["expect_features"] as? Map<String, Boolean> ?: continue
            val entitlement = decode(case["entitlement"])!!
            val now = (case["now"] as? Number)?.let { Instant.ofEpochSecond(it.toLong()) } ?: referenceNow
            for ((key, granted) in expected) {
                val feature = SnaplinkFeature.parse(key)
                assertNotNull("case $id expects an unknown feature $key", feature)
                assertEquals("case $id feature $key", granted, entitlement.has(feature!!, now))
            }
        }
    }

    @Test
    fun `limit lookups match the shared expectation`() {
        for (case in cases) {
            val id = case["id"] as String
            @Suppress("UNCHECKED_CAST")
            val expected = case["expect_limits"] as? Map<String, Map<String, Any?>> ?: continue
            val entitlement = decode(case["entitlement"])!!
            val now = (case["now"] as? Number)?.let { Instant.ofEpochSecond(it.toLong()) } ?: referenceNow
            for ((key, grant) in expected) {
                val limit = SnaplinkLimit.parse(key)
                assertNotNull("case $id expects an unknown limit $key", limit)
                val resolved = entitlement.limit(limit!!, now)
                assertNotNull("case $id limit $key must resolve while active", resolved)
                assertEquals("case $id soft", (grant["soft"] as Number).toLong(), resolved!!.soft)
                assertEquals("case $id hard", (grant["hard"] as Number).toLong(), resolved.hard)
                assertEquals(
                    "case $id unlimited must short-circuit the soft-hard pair",
                    grant["unlimited"] as? Boolean ?: false,
                    resolved.unlimited,
                )
            }
        }
    }

    @Test
    fun `an inactive entitlement grants nothing`() {
        for (case in cases) {
            val id = case["id"] as String
            if (case["expect_state"] == "active") continue
            val entitlement = decode(case["entitlement"]) ?: continue
            val now = (case["now"] as? Number)?.let { Instant.ofEpochSecond(it.toLong()) } ?: referenceNow
            for (feature in SnaplinkFeature.entries) {
                assertFalse("case $id: ${feature.wireValue} must not be granted", entitlement.has(feature, now))
            }
            for (limit in SnaplinkLimit.entries) {
                assertNull("case $id: ${limit.wireValue} must not resolve", entitlement.limit(limit, now))
            }
        }
    }

    @Test
    fun `an absent entitlement is never treated as unlimited`() {
        val state = context(null).licenseStateAt(referenceNow)
        assertEquals(SnaplinkLicenseStateKind.NOT_ACTIVATED, state.kind)
        assertFalse(state.isActive)
        assertNull(state.entitlement)
    }

    @Test
    fun `timestamps decode from unix seconds and rfc 3339`() {
        val unix = decode(
            """{"tenant_id":"t1","subscription_id":"s1","plan":{"id":"pro","version":2},"revision":1,
               "active":true,"features":{},"limits":{},"effective_at":1699999940,"generated_at":1699999940}""",
        )!!
        assertEquals(Instant.ofEpochSecond(1_699_999_940), unix.effectiveAt)
        assertNull(unix.expiresAt)

        val text = decode(
            """{"tenant_id":"t1","subscription_id":"s1","plan":{"id":"pro","version":2},"revision":1,
               "active":true,"features":{},"limits":{},"effective_at":"2026-01-01T00:00:00Z",
               "expires_at":"2026-02-01T00:00:00.500Z","generated_at":"2026-01-01T00:00:00Z"}""",
        )!!
        assertEquals(Instant.parse("2026-01-01T00:00:00Z"), text.effectiveAt)
        assertEquals(Instant.parse("2026-02-01T00:00:00.500Z"), text.expiresAt)
    }

    @Test
    fun `an unparsable timestamp decodes as absent rather than guessed`() {
        val entitlement = decode(
            """{"tenant_id":"t1","subscription_id":"s1","plan":{"id":"pro","version":2},"revision":1,
               "active":true,"features":{"scim":true},"limits":{},
               "effective_at":"whenever","expires_at":"nonsense","generated_at":"2026-01-01T00:00:00Z"}""",
        )!!
        assertNull(entitlement.effectiveAt)
        assertNull(entitlement.expiresAt)
    }

    @Test
    fun `an omitted unlimited flag is not an error`() {
        val entitlement = decode(
            """{"tenant_id":"t1","subscription_id":"s1","plan":{"id":"pro","version":1},"revision":1,
               "active":true,"features":{},"limits":{"users":{"soft":5,"hard":10}},
               "effective_at":1699000000}""",
        )!!
        assertFalse(entitlement.limit(SnaplinkLimit.USERS, Instant.ofEpochSecond(1_700_000_000))!!.unlimited)
    }

    @Test
    fun `unknown feature keys are preserved and reported`() {
        val entitlement = decode(
            """{"tenant_id":"t1","subscription_id":"s1","plan":{"id":"pro","version":1},"revision":1,
               "active":true,"features":{"scim":true,"quantum_signing":true},"limits":{},
               "effective_at":1699000000}""",
        )!!
        assertEquals(listOf("quantum_signing"), entitlement.unknownFeatures)
    }

    private fun context(entitlement: SnaplinkEntitlement?) =
        SnaplinkAccountContext(productId = "fixture", tenantId = "fixture", entitlement = entitlement)

    private fun decode(value: Any?): SnaplinkEntitlement? = when (value) {
        null -> null
        is String -> EntitlementJson.decode(value)
        else -> EntitlementJson.decode(Json.encodeToString(JsonElement.serializer(), toJsonElement(value)))
    }

    private fun toJsonElement(value: Any?): JsonElement = when (value) {
        null -> JsonNull
        is String -> JsonPrimitive(value)
        is Boolean -> JsonPrimitive(value)
        is Number -> JsonPrimitive(value)
        is Map<*, *> -> JsonObject(value.entries.associate { (key, item) -> key.toString() to toJsonElement(item) })
        is List<*> -> JsonArray(value.map(::toJsonElement))
        else -> JsonPrimitive(value.toString())
    }
}

/** Loads a shared cross-language contract from `ops/build/sdk-conformance/`. */
internal fun sharedFixture(name: String): Map<String, Any?> {
    val root = generateSequence(File(System.getProperty("user.dir"))) { it.parentFile }
        .first { File(it, "ops/build/sdk-conformance/$name").isFile }
    val document = Json.parseToJsonElement(File(root, "ops/build/sdk-conformance/$name").readText())
    return toMap(document)
}

private fun toMap(element: JsonElement): Map<String, Any?> =
    element.jsonObject.entries.associate { (key, value) -> key to toPlain(value) }

private fun toPlain(element: JsonElement): Any? = when (element) {
    is JsonNull -> null
    is JsonPrimitive -> when {
        element.isString -> element.content
        element.content == "true" -> true
        element.content == "false" -> false
        // Keep integers integral: a Double would re-serialise as "3.0" and
        // break every whole-number field in the contract.
        else -> element.longOrNull ?: element.doubleOrNull
    }
    is JsonObject -> toMap(element)
    is JsonArray -> element.map(::toPlain)
}
