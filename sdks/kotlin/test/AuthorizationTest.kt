package com.snaplink.sso

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.TimeUnit

class AuthorizationTest {
    @Test
    fun `permission matching uses every case in the shared corpus`() {
        val cases = sharedFixture("authorization.json")["cases"] as List<Map<String, Any?>>
        assertEquals(13, cases.size)
        for (case in cases) {
            assertEquals(
                case["id"] as String,
                case["expect"] as Boolean,
                SnaplinkPermissions.holds(case["held"] as List<String>, case["required"] as String),
            )
        }
    }

    @Test
    fun `the public read assembles the configured clients identity and projection`() = runBlocking {
        val fixture = InjectedClientFixture()
        fixture.login()
        fixture.handler = { request -> SnaplinkHttpResponse(200, authorizationBodies().getValue(request.path)) }
        val authorization = fixture.client.authorization()
        assertEquals("subject-1", authorization.subject)
        assertEquals("native-app", authorization.clientId)
        assertEquals("person@example.test", authorization.email)
        assertTrue(authorization.hasRole("viewer"))
        assertTrue(authorization.allows("panel:config:apply"))
        assertFalse(authorization.allows("billing:read"))
        assertEquals(listOf("/token") + AUTHORIZATION_PATHS, fixture.requests.map { it.path })
        for (request in fixture.requests.drop(1)) {
            assertEquals("GET", request.method)
            assertEquals("Bearer access-private", request.headers["Authorization"])
            assertEquals("no-store", request.headers["Cache-Control"])
            assertEquals("no-cache", request.headers["Pragma"])
            if (request.path != "/userinfo") assertTrue(request.url.endsWith("?client_id=native-app"))
        }
    }

    @Test
    fun `an anonymous client cannot request or fabricate authorization`() = runBlocking {
        val fixture = InjectedClientFixture()
        val error = runCatching { fixture.client.authorization() }.exceptionOrNull() as SnaplinkAuthException
        assertEquals("login_required", error.errorCode)
        assertTrue(fixture.requests.isEmpty())
    }

    @Test
    fun `explicit empty grant and menu arrays are valid without granting anything`() = runBlocking {
        val fixture = InjectedClientFixture()
        fixture.login()
        fixture.handler = { request ->
            SnaplinkHttpResponse(200, authorizationBodies(permissions = "[]", roles = "[]", menus = "[]").getValue(request.path))
        }
        val result = fixture.client.authorization()
        assertEquals("subject-1", result.subject)
        assertTrue(result.permissions.isEmpty())
        assertTrue(result.roles.isEmpty())
        assertTrue(result.menus.isEmpty())
        assertFalse(result.allows("panel:read"))
    }

    @Test
    fun `missing or malformed subject fails before any grant requests`() = runBlocking {
        for (identity in listOf("{}", """{"sub":null}""", """{"sub":7}""", """{"sub":" "}""", "[]")) {
            val fixture = InjectedClientFixture()
            fixture.login()
            fixture.handler = { SnaplinkHttpResponse(200, identity) }
            assertInvalid { fixture.client.authorization() }
            assertEquals(listOf("/token", "/userinfo"), fixture.requests.map { it.path })
        }
    }

    @Test
    fun `each failed endpoint aborts instead of returning a partial projection`() = runBlocking {
        for (failedPath in AUTHORIZATION_PATHS) {
            val fixture = InjectedClientFixture()
            fixture.login()
            fixture.handler = { request ->
                if (request.path == failedPath) SnaplinkHttpResponse(503, """{"error":"permission_lookup_failed"}""")
                else SnaplinkHttpResponse(200, authorizationBodies().getValue(request.path))
            }
            val error = runCatching { fixture.client.authorization() }.exceptionOrNull() as SnaplinkAuthException
            assertEquals("permission_lookup_failed", error.errorCode)
            assertEquals(503, error.httpStatus)
            assertEquals(
                listOf("/token") + AUTHORIZATION_PATHS.take(AUTHORIZATION_PATHS.indexOf(failedPath) + 1),
                fixture.requests.map { it.path },
            )
        }
    }

    @Test
    fun `unconfigured and disabled permission routes are errors not empty navigation`() = runBlocking {
        for (status in listOf(404, 501)) {
            val fixture = InjectedClientFixture()
            fixture.login()
            fixture.handler = { request ->
                if (request.path == "/userinfo") SnaplinkHttpResponse(200, authorizationBodies().getValue(request.path))
                else SnaplinkHttpResponse(status, """{"error":"permission_provider_not_configured"}""")
            }
            val error = runCatching { fixture.client.authorization() }.exceptionOrNull() as SnaplinkAuthException
            assertEquals(status, error.httpStatus)
            assertEquals("permission_provider_not_configured", error.errorCode)
        }
    }

    @Test
    fun `every scoped projection must echo the configured client id`() = runBlocking {
        for (path in AUTHORIZATION_PATHS.drop(1)) {
            for (wrongClient in listOf("other-client", "")) {
                val fixture = InjectedClientFixture()
                fixture.login()
                fixture.handler = { request ->
                    val bodies = authorizationBodies()
                    val body = bodies.getValue(request.path)
                    SnaplinkHttpResponse(200, if (request.path == path) body.replace("native-app", wrongClient) else body)
                }
                assertInvalid { fixture.client.authorization() }
            }
        }
    }

    @Test
    fun `missing or null arrays and invalid grant codes cannot masquerade as empty success`() = runBlocking {
        val invalidBodies = listOf(
            "{}", """{"client_id":"native-app"}""",
            """{"client_id":"native-app","permissions":null}""",
            """{"client_id":"native-app","permissions":{}}""",
            """{"client_id":"native-app","permissions":[{}]}""",
            """{"client_id":"native-app","permissions":[{"code":true}]}""",
            """{"client_id":"native-app","permissions":[""]}""",
        )
        for (body in invalidBodies) {
            val fixture = InjectedClientFixture()
            fixture.login()
            fixture.handler = { request ->
                SnaplinkHttpResponse(200, if (request.path == "/permissions/me") body else authorizationBodies().getValue(request.path))
            }
            assertInvalid { fixture.client.authorization() }
        }
    }

    @Test
    fun `missing or null roles and menus fail the complete read`() = runBlocking {
        for (path in listOf("/roles/me", "/menus/me")) {
            val field = path.removePrefix("/").substringBefore('/')
            for (body in listOf("""{"client_id":"native-app"}""", """{"client_id":"native-app","$field":null}""")) {
                val fixture = InjectedClientFixture()
                fixture.login()
                fixture.handler = { request ->
                    SnaplinkHttpResponse(200, if (request.path == path) body else authorizationBodies().getValue(request.path))
                }
                assertInvalid { fixture.client.authorization() }
            }
        }
    }

    @Test
    fun `menu null permissions or malformed structure never become unrestricted display`() = runBlocking {
        val invalidMenus = listOf(
            "null", "[null]", """[{"id":"x"}]""",
            """[{"id":"x","name":"X","permission":null}]""",
            """[{"id":"x","name":"X","buttons":null}]""",
            """[{"id":"x","name":"X","children":{}}]""",
            """[{"id":"x","name":"X","buttons":[{"code":"go","permission":false}]}]""",
        )
        for (menus in invalidMenus) {
            val fixture = InjectedClientFixture()
            fixture.login()
            fixture.handler = { request -> SnaplinkHttpResponse(200, authorizationBodies(menus = menus).getValue(request.path)) }
            assertInvalid { fixture.client.authorization() }
        }
    }

    @Test
    fun `visible menus recursively filter denied parents and buttons without changing the raw tree`() {
        val open = SnaplinkMenuNode("open", "Open", buttons = listOf(
            SnaplinkMenuButton("view"), SnaplinkMenuButton("read", permission = "panel:read"),
            SnaplinkMenuButton("bill", permission = "billing:write"),
        ), children = listOf(
            SnaplinkMenuNode("allowed", "Allowed", permission = "panel:read"),
            SnaplinkMenuNode("denied", "Denied", permission = "billing:write"),
        ))
        val deniedParent = SnaplinkMenuNode("hidden", "Hidden", permission = "billing:write", children = listOf(open))
        val authorization = SnaplinkAuthorization("s", "c", null, null, emptyList(), listOf("panel:*"), listOf(open, deniedParent))
        val visible = authorization.visibleMenus()
        assertEquals(listOf("open"), visible.map { it.id })
        assertEquals(listOf("view", "read"), visible.single().buttons.map { it.code })
        assertEquals(listOf("allowed"), visible.single().children.map { it.id })
        assertEquals(3, open.buttons.size)
        assertEquals(2, open.children.size)
    }

    @Test
    fun `menu depth is bounded even when the JSON response fits the byte limit`() = runBlocking {
        for (depth in listOf(32, 33)) {
            var node = """{"id":"leaf","name":"Leaf"}"""
            repeat(depth - 1) { node = """{"id":"parent-$it","name":"Parent","children":[$node]}""" }
            val fixture = InjectedClientFixture()
            fixture.login()
            fixture.handler = { request -> SnaplinkHttpResponse(200, authorizationBodies(menus = "[$node]").getValue(request.path)) }
            if (depth == 32) assertEquals(1, fixture.client.authorization().visibleMenus().size)
            else assertInvalid { fixture.client.authorization() }
        }
    }

    @Test(timeout = 10_000)
    fun `clear or logout during a read prevents late grants and further requests`() = runBlocking {
        for (revoke in listOf(false, true)) {
            val fixture = InjectedClientFixture()
            fixture.login()
            val started = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            fixture.handler = { request ->
                if (request.path == "/token/revoke") SnaplinkHttpResponse(200)
                else {
                    started.complete(Unit)
                    release.await()
                    SnaplinkHttpResponse(200, authorizationBodies().getValue(request.path))
                }
            }
            val read = async(Dispatchers.Default) { runCatching { fixture.client.authorization() } }
            started.await()
            if (revoke) fixture.client.logout() else fixture.client.clear()
            release.complete(Unit)
            val error = read.await().exceptionOrNull() as SnaplinkAuthException
            assertEquals("login_required", error.errorCode)
            assertFalse(fixture.client.isLoggedIn())
            assertFalse(fixture.requests.any { it.path == "/permissions/me" })
        }
    }

    @Test(timeout = 10_000)
    fun `a replacement login cannot inherit an in flight authorization projection`() = runBlocking {
        val fixture = InjectedClientFixture()
        fixture.login()
        val started = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        fixture.handler = { request ->
            if (request.path == "/token") tokenResponse("replacement")
            else {
                started.complete(Unit)
                release.await()
                SnaplinkHttpResponse(200, authorizationBodies().getValue(request.path))
            }
        }
        val read = async(Dispatchers.Default) { runCatching { fixture.client.authorization() } }
        started.await()
        fixture.login()
        release.complete(Unit)
        assertEquals("login_required", (read.await().exceptionOrNull() as SnaplinkAuthException).errorCode)
        assertEquals("replacement", fixture.client.accessToken())
        assertFalse(fixture.requests.any { it.path == "/permissions/me" })
    }

    @Test
    fun `reads never reuse a cached grant projection`() = runBlocking {
        val fixture = InjectedClientFixture()
        fixture.login()
        fixture.handler = { request -> SnaplinkHttpResponse(200, authorizationBodies().getValue(request.path)) }
        assertTrue(fixture.client.authorization().allows("panel:read"))
        fixture.handler = { request -> SnaplinkHttpResponse(200, authorizationBodies(permissions = "[]").getValue(request.path)) }
        assertFalse(fixture.client.authorization().allows("panel:read"))
        assertEquals(9, fixture.requests.size)
    }

    @Test
    fun `wire reads bind UTF8 client ids without leaking the bearer into a URL`() = runBlocking {
        val server = MockWebServer()
        val bodies = authorizationBodies(clientId = "中+")
        AUTHORIZATION_PATHS.forEach { server.enqueue(MockResponse().setBody(bodies.getValue(it))) }
        server.start()
        try {
            val config = SnaplinkConfiguration(server.url("/").toString(), "中+", "com.example.app:/oauth/callback", allowInsecureHttpForDevelopment = true)
            val result = HttpAuthorizationTransport(config).read("bearer-private")
            assertEquals("subject-1", result.subject)
            for (path in AUTHORIZATION_PATHS) {
                val request = server.takeRequest(2, TimeUnit.SECONDS)!!
                assertEquals(path, request.requestUrl!!.encodedPath)
                assertEquals("Bearer bearer-private", request.getHeader("Authorization"))
                assertEquals(null, request.getHeader("Cookie"))
                assertFalse(request.path!!.contains("bearer-private"))
                if (path != "/userinfo") assertEquals("中+", request.requestUrl!!.queryParameter("client_id"))
            }
        } finally {
            server.shutdown()
        }
    }

    private suspend fun assertInvalid(block: suspend () -> Unit) {
        val error = runCatching { block() }.exceptionOrNull() as SnaplinkAuthException
        assertEquals("invalid_response", error.errorCode)
    }
}

private val AUTHORIZATION_PATHS = listOf("/userinfo", "/permissions/me", "/roles/me", "/menus/me")

private fun authorizationBodies(
    clientId: String = "native-app",
    permissions: String = """[{"code":"panel:*"}]""",
    roles: String = """[{"code":"viewer"}]""",
    menus: String = """[{"id":"home","name":"Home","buttons":[{"code":"view"}]}]""",
): Map<String, String> = mapOf(
    "/userinfo" to """{"sub":"subject-1","email":"person@example.test","name":"Person"}""",
    "/permissions/me" to """{"client_id":"$clientId","permissions":$permissions}""",
    "/roles/me" to """{"client_id":"$clientId","roles":$roles}""",
    "/menus/me" to """{"client_id":"$clientId","menus":$menus}""",
)
