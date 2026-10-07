package com.snaplink.sso

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.CookieJar
import okhttp3.OkHttpClient
import java.util.concurrent.TimeUnit

/**
 * Executes SDK-built requests without taking over OAuth or session management.
 *
 * Implementations must preserve method, URL, headers and body; never follow
 * redirects, attach cookies, cache credential responses, or log credentials.
 * Suspending implementations must not block the caller's dispatcher. Response
 * status and size are checked by the SDK even for a caller-supplied transport.
 */
public fun interface SnaplinkHttpTransport {
    public suspend fun execute(request: SnaplinkHttpRequest): SnaplinkHttpResponse
}

/** Raw HTTP result. Its diagnostic representation never includes the body. */
public class SnaplinkHttpResponse(
    public val status: Int,
    public val body: String = "",
) {
    override fun toString(): String = "SnaplinkHttpResponse(status=$status, body=<redacted>)"
}

/**
 * Default transport, optionally using caller-configured proxies or interceptors.
 *
 * Cookies, redirects and caches remain disabled. A caller may shorten the call
 * timeout but cannot make this adapter exceed its 15-second deadline. Custom
 * interceptors are trusted execution code and must obey the transport contract.
 */
public class SnaplinkOkHttpTransport(client: OkHttpClient = defaultClient()) : SnaplinkHttpTransport {
    private val client = client.newBuilder()
        .cookieJar(CookieJar.NO_COOKIES)
        .followRedirects(false)
        .followSslRedirects(false)
        .cache(null)
        .callTimeout(
            (client.callTimeoutMillis.takeIf { it > 0 }?.coerceAtMost(TIMEOUT_MILLIS) ?: TIMEOUT_MILLIS).toLong(),
            TimeUnit.MILLISECONDS,
        )
        .build()

    override suspend fun execute(request: SnaplinkHttpRequest): SnaplinkHttpResponse = withContext(Dispatchers.IO) {
        client.newCall(request.toOkHttp()).execute().use { response ->
            SnaplinkHttpResponse(
                status = response.code,
                body = response.body?.source()?.let(SnaplinkHttp::readBounded).orEmpty(),
            )
        }
    }

    private companion object {
        const val TIMEOUT_MILLIS = 15_000

        fun defaultClient(): OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(TIMEOUT_MILLIS.toLong(), TimeUnit.MILLISECONDS)
            .readTimeout(TIMEOUT_MILLIS.toLong(), TimeUnit.MILLISECONDS)
            .callTimeout(TIMEOUT_MILLIS.toLong(), TimeUnit.MILLISECONDS)
            .build()
    }
}
