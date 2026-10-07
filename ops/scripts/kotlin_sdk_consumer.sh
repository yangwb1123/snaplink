#!/usr/bin/env bash
# Compile and test a real external Android consumer, using only the candidate POM.
# Requires the workspace's JDK/Android SDK. Never publishes to a remote registry.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/snaplink-kotlin-consumer.XXXXXX")"
trap 'rm -rf -- "$tmp"' EXIT

python3 - "$root" "$tmp" <<'PY'
from pathlib import Path
import re
import sys

root, temp = map(Path, sys.argv[1:])
plugins = (root / "sdks/build.gradle.kts").read_text(encoding="utf-8")
module = (root / "sdks/kotlin/build.gradle.kts").read_text(encoding="utf-8")

def one(pattern, text):
    values = re.findall(pattern, text, flags=re.MULTILINE)
    if len(values) != 1:
        raise SystemExit("candidate toolchain/version cannot be determined")
    return values[0]

agp = one(r'id\("com.android.library"\) version "([0-9.]+)"', plugins)
kotlin = one(r'id\("org.jetbrains.kotlin.android"\) version "([0-9.]+)"', plugins)
version = one(r'^version = "([0-9A-Za-z.+-]+)"$', module)
# Gradle reads the standard external project's source folders, never SDK sources.
consumer = temp / "consumer"
consumer.mkdir()
(consumer / "main").mkdir()
(consumer / "test").mkdir()
(consumer / "settings.gradle.kts").write_text(f'''
pluginManagement {{ repositories {{ google(); mavenCentral(); gradlePluginPortal() }} }}
dependencyResolutionManagement {{
    repositories {{
        maven {{
            url = uri("{(temp / 'repo').as_uri()}")
            // Exercise the POM, without Gradle module metadata masking a wrong scope.
            metadataSources {{ mavenPom(); artifact() }}
        }}
        google()
        mavenCentral()
    }}
}}
rootProject.name = "snaplink-external-consumer"
''', encoding="utf-8")
(consumer / "build.gradle.kts").write_text(f'''
plugins {{
    id("com.android.library") version "{agp}"
    id("org.jetbrains.kotlin.android") version "{kotlin}"
}}
android {{
    namespace = "example.consumer"
    compileSdk = 36
    defaultConfig {{ minSdk = 23 }}
    compileOptions {{
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        isCoreLibraryDesugaringEnabled = true
    }}
    kotlinOptions {{ jvmTarget = "17" }}
    sourceSets {{
        getByName("main") {{ manifest.srcFile("AndroidManifest.xml"); java.srcDirs("main") }}
        getByName("test") {{ java.srcDirs("test") }}
    }}
}}
dependencies {{
    implementation("cn.ywbsd.sso:snaplink:{version}")
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.5")
    testImplementation("junit:junit:4.13.2")
}}
''', encoding="utf-8")
(consumer / "gradle.properties").write_text("android.useAndroidX=true\norg.gradle.jvmargs=-Xmx1536m\n", encoding="utf-8")
(consumer / "AndroidManifest.xml").write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" />\n', encoding="utf-8")
(consumer / "main/PublicConsumer.kt").write_text('''
package example.consumer

import com.snaplink.sso.*
import okhttp3.OkHttpClient

fun configuredClient(http: OkHttpClient): SnaplinkAuthClient = SnaplinkAuthClient(
    SnaplinkMemorySecureStore(), // Test/development only; applications use encrypted storage.
    SnaplinkConfiguration("https://sso.example.test", "native-app", "com.example.app:/oauth/callback"),
    SnaplinkOkHttpTransport(http),
)

fun callerTransport(): SnaplinkHttpTransport = SnaplinkHttpTransport { request ->
    check(request.method == "GET")
    check(request.headers["Authorization"] != null)
    // Only a compile fixture, not an application HTTP implementation.
    SnaplinkHttpResponse(503, "{\\"error\\":\\"temporarily_unavailable\\"}")
}

suspend fun navigation(client: SnaplinkAuthClient): List<SnaplinkMenuNode> {
    check(client.isLoggedIn())
    val identity: SnaplinkAuthorization = client.authorization()
    check(identity.clientId.isNotBlank() && identity.subject.isNotBlank())
    identity.hasRole("viewer")
    identity.allows("order:read")
    return identity.visibleMenus().onEach { it.actions(identity.permissions) }
}
''', encoding="utf-8")
(consumer / "test/PublicConsumerTest.kt").write_text('''
package example.consumer

import com.snaplink.sso.*
import okhttp3.OkHttpClient
import org.junit.Assert.*
import org.junit.Test

class PublicConsumerTest {
    @Test fun publicConstructorsAndPermissionRulesAreUsable() {
        assertNotNull(configuredClient(OkHttpClient.Builder().build()))
        assertTrue(SnaplinkPermissions.holds(listOf("order:*"), "order:read"))
        assertFalse(SnaplinkPermissions.holds(listOf("order:*"), "orders:read"))
    }
    @Test fun publicRequestFactoryAndDiagnosticsAreUsable() {
        val request = SnaplinkRequestFactory.bearerRead("https://sso.example.test", "userinfo", bearer = "private-bearer")
        assertEquals("GET", request.method)
        assertFalse(request.toString().contains("private-bearer"))
        assertFalse(SnaplinkHttpResponse(200, "private-body").toString().contains("private-body"))
        assertNotNull(callerTransport())
    }
}
''', encoding="utf-8")
PY

# Opt out of signing/Central even if the caller's environment enables release flags.
cd "$root/sdks"
./gradlew --no-daemon --no-configuration-cache --no-build-cache \
    -PmavenCentralPublishing=false -PsignAllPublications=false \
    -Dmaven.repo.local="$tmp/repo" :snaplink:publishToMavenLocal
./gradlew --no-daemon --no-configuration-cache --no-build-cache \
    --project-dir "$tmp/consumer" testDebugUnitTest assembleRelease
printf 'External Kotlin consumer passed (POM-only resolution; no remote publication).\n'
