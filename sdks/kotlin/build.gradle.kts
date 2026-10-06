plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.serialization")
    id("maven-publish")
    // Required explicitly: maven-publish does not apply the signing plugin, and
    // without it the signing {} extension below does not exist.
    id("signing")
}

group = "cn.ywbsd.sso"
version = "0.3.0"

android {
    namespace = "com.snaplink.sso"
    compileSdk = 36

    defaultConfig {
        minSdk = 23
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    sourceSets {
        getByName("main") {
            manifest.srcFile("AndroidManifest.xml")
            java.setSrcDirs(listOf("main"))
        }
        getByName("test") {
            java.setSrcDirs(listOf("test"))
        }
        getByName("androidTest") {
            java.setSrcDirs(listOf("androidTest"))
        }
    }

    publishing {
        // Maven Central requires a sources jar and a javadoc jar alongside the
        // AAR, and rejects the upload without them. Both are generated from this
        // single variant so they can never drift from what is shipped.
        singleVariant("release") {
            withSourcesJar()
            withJavadocJar()
        }
    }

    compileOptions {
        // minSdk is 23 but the SDK uses java.time and java.util.Base64, which
        // the platform only provides from API 26. Core library desugaring
        // back-ports them for older devices without raising minSdk, and is the
        // resolution android lint's NewApi check accepts for these calls.
        //
        // This is recorded in the AAR metadata (coreLibraryDesugaringEnabled
        // plus desugarJdkLib), so a consuming app must also enable core library
        // desugaring in its own build. That is a real, deliberate trade for
        // keeping minSdk at 23: the alternative is raising minSdk to 26.
        isCoreLibraryDesugaringEnabled = true
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation("androidx.browser:browser:1.8.0")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.5")

    testImplementation("junit:junit:4.13.2")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")

    androidTestImplementation("androidx.test:core:1.6.1")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
}

// ── Publication ────────────────────────────────────────────────────
//
// The coordinate follows the naming scheme in sdks/README.md: the groupId is
// the reverse-DNS form of the product host sso.ywbsd.cn, because Maven
// Central verifies a groupId against a domain the publisher controls, and the
// brand sits in the artifactId. `com.snaplink` would assert a domain this
// project does not own.
//
// The POM is written out in full rather than left to defaults because Central
// rejects an upload whose POM is missing a name, description, url, licence,
// developer or scm section, and because a published artefact is immutable: a
// coordinate that has to be retired is a coordinate nobody can fix.
publishing {
    repositories {
        // The Central upload target, registered only when credentials are present
        // so that local verification and ordinary CI builds never require them.
        //
        // The endpoint is Sonatype's OSSRH staging API. Sonatype has been
        // migrating publishing to the Central Portal, and the two are not
        // interchangeable, so this URL must be confirmed against Sonatype's
        // current documentation before the first real publish. Everything around
        // it - the coordinate, the artifact set, the POM and the signing - is
        // verified, so a wrong endpoint fails at the upload step with a clear
        // error rather than publishing anything wrong.
        val centralUser: String? = providers.environmentVariable("CENTRAL_TOKEN_USERNAME").orNull
        val centralPassword: String? = providers.environmentVariable("CENTRAL_TOKEN_PASSWORD").orNull
        if (centralUser != null && centralPassword != null) {
            maven {
                name = "sonatype"
                url = uri("https://oss.sonatype.org/service/local/staging/deploy/maven2/")
                credentials {
                    username = centralUser
                    password = centralPassword
                }
            }
        }
    }

    publications {
        register<MavenPublication>("release") {
            groupId = "cn.ywbsd.sso"
            artifactId = "snaplink"
            version = project.version.toString()

            afterEvaluate { from(components["release"]) }

            pom {
                name.set("Snaplink Android SDK")
                description.set(
                    "Android SDK for the snaplink/sso OAuth 2.0 and OpenID Connect hosted login."
                )
                url.set("https://github.com/yangwb1123/snaplink/tree/main/sdks/kotlin")

                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                        distribution.set("repo")
                    }
                }
                developers {
                    developer {
                        id.set("snaplink")
                        name.set("Snaplink contributors")
                    }
                }
                scm {
                    url.set("https://github.com/yangwb1123/snaplink")
                    connection.set("scm:git:https://github.com/yangwb1123/snaplink.git")
                    developerConnection.set("scm:git:ssh://git@github.com/yangwb1123/snaplink.git")
                }
                issueManagement {
                    system.set("GitHub Issues")
                    url.set("https://github.com/yangwb1123/snaplink/issues")
                }
            }
        }
    }
}

// Central requires every published artifact to be GPG-signed, and the signing
// key must never live in the repository. Signing is therefore wired to key
// material supplied by the environment and simply not applied when it is
// absent, so a local `publishToMavenLocal` needs no secrets and still verifies
// the artifact set and the POM.
val signingKey: String? = providers.environmentVariable("MAVEN_SIGNING_KEY").orNull
val signingPassword: String? = providers.environmentVariable("MAVEN_SIGNING_PASSWORD").orNull
signing {
    if (signingKey != null && signingPassword != null) {
        useInMemoryPgpKeys(signingKey, signingPassword)
        sign(publishing.publications)
    }
}
