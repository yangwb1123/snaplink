plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.serialization")
}

group = "site.ywbsd.sso"
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
