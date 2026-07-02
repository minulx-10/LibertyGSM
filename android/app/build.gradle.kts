import java.io.FileInputStream
import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Release signing is read from android/keystore.properties (kept out of git).
// When it's absent (fresh clone / CI), the release build falls back to the debug
// key so `assembleRelease` still succeeds -- it just isn't distributable.
val keystorePropsFile = rootProject.file("keystore.properties")
val hasKeystore = keystorePropsFile.exists()
val keystoreProps = Properties().apply {
    if (hasKeystore) FileInputStream(keystorePropsFile).use { load(it) }
}

android {
    namespace = "com.libertygsm.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.libertygsm.app"
        minSdk = 21
        targetSdk = 34
        versionCode = 4
        versionName = "1.3.3"
    }

    signingConfigs {
        if (hasKeystore) {
            create("release") {
                storeFile = file(keystoreProps["storeFile"] as String)
                storePassword = keystoreProps["storePassword"] as String
                keyAlias = keystoreProps["keyAlias"] as String
                keyPassword = keystoreProps["keyPassword"] as String
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = if (hasKeystore) {
                signingConfigs.getByName("release")
            } else {
                signingConfigs.getByName("debug")
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        viewBinding = true
    }
}

dependencies {
    // libgsm.aar is produced by ../build-aar.sh (gomobile bind of core-go/tunnel).
    // fileTree so Gradle still syncs before it's generated (compile then fails
    // on the tunnel.* imports with a clear message until you run build-aar).
    implementation(fileTree("libs") { include("*.aar") })
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
}
