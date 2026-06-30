plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.libertygsm.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.libertygsm.app"
        minSdk = 21
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
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
