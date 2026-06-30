pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.PREFER_SETTINGS)
    repositories {
        google()
        mavenCentral()
        flatDir { dirs("app/libs") } // libgsm.aar produced by gomobile bind
    }
}

rootProject.name = "LibertyGSM"
include(":app")
