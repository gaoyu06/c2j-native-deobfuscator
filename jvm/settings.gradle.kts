pluginManagement {
    repositories {
        mavenCentral()
        gradlePluginPortal()
    }
}

rootProject.name = "j2c-dumper-jvm"

include(":common")
include(":jar-parser")
include(":trace-to-bytecode")
include(":class-rebuilder")
include(":dynamic-trace-agent-java")
