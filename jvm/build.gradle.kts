plugins {
    kotlin("jvm") version "2.0.21" apply false
}

allprojects {
    repositories {
        mavenCentral()
    }
}

subprojects {
    apply(plugin = "org.jetbrains.kotlin.jvm")
    apply(plugin = "java")

    extensions.configure<JavaPluginExtension> {
        toolchain {
            languageVersion.set(JavaLanguageVersion.of(17))
        }
    }

    extensions.configure<org.jetbrains.kotlin.gradle.dsl.KotlinJvmProjectExtension> {
        jvmToolchain(17)
    }

    dependencies {
        val implementation by configurations
        val testImplementation by configurations
        implementation("org.ow2.asm:asm:9.7")
        implementation("org.ow2.asm:asm-tree:9.7")
        implementation("org.ow2.asm:asm-commons:9.7")
        implementation("org.ow2.asm:asm-util:9.7")
        implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.17.2")
        implementation("info.picocli:picocli:4.7.6")
        testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
    }

    tasks.withType<Test>().configureEach {
        useJUnitPlatform()
    }
}
