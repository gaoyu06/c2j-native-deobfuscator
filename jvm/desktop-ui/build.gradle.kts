plugins {
    kotlin("jvm")
    application
}

// Swing uses the full JDK 21 toolchain configured for every module in the root build.

dependencies {
    implementation(project(":common"))
    // FlatLaf: a flat Swing look-and-feel. Pinned; no browser, no JavaFX.
    implementation("com.formdev:flatlaf:3.5.4")
    // Gradle 9 no longer puts the JUnit Platform launcher on the test
    // runtime classpath automatically; add it so tests run.
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

application {
    mainClass.set("j2c.desktop.MainKt")
}

// Offscreen screenshot export. Renders each viewer state to a PNG under
// jvm/desktop-ui/screenshots/ without a human at the keyboard. Run under
// Xvfb on headless machines:  xvfb-run ./gradlew :desktop-ui:exportShots
tasks.register<JavaExec>("exportShots") {
    group = "verification"
    description = "Render viewer states to screenshots/ (needs a display or Xvfb)."
    dependsOn("testClasses")
    mainClass.set("j2c.desktop.ShotExporterKt")
    classpath = sourceSets["test"].runtimeClasspath
    workingDir = projectDir
    args = listOf("screenshots")
}
