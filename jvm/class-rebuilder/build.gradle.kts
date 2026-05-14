plugins {
    kotlin("jvm")
    application
}

dependencies {
    implementation(project(":common"))
}

application {
    mainClass.set("j2c.classrebuilder.MainKt")
}
