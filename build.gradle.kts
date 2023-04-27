import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "1.8.0"
    application
}

group = "me.corite"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
    maven { url= uri("https://jitpack.io") }
}

dependencies {
    testImplementation(kotlin("test"))
    implementation("com.github.corite:aes-128:v0.5-alpha")
}

tasks.test {
    useJUnitPlatform()
}
tasks.withType<KotlinCompile> {
    kotlinOptions.jvmTarget = "17"
    kotlinOptions.freeCompilerArgs += "-Xopt-in=kotlin.RequiresOptIn"
}

kotlin {
    jvmToolchain(17)
}

application {
    mainClass.set("me.corite.crypto.MainKt")
}