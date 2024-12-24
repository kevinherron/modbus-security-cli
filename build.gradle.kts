plugins {
    kotlin("jvm") version "2.0.21"
    application
    id("com.gradleup.shadow") version "9.0.0-beta4"
}

group = "com.kevinherron.modbus"
version = "1.0-SNAPSHOT"

application {
    mainClass = "ModbusSecurityServerKt"
}

repositories {
    mavenLocal()
    mavenCentral()
}

dependencies {
    implementation("com.digitalpetri.modbus:modbus-tcp:2.0.2-SNAPSHOT")
    implementation("org.bouncycastle:bcprov-jdk18on:1.79")
    implementation("org.bouncycastle:bcpkix-jdk18on:1.79")
    implementation("org.slf4j:slf4j-simple:2.0.16")

    testImplementation(kotlin("test"))
    testImplementation("io.stepfunc:rodbus:1.4.0")
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(17)
}
