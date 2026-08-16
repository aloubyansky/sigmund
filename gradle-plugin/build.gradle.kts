plugins {
    `java-gradle-plugin`
    `maven-publish`
}

group = "dev.cyberstamp.sigmund"
version = "0.0.2-SNAPSHOT"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

repositories {
    mavenLocal()
    mavenCentral()
}

dependencies {
    implementation("dev.cyberstamp.sigmund:sigmund-core:0.0.2-SNAPSHOT")
    testImplementation("org.junit.jupiter:junit-jupiter:6.1.3")
    testImplementation("org.assertj:assertj-core:3.27.7")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher:6.1.3")
}

gradlePlugin {
    plugins {
        create("sigmund") {
            id = "dev.cyberstamp.sigmund"
            implementationClass = "dev.cyberstamp.sigmund.gradle.SigmundPlugin"
        }
    }
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}
