plugins {
    java
}

repositories {
    mavenCentral()
}

dependencyLocking {
    lockAllConfigurations()
}

dependencies {
    implementation("org.apache.logging.log4j:log4j-core:2.14.1")
    implementation("com.squareup.okhttp3:okhttp:4.9.0")
    testImplementation("junit:junit:4.12")
}
