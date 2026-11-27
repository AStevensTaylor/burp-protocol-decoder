plugins {
    java
}

group = "protocoldecoder"
// The version lives in gradle.properties so CI can override it with
// `-Pversion=<next>`; releases derive that number from the git tags.

// Identifies the exact build at runtime. CI provides the sha; a local build
// falls back to git, and to "unknown" outside a checkout.
val buildCommit: Provider<String> =
    providers.environmentVariable("GITHUB_SHA").map { it.take(7) }
        .orElse(
            providers.exec {
                commandLine("git", "rev-parse", "--short", "HEAD")
                isIgnoreExitValue = true
            }.standardOutput.asText.map { it.trim() }
        )
        .map { it.ifBlank { "unknown" } }
        .orElse("unknown")

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extensions:montoya-api:2026.7")
    implementation("org.mozilla:rhino:1.9.2")
    implementation("com.google.code.gson:gson:2.15.0")

    testImplementation("net.portswigger.burp.extensions:montoya-api:2026.7")
    testImplementation(platform("org.junit:junit-bom:6.1.3"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}


tasks.withType<JavaCompile>().configureEach {
    options.release.set(21)
    options.encoding = "UTF-8"
    options.compilerArgs.addAll(listOf("-Xlint:unchecked", "-Xlint:deprecation"))
}

tasks.test {
    useJUnitPlatform()
    systemProperty("java.awt.headless", "true")
    providers.gradleProperty("snapshotDir").orNull?.let { systemProperty("snapshotDir", it) }
}

// Burp loads a single jar, so bundle runtime dependencies (Rhino, Gson) into it.
tasks.jar {
    archiveFileName.set("burp-protocol-decoder-${project.version}.jar")
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) }) {
        exclude("META-INF/*.SF", "META-INF/*.DSA", "META-INF/*.RSA", "META-INF/MANIFEST.MF", "module-info.class", "META-INF/versions/*/module-info.class")
    }
    manifest {
        attributes(
            "Implementation-Title" to "Burp Protocol Decoder",
            "Implementation-Version" to project.version.toString(),
            "Implementation-Commit" to buildCommit.get(),
        )
    }
}
