plugins {
	id("org.jetbrains.kotlin.jvm") version "2.2.20"
	id("org.ec4j.editorconfig") version "0.1.0"
	id("idea")
	signing
	`maven-publish`
}

val jwtGroupId = "me.saro"
val jwtArtifactId = "jwt"
val jwtVersion = "7.0.0"

repositories {
	mavenCentral()
}

java {
	withJavadocJar()
	withSourcesJar()
}

dependencies {
	// jackson
	implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.20.0")

	// test
    val junitVer = "6.0.0"
	testImplementation("org.junit.jupiter:junit-jupiter:$junitVer")
	testRuntimeOnly("org.junit.platform:junit-platform-launcher:$junitVer")
}

tasks.withType<Test> {
	useJUnitPlatform()
}

publishing {
	publications {
		create<MavenPublication>("maven") {

			groupId = jwtGroupId
			artifactId = jwtArtifactId
			version = jwtVersion

			from(components["java"])

			repositories {
				maven {
					credentials {
						try {
							username = project.property("sonatype.username").toString()
							password = project.property("sonatype.password").toString()
						} catch (e: Exception) {
							println("warn: " + e.message)
						}
					}
					val releasesRepoUrl = uri("https://oss.sonatype.org/service/local/staging/deploy/maven2/")
					val snapshotsRepoUrl = uri("https://oss.sonatype.org/content/repositories/snapshots/")
					url = if (version.toString().endsWith("SNAPSHOT")) snapshotsRepoUrl else releasesRepoUrl
				}
			}

			pom {
				name.set("SARO JWT")
				description.set("SARO JWT")
				url.set("https://saro.me")

				licenses {
					license {
						name.set("The Apache License, Version 2.0")
						url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
					}
				}
				developers {
					developer {
						name.set("PARK Yong Seo")
						email.set("j@saro.me")
					}
				}
				scm {
					connection.set("scm:git:git://github.com/saro-lab/jwt.git")
					developerConnection.set("scm:git:git@github.com:saro-lab/jwt.git")
					url.set("https://github.com/saro-lab/jwt")
				}
			}
		}
	}
}

signing {
	sign(publishing.publications["maven"])
}

tasks.withType<Test> {
	useJUnitPlatform()
	testLogging {
		events("passed", "failed", "skipped")
		showStandardStreams = true
	}
}

tasks.withType<Javadoc>().configureEach {
	options {
		this as StandardJavadocDocletOptions
		addBooleanOption("Xdoclint:none", true)
	}
}

configure<JavaPluginExtension> {
	sourceCompatibility = JavaVersion.VERSION_21
	targetCompatibility = JavaVersion.VERSION_21
}
