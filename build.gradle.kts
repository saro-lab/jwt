import java.net.HttpURLConnection
import java.net.URI
import java.util.*

plugins {
	id("org.jetbrains.kotlin.jvm") version "2.2.20"
	id("org.ec4j.editorconfig") version "0.1.0"
	id("idea")
	signing
	`maven-publish`
}

val jwtGroupId = "me.saro"
val jwtArtifactId = "jwt"
val jwtVersion = "7.0.2"

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
                    name = "ossrh-staging-api"
                    url = uri("https://ossrh-staging-api.central.sonatype.com/service/local/staging/deploy/maven2/")
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

tasks.named("publish").configure {
    doLast {
        val username = project.property("sonatype.username").toString()
        val password = project.property("sonatype.password").toString()
        val connection = URI.create("https://ossrh-staging-api.central.sonatype.com/manual/upload/defaultRepository/$jwtGroupId").toURL().openConnection() as HttpURLConnection
        connection.requestMethod = "POST"
        connection.setRequestProperty("Authorization", "Basic " + Base64.getEncoder().encodeToString("$username:$password".toByteArray()))
        connection.setRequestProperty("Content-Type", "application/json")
        connection.doOutput = true
        connection.outputStream.write("""{"publishing_type": "automatic"}""".toByteArray())
        val responseCode = connection.responseCode
        if (responseCode in 200..299) {
            println("Successfully uploaded to Central Portal")
        } else {
            throw GradleException("Failed to upload to Central Portal: $responseCode - ${connection.inputStream?.bufferedReader()?.readText()}")
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
