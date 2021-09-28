package me.saro.jwt.kotlin

import io.jsonwebtoken.SignatureAlgorithm
import me.saro.jwt.JwtKeyManager
import me.saro.jwt.impl.DefaultJwtKeyManager.Companion.create
import me.saro.jwt.model.ClaimName
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import java.util.*

@DisplayName("[Kotlin] JwtReader")
class MainTest {
    @Test
    fun `normal`() {
        val name = "안녕 hello !@#$"
        val encode = "안녕 hello !@#$"
        val jwtKeyManager: JwtKeyManager = create(SignatureAlgorithm.RS256)
        val jwt = jwtKeyManager.getJwtBuilder()
            .claim("name", name)
            .encryptClaim("encode", encode)
            .setIssuedAtNow()
            .setExpireMinutes(30)
            .claim(ClaimName.id, "id")
            .claim(ClaimName.subject, "sub")
            .claim(ClaimName.issuer, "iss")
            .build()

        println("jwt: $jwt")

        val header = String(Base64.getDecoder().decode(jwt.split(".")[0]))
        println("header: $header")

        val payload = String(Base64.getDecoder().decode(jwt.split(".")[1]))
        println("payload: $payload")

        val jwtReader = jwtKeyManager.parse(jwt)
        Assertions.assertEquals(jwtReader.claim("name").toString(), name)
        Assertions.assertEquals(jwtReader.decryptClaim("encode").toString(), encode)
    }

    @Test
    fun `signature pass and error`() {
        val m1: JwtKeyManager = create(SignatureAlgorithm.RS256)
        val m2: JwtKeyManager = create(SignatureAlgorithm.RS256)
        val jwt = m1.getJwtBuilder().claim("text", "hello").build()
        Assertions.assertDoesNotThrow {
            val reader = m1.parse(jwt)
            println(reader.claim("text"))
        }
        Assertions.assertThrows(SecurityException::class.java) {
            val reader = m2.parse(jwt)
            println(reader.claim("text"))
        }
    }


    @Test
    fun `example`() {
        // algorithm: RS256, key rotation queue size: 3, key rotation minutes: 30
        // key stored [rotation minutes (30) * queue size (3)] = 90 minutes
        val jwtKeyManager: JwtKeyManager = create(SignatureAlgorithm.RS256, 3, 30)

        val jwt = jwtKeyManager.getJwtBuilder()
            .encryptClaim(ClaimName.id, "1234")
            .claim(ClaimName.subject, "sub")
            .claim(ClaimName.issuer, "iss")
            .setIssuedAtNow()
            .setExpireMinutes(30)
            .build()
        println("jwt: $jwt")

        val header = String(Base64.getDecoder().decode(jwt.split(".")[0]))
        println("header: $header")

        val payload = String(Base64.getDecoder().decode(jwt.split(".")[1]))
        println("payload: $payload")

        val jwtReader = jwtKeyManager.parse(jwt)

        val result = mapOf(
            "id" to jwtReader.decryptClaim(ClaimName.id),
            "subject" to jwtReader.claim(ClaimName.subject),
            "issuer" to jwtReader.claim(ClaimName.issuer),
            "issuedAt" to jwtReader.claim("iat"),
            "expire" to jwtReader.claim("exp")
        )
        println("result: $result")
    }
}