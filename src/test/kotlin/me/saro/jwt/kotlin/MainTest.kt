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
        val builder = jwtKeyManager.getJwtBuilder()
        builder.claim("name", name)
        builder.encryptClaim("encode", encode)
        builder.setIssuedAtNow()
        builder.setExpireMinutes(30)
        builder.claim(ClaimName.id, "id")
        builder.claim(ClaimName.subject, "sub")
        builder.claim(ClaimName.issuer, "iss")
        val jwt = builder.build()
        println("- JWT")
        println(jwt)
        println("- header / payload")
        jwt.split(".").stream().limit(2)
            .map { e: String -> String(Base64.getDecoder().decode(e.replace('-', '+').replace('_', '/'))) }
            .forEach { x: String? -> println(x) }
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
}