//package me.saro.jwt.kotlin
//
//import io.jsonwebtoken.SignatureAlgorithm
//import me.saro.jwt.old.JwtKeyManager
//import me.saro.jwt.old.impl.DefaultJwtKeyManager.Companion.create
//import org.junit.jupiter.api.Assertions
//import org.junit.jupiter.api.DisplayName
//import org.junit.jupiter.api.Test
//import java.util.*
//
//@DisplayName("[Kotlin] MainTest")
//class MainTest {
//    @Test
//    fun normal() {
//        val name = "안녕 hello !@#$"
//        val encode = "안녕 hello !@#$"
//        val jwtKeyManager: JwtKeyManager = create(SignatureAlgorithm.RS256)
//        val jwt = jwtKeyManager.getJwtBuilder()
//            .claim("name", name)
//            .encryptClaim("encode", encode)
//            .issuedAtNow()
//            .expireMinutes(30)
//            .id("id")
//            .subject("sub")
//            .issuer("iss")
//            .build()
//
//        println("jwt: $jwt")
//
//        val header = String(Base64.getDecoder().decode(jwt.split(".")[0]))
//        println("header: $header")
//
//        val payload = String(Base64.getDecoder().decode(jwt.split(".")[1]))
//        println("payload: $payload")
//
//        val jwtReader = jwtKeyManager.parse(jwt)
//        Assertions.assertEquals(name, jwtReader.claim("name"))
//        Assertions.assertEquals(encode, jwtReader.decryptClaim("encode"))
//    }
//
//    @Test
//    fun `signature pass and error`() {
//        val m1: JwtKeyManager = create(SignatureAlgorithm.RS256)
//        val m2: JwtKeyManager = create(SignatureAlgorithm.RS256)
//        val jwt = m1.getJwtBuilder().claim("text", "hello").build()
//        Assertions.assertDoesNotThrow {
//            val reader = m1.parse(jwt)
//            println(reader.claim("text"))
//        }
//        Assertions.assertThrows(SecurityException::class.java) {
//            val reader = m2.parse(jwt)
//            println(reader.claim("text"))
//        }
//    }
//
//
//    @Test
//    fun example() {
//        // algorithm: RS256, key rotation queue size: 3, key rotation minutes: 30
//        // key stored [rotation minutes (30) * queue size (3)] = 90 minutes
//        val jwtKeyManager: JwtKeyManager = create(SignatureAlgorithm.RS256, 3, 30)
//
//        val jwt = jwtKeyManager.getJwtBuilder()
//            .encryptClaim("jti", "1234")
//            .subject("sub")
//            .issuer("iss")
//            .issuedAtNow()
//            .expireMinutes(30)
//            .build()
//        println("jwt: $jwt")
//
//        val header = String(Base64.getDecoder().decode(jwt.split(".")[0]))
//        println("header: $header")
//
//        val payload = String(Base64.getDecoder().decode(jwt.split(".")[1]))
//        println("payload: $payload")
//
//        val jwtReader = jwtKeyManager.parse(jwt)
//
//        val result = mapOf(
//            "id" to jwtReader.decryptClaim("jti"),
//            "subject" to jwtReader.subject,
//            "issuer" to jwtReader.issuer,
//            "issuedAt" to jwtReader.issuedAt,
//            "expire" to jwtReader.expire
//        )
//        println("result: $result")
//    }
//}