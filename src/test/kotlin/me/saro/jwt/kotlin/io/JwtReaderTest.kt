package me.saro.jwt.kotlin.io

import io.jsonwebtoken.SignatureAlgorithm
import me.saro.jwt.JwtKeyManager
import me.saro.jwt.impl.DefaultJwtKeyManager.Companion.create
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

@DisplayName("[Kotlin] JwtReader")
class JwtReaderTest {
    @Test
    fun read() {
        val name = "안녕 hello !@#$"
        val encode = "안녕 hello !@#$"
        val jwtKeyManager: JwtKeyManager = create(SignatureAlgorithm.RS256)
        val builder = jwtKeyManager.getJwtBuilder()
        builder.claim("name", name)
        builder.encryptClaim("encode", encode)
        val jwt = builder.build()
        println(jwt)
        val jwtReader = jwtKeyManager.parse(jwt)
        Assertions.assertEquals(name, jwtReader.claim("name"))
        Assertions.assertEquals(encode, jwtReader.decryptClaim("encode"))
    }
}