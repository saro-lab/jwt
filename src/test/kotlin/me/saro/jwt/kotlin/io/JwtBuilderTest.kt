package me.saro.jwt.kotlin.io

import io.jsonwebtoken.SignatureAlgorithm
import me.saro.jwt.io.JwtBuilder
import me.saro.jwt.model.KeyChain.Companion.create
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

@DisplayName("[Kotlin] JwtBuilder")
class JwtBuilderTest {
    @Test
    fun `arguments check`() {
        Assertions.assertThrows(IllegalArgumentException::class.java) { JwtBuilder(SignatureAlgorithm.RS384, create(SignatureAlgorithm.RS256)) }

        val builder = JwtBuilder(SignatureAlgorithm.RS256, create(SignatureAlgorithm.RS256))

        Assertions.assertThrows(IllegalArgumentException::class.java) { builder.header("kid", "") }
        Assertions.assertThrows(IllegalArgumentException::class.java) { builder.header("alg", "") }
        Assertions.assertThrows(IllegalArgumentException::class.java) { builder.header("", "") }
        Assertions.assertThrows(IllegalArgumentException::class.java) { builder.claim("exp", "") }
        Assertions.assertThrows(IllegalArgumentException::class.java) { builder.claim("iat", "") }
        Assertions.assertThrows(IllegalArgumentException::class.java) { builder.claim("", "") }
    }

    @Test
    fun build() {
        Assertions.assertDoesNotThrow {
            val builder = JwtBuilder(SignatureAlgorithm.RS256, create(SignatureAlgorithm.RS256))
            builder.claim("name", "안녕")
            builder.build()
        }
    }
}