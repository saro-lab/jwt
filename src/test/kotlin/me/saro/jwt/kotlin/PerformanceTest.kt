package me.saro.jwt.kotlin

import me.saro.jwt.Jwt
import me.saro.jwt.Jwt.Companion.parseJwt
import me.saro.jwt.JwtAlgorithm
import me.saro.jwt.JwtNode
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

@DisplayName("[Kotlin] Performance Test")
class PerformanceTest {
    @Test
    @DisplayName("[Kotlin] ES dynamic keys test")
    fun d_es() {
        dynamicKeys(100, Jwt.ES256, Jwt.ES384, Jwt.ES512)
    }

    @Test
    @DisplayName("[Kotlin] HS dynamic keys test")
    fun d_hs() {
        dynamicKeys(1000, Jwt.HS256, Jwt.HS384, Jwt.HS512)
    }

    @Test
    @DisplayName("[Kotlin] PS dynamic keys test")
    fun d_ps() {
        dynamicKeys(10, Jwt.PS256, Jwt.PS384, Jwt.PS512)
    }

    @Test
    @DisplayName("[Kotlin] RS dynamic keys test")
    fun d_rs() {
        dynamicKeys(10, Jwt.RS256, Jwt.RS384, Jwt.RS512)
    }

    @Test
    @DisplayName("[Kotlin] ES fixed keys test")
    fun f_es() {
        fixedKeys(1000, Jwt.ES256, Jwt.ES384, Jwt.ES512)
    }

    @Test
    @DisplayName("[Kotlin] HS fixed keys test")
    fun f_hs() {
        fixedKeys(5000, Jwt.HS256, Jwt.HS384, Jwt.HS512)
    }

    @Test
    @DisplayName("[Kotlin] PS fixed keys test")
    fun f_ps() {
        fixedKeys(300, Jwt.PS256, Jwt.PS384, Jwt.PS512)
    }

    @Test
    @DisplayName("[Kotlin] RS fixed keys test")
    fun f_rs() {
        fixedKeys(500, Jwt.RS256, Jwt.RS384, Jwt.RS512)
    }

    private fun dynamicKeys(loop: Int, vararg algs: JwtAlgorithm) {
        for (alg in algs) {
            val start = System.currentTimeMillis()
            for (i in 0..<loop) {
                val key = alg.newRandomKey()
                val jwt = Jwt.createJwt(key)
                    .subject("1234567890")
                    .claim("name", "John Doe")
                    .claim("admin", true)
                    .claim("iat", 1516239022)
                    .build()

                val node = Assertions.assertDoesNotThrow<JwtNode> { parseJwt(jwt) { key } }
                Assertions.assertEquals("1234567890", node.subject)
                Assertions.assertEquals("John Doe", node.claimString("name"))
                Assertions.assertEquals(true, node.claimBoolean("admin"))
                Assertions.assertEquals(1516239022, node.claimInt("iat"))
            }
            println(alg.algorithmFullName + " dynamic keys " + loop + " loops time: " + (System.currentTimeMillis() - start) + "ms")
        }
    }

    private fun fixedKeys(loop: Int, vararg algs: JwtAlgorithm) {
        for (alg in algs) {
            val key = alg.newRandomKey()
            val start = System.currentTimeMillis()
            for (i in 0..<loop) {
                val jwt = Jwt.createJwt(key)
                    .subject("1234567890")
                    .claim("name", "John Doe")
                    .claim("admin", true)
                    .claim("iat", 1516239022)
                    .build()

                val node = Assertions.assertDoesNotThrow<JwtNode> { parseJwt(jwt) { key } }
                Assertions.assertEquals("1234567890", node.subject)
                Assertions.assertEquals("John Doe", node.claimString("name"))
                Assertions.assertEquals(true, node.claimBoolean("admin"))
                Assertions.assertEquals(1516239022, node.claimInt("iat"))
            }
            println(alg.algorithmFullName + " fixed keys " + loop + " loops time: " + (System.currentTimeMillis() - start) + "ms")
        }
    }
}
