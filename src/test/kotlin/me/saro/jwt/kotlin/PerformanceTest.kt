package me.saro.jwt.kotlin

import me.saro.jwt.key.JwtAlgorithm
import me.saro.jwt.key.JwtKey.Companion.generateHash
import me.saro.jwt.key.JwtKey.Companion.generateKeyPair
import me.saro.jwt.node.Jwt.Companion.builder
import me.saro.jwt.node.Jwt.Companion.parseOrThrow
import me.saro.jwt.node.JwtNode
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.function.ThrowingSupplier

@DisplayName("[Kotlin] Performance Test")
class PerformanceTest {
    @Test
    @DisplayName("[Kotlin] ES dynamic keys test")
    fun d_es() {
        dynamicKeysPair(100, JwtAlgorithm.ES256, JwtAlgorithm.ES384, JwtAlgorithm.ES512)
    }

    @Test
    @DisplayName("[Kotlin] HS dynamic keys test")
    fun d_hs() {
        dynamicKeysHash(1000, JwtAlgorithm.HS256, JwtAlgorithm.HS384, JwtAlgorithm.HS512)
    }

    @Test
    @DisplayName("[Kotlin] PS dynamic keys test")
    fun d_ps() {
        dynamicKeysPair(10, JwtAlgorithm.PS256, JwtAlgorithm.PS384, JwtAlgorithm.PS512)
    }

    @Test
    @DisplayName("[Kotlin] RS dynamic keys test")
    fun d_rs() {
        dynamicKeysPair(10, JwtAlgorithm.RS256, JwtAlgorithm.RS384, JwtAlgorithm.RS512)
    }

    @Test
    @DisplayName("[Kotlin] ES fixed keys test")
    fun f_es() {
        fixedKeysPair(1000, JwtAlgorithm.ES256, JwtAlgorithm.ES384, JwtAlgorithm.ES512)
    }

    @Test
    @DisplayName("[Kotlin] HS fixed keys test")
    fun f_hs() {
        fixedKeysHash(5000, JwtAlgorithm.HS256, JwtAlgorithm.HS384, JwtAlgorithm.HS512)
    }

    @Test
    @DisplayName("[Kotlin] PS fixed keys test")
    fun f_ps() {
        fixedKeysPair(300, JwtAlgorithm.PS256, JwtAlgorithm.PS384, JwtAlgorithm.PS512)
    }

    @Test
    @DisplayName("[Kotlin] RS fixed keys test")
    fun f_rs() {
        fixedKeysPair(500, JwtAlgorithm.RS256, JwtAlgorithm.RS384, JwtAlgorithm.RS512)
    }

    private fun dynamicKeysHash(loop: Int, vararg algs: JwtAlgorithm) {
        for (alg in algs) {
            val start = System.currentTimeMillis()
            for (i in 0..<loop) {
                val key = generateHash(alg, 32)
                val jwt = builder()
                    .subject("1234567890")
                    .claim("name", "John Doe")
                    .claim("admin", true)
                    .claim("iat", 1516239022)
                    .build(key)

                val node = Assertions.assertDoesNotThrow<JwtNode>(ThrowingSupplier { parseOrThrow(jwt) })
                Assertions.assertTrue(node.verify(key))
                Assertions.assertEquals("1234567890", node.subject)
                Assertions.assertEquals("John Doe", node.claimString("name"))
                Assertions.assertEquals(true, node.claimBoolean("admin"))
                Assertions.assertEquals(1516239022, node.claimInt("iat"))
            }
            println(alg.name + " dynamic keys " + loop + " loops time: " + (System.currentTimeMillis() - start) + "ms")
        }
    }

    private fun fixedKeysHash(loop: Int, vararg algs: JwtAlgorithm) {
        for (alg in algs) {
            val key = generateHash(alg, 32)
            val start = System.currentTimeMillis()
            for (i in 0..<loop) {
                val jwt = builder()
                    .subject("1234567890")
                    .claim("name", "John Doe")
                    .claim("admin", true)
                    .claim("iat", 1516239022)
                    .build(key)

                val node = Assertions.assertDoesNotThrow<JwtNode>(ThrowingSupplier { parseOrThrow(jwt) })
                Assertions.assertTrue(node.verify(key))
                Assertions.assertEquals("1234567890", node.subject)
                Assertions.assertEquals("John Doe", node.claimString("name"))
                Assertions.assertEquals(true, node.claimBoolean("admin"))
                Assertions.assertEquals(1516239022, node.claimInt("iat"))
            }
            println(alg.name + " fixed keys " + loop + " loops time: " + (System.currentTimeMillis() - start) + "ms")
        }
    }

    private fun dynamicKeysPair(loop: Int, vararg algs: JwtAlgorithm) {
        for (alg in algs) {
            val start = System.currentTimeMillis()
            for (i in 0..<loop) {
                val key = generateKeyPair(alg)
                val jwt = builder()
                    .subject("1234567890")
                    .claim("name", "John Doe")
                    .claim("admin", true)
                    .claim("iat", 1516239022)
                    .build(key.private)

                val node = Assertions.assertDoesNotThrow<JwtNode>(ThrowingSupplier { parseOrThrow(jwt) })
                Assertions.assertTrue(node.verify(key.public))
                Assertions.assertEquals("1234567890", node.subject)
                Assertions.assertEquals("John Doe", node.claimString("name"))
                Assertions.assertEquals(true, node.claimBoolean("admin"))
                Assertions.assertEquals(1516239022, node.claimInt("iat"))
            }
            println(alg.name + " dynamic keys " + loop + " loops time: " + (System.currentTimeMillis() - start) + "ms")
        }
    }

    private fun fixedKeysPair(loop: Int, vararg algs: JwtAlgorithm) {
        for (alg in algs) {
            val key = generateKeyPair(alg)
            val start = System.currentTimeMillis()
            for (i in 0..<loop) {
                val jwt = builder()
                    .subject("1234567890")
                    .claim("name", "John Doe")
                    .claim("admin", true)
                    .claim("iat", 1516239022)
                    .build(key.private)

                val node = Assertions.assertDoesNotThrow<JwtNode>(ThrowingSupplier { parseOrThrow(jwt) })
                Assertions.assertTrue(node.verify(key.public))
                Assertions.assertEquals("1234567890", node.subject)
                Assertions.assertEquals("John Doe", node.claimString("name"))
                Assertions.assertEquals(true, node.claimBoolean("admin"))
                Assertions.assertEquals(1516239022, node.claimInt("iat"))
            }
            println(alg.name + " fixed keys " + loop + " loops time: " + (System.currentTimeMillis() - start) + "ms")
        }
    }
}
