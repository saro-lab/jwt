package me.saro.jwt.kotlin.impl

import io.jsonwebtoken.SignatureAlgorithm
import me.saro.jwt.old.impl.DefaultJwtKeyManager
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test

@DisplayName("[Kotlin] DefaultJwtKeyManager")
class DefaultJwtObjectKeyManagerTest{

    @Test
    fun `key not rotate`() {
        val jwtManager = DefaultJwtKeyManager.create(SignatureAlgorithm.RS256)
        val kc1 = jwtManager.getKeyChain()
        val kc2 = jwtManager.getKeyChain()

        println("not rotate kc1 ---------------------")
        println(kc1)
        println("not rotate kc2 ---------------------")
        println(kc2)

        assert(kc1 == kc2)
    }

    @Test
    fun `key rotate`() {
        val jwtManager = DefaultJwtKeyManager.create(SignatureAlgorithm.RS256)
        val kc1 = jwtManager.getKeyChain()
        jwtManager.rotate()
        val kc2 = jwtManager.getKeyChain()

        println("rotate kc1 ---------------------")
        println(kc1)
        println("rotate kc2 ---------------------")
        println(kc2)

        assert(kc1 != kc2)
    }

    @Test
    fun `parameter pass`() {
        Assertions.assertDoesNotThrow<DefaultJwtKeyManager> {
            DefaultJwtKeyManager.create(SignatureAlgorithm.RS256, 3)
        }
        Assertions.assertDoesNotThrow<DefaultJwtKeyManager> {
            DefaultJwtKeyManager.create(SignatureAlgorithm.RS256, 3,0)
        }
        Assertions.assertDoesNotThrow<DefaultJwtKeyManager> {
            DefaultJwtKeyManager.create(SignatureAlgorithm.RS256, 4, 1)
        }
    }

    @Test
    fun `parameter error`() {
        Assertions.assertThrows(IllegalArgumentException::class.java) {
            DefaultJwtKeyManager.create(SignatureAlgorithm.RS256, 2)
        }
        Assertions.assertThrows(IllegalArgumentException::class.java) {
            DefaultJwtKeyManager.create(SignatureAlgorithm.RS256, 3, -1)
        }
    }
}

