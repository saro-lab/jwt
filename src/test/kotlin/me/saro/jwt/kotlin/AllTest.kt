package me.saro.jwt.kotlin

import me.saro.jwt.Jwt
import me.saro.jwt.Jwt.Companion.createJwt
import me.saro.jwt.Jwt.Companion.parseJwt
import me.saro.jwt.Jwt.Companion.parseKey
import me.saro.jwt.JwtKey
import me.saro.jwt.JwtNode
import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode
import org.junit.jupiter.api.*
import java.time.OffsetDateTime
import java.util.*
import java.util.function.Consumer

@DisplayName("[Kotlin] all test")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(
    MethodOrderer.DisplayName::class
)
class AllTest {
    var createKeyList: MutableList<JwtKey> = ArrayList()
    var stringKeyList: MutableList<String> = ArrayList()
    var convertKeyList: MutableList<JwtKey> = ArrayList()

    @Test
    @DisplayName("[Kotlin] 01 created Keys")
    fun test01() {
        val start = System.currentTimeMillis()

        // HS Algorithm
        createKeyList.add(Jwt.HS256.newRandomKey())
        createKeyList.add(Jwt.HS256.newRandomJwtKey(20))
        createKeyList.add(Jwt.HS256.newRandomJwtKey(10, 40))
        createKeyList.add(Jwt.HS256.toKeyByText("HS256_4_key"))
        createKeyList.add(Jwt.HS384.newRandomKey())
        createKeyList.add(Jwt.HS384.newRandomJwtKey(20))
        createKeyList.add(Jwt.HS384.newRandomJwtKey(10, 40))
        createKeyList.add(Jwt.HS384.toKeyByText("HS384_4_key"))
        createKeyList.add(Jwt.HS512.newRandomKey())
        createKeyList.add(Jwt.HS512.newRandomJwtKey(20))
        createKeyList.add(Jwt.HS512.newRandomJwtKey(10, 40))
        createKeyList.add(Jwt.HS512.toKeyByText("HS512_4_key"))

        // ES Algorithm
        createKeyList.add(Jwt.ES256.newRandomKey())
        createKeyList.add(Jwt.ES256.newRandomKey())
        createKeyList.add(Jwt.ES256.newRandomKey())
        createKeyList.add(Jwt.ES384.newRandomKey())
        createKeyList.add(Jwt.ES384.newRandomKey())
        createKeyList.add(Jwt.ES384.newRandomKey())
        createKeyList.add(Jwt.ES512.newRandomKey())
        createKeyList.add(Jwt.ES512.newRandomKey())
        createKeyList.add(Jwt.ES512.newRandomKey())

        // PS Algorithm
        createKeyList.add(Jwt.PS256.newRandomKey())
        createKeyList.add(Jwt.PS256.newRandomJwtKey(2048))
        createKeyList.add(Jwt.PS256.newRandomJwtKey(3072))
        createKeyList.add(Jwt.PS256.newRandomJwtKey(4096))
        createKeyList.add(Jwt.PS384.newRandomKey())
        createKeyList.add(Jwt.PS384.newRandomJwtKey(2048))
        createKeyList.add(Jwt.PS384.newRandomJwtKey(3072))
        createKeyList.add(Jwt.PS384.newRandomJwtKey(4096))
        createKeyList.add(Jwt.PS512.newRandomKey())
        createKeyList.add(Jwt.PS512.newRandomJwtKey(2048))
        createKeyList.add(Jwt.PS512.newRandomJwtKey(3072))
        createKeyList.add(Jwt.PS512.newRandomJwtKey(4096))

        // RS Algorithm
        createKeyList.add(Jwt.RS256.newRandomKey())
        createKeyList.add(Jwt.RS256.newRandomJwtKey(2048))
        createKeyList.add(Jwt.RS256.newRandomJwtKey(3072))
        createKeyList.add(Jwt.RS256.newRandomJwtKey(4096))
        createKeyList.add(Jwt.RS384.newRandomKey())
        createKeyList.add(Jwt.RS384.newRandomJwtKey(2048))
        createKeyList.add(Jwt.RS384.newRandomJwtKey(3072))
        createKeyList.add(Jwt.RS384.newRandomJwtKey(4096))
        createKeyList.add(Jwt.RS512.newRandomKey())
        createKeyList.add(Jwt.RS512.newRandomJwtKey(2048))
        createKeyList.add(Jwt.RS512.newRandomJwtKey(3072))
        createKeyList.add(Jwt.RS512.newRandomJwtKey(4096))

        Assertions.assertEquals(45, createKeyList.size)
        println("create " + createKeyList.size + " keys - " + (System.currentTimeMillis() - start) + "ms")
    }

    @Test
    @DisplayName("[Kotlin] 02 stringify keys")
    fun test02() {
        Assertions.assertNotEquals(
            0,
            createKeyList.size,
            "This function cannot be tested independently. Please run the entire test."
        )

        val start = System.currentTimeMillis()

        createKeyList.forEach(Consumer { key: JwtKey -> stringKeyList.add(key.toString()) })

        Assertions.assertEquals(45, stringKeyList.size)

        stringKeyList.forEach(Consumer { x: String? -> println(x) })
        println("pass stringify " + stringKeyList.size + " keys - " + (System.currentTimeMillis() - start) + "ms")
    }

    @Test
    @DisplayName("[Kotlin] 03 convert string keys")
    fun test03() {
        Assertions.assertNotEquals(
            0,
            stringKeyList.size,
            "This function cannot be tested independently. Please run the entire test."
        )

        val start = System.currentTimeMillis()

        stringKeyList.forEach(Consumer { key: String? ->
            convertKeyList.add(
                parseKey(
                    key!!
                )
            )
        })

        Assertions.assertEquals(45, convertKeyList.size)

        convertKeyList.forEach(Consumer { x: JwtKey? -> println(x) })
        println("pass convert " + convertKeyList.size + " keys - " + (System.currentTimeMillis() - start) + "ms")
    }

    @Test
    @DisplayName("[Kotlin] 04 expired")
    fun test04() {
        Assertions.assertNotEquals(
            0,
            createKeyList.size,
            "This function cannot be tested independently. Please run the entire test."
        )

        val start = System.currentTimeMillis()

        createKeyList.forEach(Consumer { key: JwtKey? ->
            val jwt = createJwt(key!!)
                .expire(OffsetDateTime.now().minusMinutes(1))
                .build()
            val exception = Assertions.assertThrows(
                JwtException::class.java
            ) { parseJwt(jwt, convertKeyList) }
            Assertions.assertEquals(JwtExceptionCode.DATE_EXPIRED, exception.code)
        })

        println("pass expired test - " + (System.currentTimeMillis() - start) + "ms")
    }

    @Test
    @DisplayName("[Kotlin] 05 not before")
    fun test05() {
        Assertions.assertNotEquals(
            0,
            createKeyList.size,
            "This function cannot be tested independently. Please run the entire test."
        )

        val start = System.currentTimeMillis()

        createKeyList.forEach(Consumer { key: JwtKey? ->
            val jwt = createJwt(key!!)
                .notBefore(OffsetDateTime.now().plusDays(1))
                .build()
            val exception = Assertions.assertThrows(
                JwtException::class.java
            ) { parseJwt(jwt, convertKeyList) }
            Assertions.assertEquals(JwtExceptionCode.DATE_BEFORE, exception.code)
        })

        println("pass not before test - " + (System.currentTimeMillis() - start) + "ms")
    }

    @Test
    @DisplayName("[Kotlin] 06 pass")
    fun test06() {
        Assertions.assertNotEquals(
            0,
            createKeyList.size,
            "This function cannot be tested independently. Please run the entire test."
        )

        val start = System.currentTimeMillis()

        createKeyList.forEach(Consumer { key: JwtKey ->
            val jwt = createJwt(key)
                .build()
            val node = Assertions.assertDoesNotThrow<JwtNode> {
                parseJwt(
                    jwt,
                    convertKeyList
                )
            }
            Assertions.assertEquals(key.kid, node.kid)
        })

        println("pass test - " + (System.currentTimeMillis() - start) + "ms")
    }

    @Test
    @DisplayName("[Kotlin] 07 data")
    fun test07() {
        Assertions.assertNotEquals(
            0,
            createKeyList.size,
            "This function cannot be tested independently. Please run the entire test."
        )

        val start = System.currentTimeMillis()

        val issuer = "issuer1"
        val subject = "subject2"
        val audience = "audience3"
        val id = "id4"
        val boolData = true
        val boolData2 = "no"
        val boolData3 = "1"
        val boolData4 = "Y"
        val boolData5 = "YeS"
        val boolData6 = "N"
        val intData1 = 1237890
        val intData2 = "-7890"
        val longData1 = 1234567891110L
        val longData2 = "42345678911103"
        val issuedAt = Date(OffsetDateTime.now().toEpochSecond() * 1000L)
        val notBefore = OffsetDateTime.now().minusMinutes(1).toEpochSecond()
        val expire = OffsetDateTime.now().plusHours(1).toEpochSecond()

        createKeyList.forEach(Consumer { key: JwtKey ->
            val jwt = createJwt(key)
                .issuer(issuer)
                .subject(subject)
                .audience(audience)
                .id(id)
                .claim("boolData", boolData)
                .claim("boolData2", boolData2)
                .claim("boolData3", boolData3)
                .claim("boolData4", boolData4)
                .claim("boolData5", boolData5)
                .claim("boolData6", boolData6)
                .claim("intData1", intData1)
                .claim("intData2", intData2)
                .claim("longData1", longData1)
                .claim("longData2", longData2)
                .claim("test", "test-value")
                .issuedAt(issuedAt)
                .notBefore(notBefore)
                .expire(expire)
                .build()
            val node = Assertions.assertDoesNotThrow<JwtNode> {
                parseJwt(
                    jwt,
                    convertKeyList
                )
            }
            Assertions.assertEquals(key.kid, node.kid)
            Assertions.assertEquals(key.algorithm.algorithmFullName, node.algorithm)
            Assertions.assertEquals(issuer, node.issuer)
            Assertions.assertEquals(subject, node.subject)
            Assertions.assertEquals(audience, node.audience)
            Assertions.assertEquals(id, node.id)
            Assertions.assertEquals(boolData, node.claimBoolean("boolData"))
            Assertions.assertEquals(false, node.claimBoolean("boolData2"))
            Assertions.assertEquals(true, node.claimBoolean("boolData3"))
            Assertions.assertEquals(true, node.claimBoolean("boolData4"))
            Assertions.assertEquals(true, node.claimBoolean("boolData5"))
            Assertions.assertEquals(false, node.claimBoolean("boolData6"))
            Assertions.assertEquals(intData1, node.claimInt("intData1"))
            Assertions.assertEquals(-7890, node.claimInt("intData2"))
            Assertions.assertEquals(longData1, node.claimLong("longData1"))
            Assertions.assertEquals(42345678911103L, node.claimLong("longData2"))
            Assertions.assertEquals("test-value", node.claimString("test"))
            Assertions.assertEquals(issuedAt, node.issuedAt)
            Assertions.assertEquals(notBefore, node.notBeforeEpochSecond)
            Assertions.assertEquals(expire, node.expireEpochSecond)
            println("pass: $node")
        })

        println("pass test - " + (System.currentTimeMillis() - start) + "ms")
    }
}
