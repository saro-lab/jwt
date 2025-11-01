package me.saro.jwt.kotlin

import me.saro.jwt.key.*
import me.saro.jwt.key.JwtAlgorithm.*
import me.saro.jwt.key.JwtKey.Companion.generateHash
import me.saro.jwt.key.JwtKey.Companion.generateKeyPair
import me.saro.jwt.key.JwtKey.Companion.parseHashByBase64
import me.saro.jwt.key.JwtKey.Companion.parseHashByHex
import me.saro.jwt.key.JwtKey.Companion.parseHashByText
import me.saro.jwt.node.Jwt.Companion.builder
import me.saro.jwt.node.Jwt.Companion.builderOrNull
import me.saro.jwt.node.Jwt.Companion.parseOrNull
import me.saro.jwt.node.Jwt.Companion.parseOrThrow
import me.saro.jwt.node.JwtNode
import org.junit.jupiter.api.*
import java.time.OffsetDateTime
import java.util.*
import java.util.function.Consumer

@DisplayName("[Kotlin] all test")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestMethodOrder(MethodOrderer.DisplayName::class)
class AllTest {
    var hashKeyList: MutableList<JwtHashKey> = ArrayList<JwtHashKey>()
    var keyPairList: MutableList<JwtKeyPair> = ArrayList<JwtKeyPair>()
    var hashKeyListText: MutableList<List<String>> = ArrayList<List<String>>()
    var keyPairListText: MutableList<List<String>> = ArrayList<List<String>>()

    var signatureKeyList: MutableList<JwtSignatureKey> = ArrayList<JwtSignatureKey>()
    var verifyKeyList: MutableList<JwtVerifyKey> = ArrayList<JwtVerifyKey>()

    @Test
    @DisplayName("[Kotlin] 01 created Keys")
    fun test01() {
        val start = System.currentTimeMillis()

        // HS Algorithm
        for (alg in listOf(HS256, HS384, HS512)) {
            hashKeyList.add(generateHash(alg, 1))
            hashKeyList.add(generateHash(alg, 32))
            hashKeyList.add(generateHash(alg, 64))
            hashKeyList.add(parseHashByText(alg, "abcd"))
            hashKeyList.add(parseHashByHex(alg, "A162c364"))
            hashKeyList.add(parseHashByBase64(alg, "YWJjZA=="))
        }

        for (alg in listOf(
            ES256,
            ES384,
            ES512,
            RS256,
            RS384,
            RS512,
            PS256,
            PS384,
            PS512
        )) {
            keyPairList.add(generateKeyPair(alg))
            keyPairList.add(generateKeyPair(alg))
            keyPairList.add(generateKeyPair(alg))
        }

        println("create " + (hashKeyList.size + keyPairList.size) + " keys - " + (System.currentTimeMillis() - start) + "ms")
    }

    @Test
    @DisplayName("[Kotlin] 02 stringify keys")
    fun test02() {
        Assertions.assertNotEquals(
            0,
            hashKeyList.size,
            "This function cannot be tested independently. Please run the entire test."
        )
        Assertions.assertNotEquals(
            0,
            keyPairList.size,
            "This function cannot be tested independently. Please run the entire test."
        )

        val start = System.currentTimeMillis()

        hashKeyList.forEach(Consumer { key: JwtHashKey ->
            hashKeyListText.add(
                listOf(
                    key.algorithm.name,
                    key.toBase64()
                )
            )
        })
        keyPairList.forEach(Consumer { key: JwtKeyPair ->
            keyPairListText.add(
                listOf(
                    key.public.algorithm.name,
                    key.public.toBase64(),
                    key.private.toBase64()
                )
            )
        })

        println("stringify " + (hashKeyListText.size + keyPairListText.size) + " keys - " + (System.currentTimeMillis() - start) + "ms")
    }

    @Test
    @DisplayName("[Kotlin] 03 convert string keys")
    fun test03() {
        Assertions.assertNotEquals(
            0,
            hashKeyListText.size,
            "This function cannot be tested independently. Please run the entire test."
        )
        Assertions.assertNotEquals(
            0,
            keyPairListText.size,
            "This function cannot be tested independently. Please run the entire test."
        )

        val start = System.currentTimeMillis()

        hashKeyListText.forEach(Consumer { key: List<String> ->
            val hashKey = JwtKey.parseHashByBase64(valueOf(key[0]), key[1])
            signatureKeyList.add(hashKey)
            verifyKeyList.add(hashKey)
        })
        keyPairListText.forEach(Consumer { key: List<String> ->
            val alg = valueOf(key[0])
            val publicKey = JwtKey.parsePairPublicByPem(alg, key[1])
            val privateKey = JwtKey.parsePairPrivateByPem(alg, key[2])
            signatureKeyList.add(privateKey)
            verifyKeyList.add(publicKey)
        })

        println("convert " + (signatureKeyList.size) + " keys - " + (System.currentTimeMillis() - start) + "ms")
    }

    @Test
    @DisplayName("[Kotlin] 04 expired")
    fun test04() {
        Assertions.assertNotEquals(
            0,
            signatureKeyList.size,
            "This function cannot be tested independently. Please run the entire test."
        )
        Assertions.assertNotEquals(
            0,
            verifyKeyList.size,
            "This function cannot be tested independently. Please run the entire test."
        )

        val start = System.currentTimeMillis()

        for (i in signatureKeyList.indices) {
            val jwt = builder().expire(OffsetDateTime.now().minusMinutes(1)).build(signatureKeyList.get(i))
            Assertions.assertFalse(parseOrThrow(jwt).verify(verifyKeyList.get(i)))
        }

        println("pass expired test - " + (System.currentTimeMillis() - start) + "ms")
    }

    @Test
    @DisplayName("[Kotlin] 05 not before")
    fun test05() {
        Assertions.assertNotEquals(
            0,
            signatureKeyList.size,
            "This function cannot be tested independently. Please run the entire test."
        )
        Assertions.assertNotEquals(
            0,
            verifyKeyList.size,
            "This function cannot be tested independently. Please run the entire test."
        )

        val start = System.currentTimeMillis()

        for (i in signatureKeyList.indices) {
            val jwt = builder().notBefore(OffsetDateTime.now().plusDays(1)).build(signatureKeyList.get(i))
            Assertions.assertFalse(parseOrThrow(jwt).verify(verifyKeyList.get(i)))
        }

        println("pass not before test - " + (System.currentTimeMillis() - start) + "ms")
    }

    @Test
    @DisplayName("[Kotlin] 06 pass")
    fun test06() {
        Assertions.assertNotEquals(
            0,
            signatureKeyList.size,
            "This function cannot be tested independently. Please run the entire test."
        )
        Assertions.assertNotEquals(
            0,
            verifyKeyList.size,
            "This function cannot be tested independently. Please run the entire test."
        )

        val start = System.currentTimeMillis()

        for (i in signatureKeyList.indices) {
            val jwt = builder().build(signatureKeyList[i])
            Assertions.assertTrue(parseOrThrow(jwt).verify(verifyKeyList[i]))
        }

        println("pass test - " + (System.currentTimeMillis() - start) + "ms")
    }

    @Test
    @DisplayName("[Kotlin] 07 data")
    fun test07() {
        Assertions.assertNotEquals(
            0,
            signatureKeyList.size,
            "This function cannot be tested independently. Please run the entire test."
        )
        Assertions.assertNotEquals(
            0,
            verifyKeyList.size,
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

        for (i in signatureKeyList.indices) {
            val signatureKey = signatureKeyList.get(i)
            val verifyKey = verifyKeyList.get(i)

            val jwt = builder()
                .kid(i.toString())
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
                .build(signatureKey)

            val node = Assertions.assertDoesNotThrow<JwtNode> { parseOrThrow(jwt) }
            Assertions.assertTrue(node.verify(verifyKey))
            Assertions.assertEquals(i.toString(), node.kid)
            Assertions.assertEquals(signatureKey.algorithm.name, node.algorithm)
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
        }

        println("pass test - " + (System.currentTimeMillis() - start) + "ms")
    }

    @Test
    @DisplayName("[Java] 08 builder test")
    fun test08() {
        val key = generateKeyPair(ES256)
        val builder = builder().issuer("iss").subject("sub")
        val b1 = builderOrNull(builder.toBody())
        Assertions.assertNotNull(b1)
        val b2 = builderOrNull(builder.toHeader(), null)
        Assertions.assertNotNull(b2)
        val b3 = builderOrNull(null, builder.toPayload())
        Assertions.assertNotNull(b3)

        val jwt1 = b1!!.build(key.private)
        val jwt2 = b2!!.build(key.private)
        val jwt3 = b3!!.build(key.private)

        println("jwt1: $jwt1")
        println("jwt2: $jwt2")
        println("jwt3: $jwt3")

        val node1 = parseOrNull(jwt1)
        val node2 = parseOrNull(jwt2)
        val node3 = parseOrNull(jwt3)
        Assertions.assertNotNull(node1)
        Assertions.assertNotNull(node2)
        Assertions.assertNotNull(node3)

        println("node1: $node1")
        println("node2: $node2")
        println("node3: $node3")
    }
}
