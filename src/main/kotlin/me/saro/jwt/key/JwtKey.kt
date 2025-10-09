package me.saro.jwt.key

import me.saro.jwt.JwtAlgorithm
import me.saro.jwt.JwtUtil
import me.saro.jwt.JwtUtil.Companion.decodeBase64
import me.saro.jwt.JwtUtil.Companion.decodeHex
import me.saro.jwt.JwtUtil.Companion.normalizePem
import java.security.Key
import java.util.*

interface JwtKey {
    val algorithm: JwtAlgorithm
    val key: Key
    fun toBytes(): ByteArray = key.encoded
    fun toBase64(): String = JwtUtil.encodeToBase64String(toBytes())
    fun toHex(): String = JwtUtil.encodeHex(toBytes())

    companion object {
        // hash key
        @JvmStatic fun parseHash(algorithm: JwtAlgorithm, key: ByteArray): JwtHashKey = JwtHashKey(algorithm, key)
        @JvmStatic fun parseHashByHex(algorithm: JwtAlgorithm, key: String): JwtHashKey = JwtHashKey(algorithm, decodeHex(key))
        @JvmStatic fun parseHashByBase64(algorithm: JwtAlgorithm, key: String): JwtHashKey = JwtHashKey(algorithm, decodeBase64(key))
        @JvmStatic fun parseHashByText(algorithm: JwtAlgorithm, key: String): JwtHashKey = JwtHashKey(algorithm, key.toByteArray())
        @JvmStatic fun generateHash(algorithm: JwtAlgorithm, byteSize: Int): JwtHashKey = JwtHashKey(algorithm, ByteArray(byteSize).apply { Random().nextBytes(this) })

        // pair key
        @JvmStatic fun parsePairPublic(algorithm: JwtAlgorithm, key: ByteArray): JwtPairPublicKey = JwtPairPublicKey(algorithm, key)
        @JvmStatic fun parsePairPublicByPem(algorithm: JwtAlgorithm, key: String): JwtPairPublicKey = JwtPairPublicKey(algorithm, decodeBase64(normalizePem(key)))
        @JvmStatic fun parsePairPrivate(algorithm: JwtAlgorithm, key: ByteArray): JwtPairPrivateKey = JwtPairPrivateKey(algorithm, key)
        @JvmStatic fun parsePairPrivateByPem(algorithm: JwtAlgorithm, key: String): JwtPairPrivateKey = JwtPairPrivateKey(algorithm, decodeBase64(normalizePem(key)))
        @JvmStatic fun generateKeyPair(algorithm: JwtAlgorithm, bit: Int): JwtKeyPair = JwtPairKey.generateKeyPair(algorithm, bit)
        @JvmStatic fun generateKeyPair(algorithm: JwtAlgorithm): JwtKeyPair = JwtPairKey.generateKeyPair(algorithm)
    }
}
