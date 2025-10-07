package me.saro.jwt.key

import me.saro.jwt.JwtAlgorithm
import me.saro.jwt.JwtUtils
import java.security.Key
import java.util.*

interface JwtKey {
    val algorithm: JwtAlgorithm
    val key: Key
    fun toBytes(): ByteArray = key.encoded
    fun toBase64(): String = JwtUtils.encodeToBase64String(toBytes())
    fun toHex(): String = JwtUtils.encodeHex(toBytes())

    companion object {
        @JvmStatic fun parseHs(algorithm: JwtAlgorithm, key: ByteArray): JwtKey = JwtHashKey(algorithm, key)
        @JvmStatic fun parseHsByHex(algorithm: JwtAlgorithm, key: String): JwtKey = JwtHashKey(algorithm, JwtUtils.decodeHex(key))
        @JvmStatic fun parseHsByBase64(algorithm: JwtAlgorithm, key: String): JwtKey = JwtHashKey(algorithm, JwtUtils.decodeBase64(key))
        @JvmStatic fun parseHsByText(algorithm: JwtAlgorithm, key: String): JwtKey = JwtHashKey(algorithm, key.toByteArray())
        @JvmStatic fun generateHs(algorithm: JwtAlgorithm, byteSize: Int): JwtHashKey = JwtHashKey(algorithm, ByteArray(byteSize).apply { Random().nextBytes(this) })


        fun parsePair(key: ByteArray)
    }
}
