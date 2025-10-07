package me.saro.jwt.key

import me.saro.jwt.JwtAlgorithm
import me.saro.jwt.JwtUtils
import me.saro.jwt.key.hash.JwtHsKey
import java.security.Key
import java.util.Random

interface JwtKey {
    val algorithm: JwtAlgorithm
    val key: Key
    fun toBytes(): ByteArray = key.encoded
    fun toBase64(): String = JwtUtils.encodeToBase64String(toBytes())
    fun toHex(): String = JwtUtils.encodeHex(toBytes())

    companion object {
        @JvmStatic fun parseHs256(key: ByteArray): JwtHsKey = JwtHsKey(JwtAlgorithm.HS256, key)
        @JvmStatic fun parseHs384(key: ByteArray): JwtHsKey = JwtHsKey(JwtAlgorithm.HS384, key)
        @JvmStatic fun parseHs512(key: ByteArray): JwtHsKey = JwtHsKey(JwtAlgorithm.HS512, key)
        @JvmStatic fun newHs256(byteSize: Int): JwtHsKey = JwtHsKey(JwtAlgorithm.HS256, ByteArray(byteSize).apply { Random().nextBytes(this) })
        @JvmStatic fun newHs384(byteSize: Int): JwtHsKey = JwtHsKey(JwtAlgorithm.HS384, ByteArray(byteSize).apply { Random().nextBytes(this) })
        @JvmStatic fun newHs512(byteSize: Int): JwtHsKey = JwtHsKey(JwtAlgorithm.HS512, ByteArray(byteSize).apply { Random().nextBytes(this) })
    }
}
