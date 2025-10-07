package me.saro.jwt.key

import me.saro.jwt.JwtAlgorithm
import me.saro.jwt.JwtUtils
import me.saro.jwt.key.hash.JwtHs256Key
import me.saro.jwt.key.hash.JwtHs384Key
import me.saro.jwt.key.hash.JwtHs512Key
import java.security.Key
import java.util.Random

interface JwtKey {
    val algorithm: JwtAlgorithm
    val key: Key
    fun toBytes(): ByteArray = key.encoded
    fun toBase64(): String = JwtUtils.encodeToBase64String(toBytes())
    fun toHex(): String = JwtUtils.encodeHex(toBytes())

    companion object {
        @JvmStatic fun parseHs256(key: ByteArray): JwtHs256Key = JwtHs256Key(key)
        @JvmStatic fun parseHs384(key: ByteArray): JwtHs384Key = JwtHs384Key(key)
        @JvmStatic fun parseHs512(key: ByteArray): JwtHs512Key = JwtHs512Key(key)
        @JvmStatic fun newHs256(byteSize: Int): JwtHs256Key = JwtHs256Key(ByteArray(byteSize).apply { Random().nextBytes(this) })
        @JvmStatic fun newHs384(byteSize: Int): JwtHs384Key = JwtHs384Key(ByteArray(byteSize).apply { Random().nextBytes(this) })
        @JvmStatic fun newHs512(byteSize: Int): JwtHs512Key = JwtHs512Key(ByteArray(byteSize).apply { Random().nextBytes(this) })
    }
}
