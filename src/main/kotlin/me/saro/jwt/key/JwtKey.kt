package me.saro.jwt.key

import me.saro.jwt.JwtAlgorithm
import me.saro.jwt.JwtUtils
import java.security.Key

interface JwtKey {
    val algorithm: JwtAlgorithm
    val key: Key
    fun toBytes(): ByteArray = key.encoded
    fun toBase64(): String = JwtUtils.encodeToBase64String(toBytes())
    fun toHex(): String = JwtUtils.encodeHex(toBytes())
}
