package me.saro.jwt.core

import java.util.*

interface JwtKey {
    companion object {
        private val EN_BASE64 = Base64.getUrlEncoder().withoutPadding()
        private val DE_BASE64 = Base64.getUrlDecoder()
    }

    fun toByte(): ByteArray
    fun toJwtKey(bytes: ByteArray): JwtKey

    fun toBase64(): String =
        EN_BASE64.encodeToString(toByte())

    fun base64ToJwtKey(base64: String): JwtKey =
        toJwtKey(DE_BASE64.decode(base64))
}
