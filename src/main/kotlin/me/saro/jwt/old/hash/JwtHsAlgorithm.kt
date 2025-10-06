package me.saro.jwt.old.hash

import me.saro.jwt.old.JwtAlgorithm
import me.saro.jwt.old.JwtKey
import me.saro.jwt.JwtUtils
import me.saro.jwt.JwtUtils.Companion.bind
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class JwtHsAlgorithm(
    algorithmFullNameCopy: String
): JwtAlgorithm {
    override val algorithmName: String = "HS"
    override val algorithmFullName: String = algorithmFullNameCopy
    private val keyAlgorithm: String = getKeyAlgorithm(algorithmFullNameCopy)

    fun getMac(): Mac = Mac.getInstance(keyAlgorithm)

    fun toKey(secret: ByteArray): JwtKey = JwtHsKey(this, SecretKeySpec(secret, keyAlgorithm))
    fun toKeyByBase64(base64: String): JwtKey = toKey(JwtUtils.decodeBase64(base64))
    fun toKeyByText(secret: String): JwtKey = toKey(secret.toByteArray())

    @Suppress("DEPRECATION")
    override fun parseKey(map: Map<String, String>): JwtKey =
        if (algorithmFullName == map["alg"]) {
            toKeyByBase64(map["key"] ?: throw IllegalArgumentException("key is null")).bind(map)
        } else {
            throw IllegalArgumentException("algorithm is not matched")
        }

    override fun newRandomKey(): JwtKey =
        newRandomJwtKey(32)

    fun newRandomJwtKey(minKeySize: Int, maxKeySize: Int): JwtKey {
        if (minKeySize > maxKeySize) {
            throw IllegalArgumentException("minKeySize must be less than or equal to maxKeySize")
        }
        return newRandomJwtKey(minKeySize + (Math.random() * (maxKeySize - minKeySize)).toInt())
    }

    fun newRandomJwtKey(keySize: Int): JwtKey {
        if (keySize < 1) {
            throw IllegalArgumentException("length must be greater than 0")
        }
        val bytes = ByteArray(keySize)
        SecureRandom().nextBytes(bytes)
        return toKey(bytes)
    }

    companion object {
        fun getKeyAlgorithm(algorithmFullName: String): String = when (algorithmFullName) {
            "HS256" -> "HmacSHA256"
            "HS384" -> "HmacSHA384"
            "HS512" -> "HmacSHA512"
            else -> throw IllegalArgumentException("unsupported algorithm: $algorithmFullName")
        }
    }
}
