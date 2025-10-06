package me.saro.jwt.key

import me.saro.jwt.JwtAlgorithm
import me.saro.jwt.exception.JwtIllegalArgumentException
import java.util.Random
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class JwtHashKey private constructor(
    override val algorithm: JwtAlgorithm,
    override val key: SecretKeySpec,
): JwtSignatureKey, JwtVerifyKey {

    override fun createSignature(body: ByteArray): ByteArray {
        val mac: Mac = Mac.getInstance(key.algorithm)
        mac.init(key)
        return mac.doFinal(body)
    }

    override fun verify(body: ByteArray, signature: ByteArray): Boolean =
        body.isNotEmpty() && signature.contentEquals(createSignature(body))

    companion object {
        @JvmStatic
        fun create(algorithm: JwtAlgorithm, key: ByteArray): JwtHashKey =
            JwtHashKey(algorithm, SecretKeySpec(key, getSecretKeySpecAlgorithm(algorithm)))

        @JvmStatic
        fun createByTextKey(algorithm: JwtAlgorithm, key: ByteArray): JwtHashKey =
            create(algorithm, key)

        @JvmStatic
        fun genRandomKey(algorithm: JwtAlgorithm, byteSize: Int): JwtHashKey =
            create(algorithm, ByteArray(byteSize).apply { Random().nextBytes(this) })

        @JvmStatic
        fun getSecretKeySpecAlgorithm(algorithm: JwtAlgorithm): String =
            when (algorithm) {
                JwtAlgorithm.HS256 -> "HmacSHA256"
                JwtAlgorithm.HS384 -> "HmacSHA384"
                JwtAlgorithm.HS512 -> "HmacSHA512"
                else -> throw JwtIllegalArgumentException("$algorithm does not support the JWT hash algorithm.\nuse HS algorithm")
            }
    }
}