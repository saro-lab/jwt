package me.saro.jwt.key

import me.saro.jwt.exception.JwtIllegalArgumentException
import me.saro.jwt.node.JwtUtils
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class JwtHashKey private constructor(
    override val algorithm: JwtAlgorithm,
    override val key: SecretKeySpec,
): JwtSignatureKey, JwtVerifyKey {
    constructor(algorithm: JwtAlgorithm, key: ByteArray): this(algorithm, SecretKeySpec(key, "HmacSHA${algorithm.bit}")) {
        if (algorithm.algorithm != "HS") {
            throw JwtIllegalArgumentException("$algorithm is not HS Algorithm")
        }
    }

    override fun createSignature(body: ByteArray): ByteArray {
        val mac: Mac = Mac.getInstance(key.algorithm)
        mac.init(key)
        return JwtUtils.encodeToBase64UrlWop(mac.doFinal(body))
    }

    override fun verify(body: ByteArray, signature: ByteArray): Boolean =
        body.isNotEmpty() && signature.contentEquals(createSignature(body))
}