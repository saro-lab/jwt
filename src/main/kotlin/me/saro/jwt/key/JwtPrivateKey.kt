package me.saro.jwt.key

import me.saro.jwt.JwtAlgorithm
import me.saro.jwt.JwtUtils.Companion.decodeBase64
import me.saro.jwt.JwtUtils.Companion.encodeToBase64UrlWop
import me.saro.jwt.JwtUtils.Companion.normalizePem
import me.saro.jwt.exception.JwtIllegalArgumentException
import me.saro.jwt.key.pair.JwtPairKey
import java.security.Key
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

class JwtPrivateKey private constructor(
    override val algorithm: JwtAlgorithm,
    override val key: Key,
): JwtPairKey(algorithm, key), JwtSignatureKey {

    override fun createSignature(body: ByteArray): ByteArray {
        val signature: Signature = getSignature()
        signature.initSign(key as PrivateKey)
        signature.update(body)
        return encodeToBase64UrlWop(signature.sign())
    }

    companion object {
        @JvmStatic
        fun create(algorithm: JwtAlgorithm, key: ByteArray): JwtPrivateKey {
            if (algorithm.algorithm != "PUBLIC") {
                throw JwtIllegalArgumentException("$algorithm does not jwt private key algorithm")
            }
            return JwtPrivateKey(algorithm, getKeyFactory(algorithm).generatePrivate(X509EncodedKeySpec(key)))
        }

        @JvmStatic
        fun create(algorithm: JwtAlgorithm, key: String): JwtPrivateKey =
            create(algorithm, decodeBase64(normalizePem(key)))
    }
}
