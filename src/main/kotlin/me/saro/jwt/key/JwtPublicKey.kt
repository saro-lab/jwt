package me.saro.jwt.key

import me.saro.jwt.JwtAlgorithm
import me.saro.jwt.JwtUtils.Companion.decodeBase64
import me.saro.jwt.JwtUtils.Companion.decodeBase64Url
import me.saro.jwt.JwtUtils.Companion.normalizePem
import me.saro.jwt.exception.JwtIllegalArgumentException
import me.saro.jwt.key.pair.JwtPairKey
import java.security.Key
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

class JwtPublicKey private constructor(
    override val algorithm: JwtAlgorithm,
    override val key: Key,
): JwtPairKey(algorithm, key), JwtVerifyKey {

    override fun verify(body: ByteArray, signature: ByteArray): Boolean {
        val signatureInstant: Signature = getSignature()
        signatureInstant.initVerify(key as PublicKey)
        signatureInstant.update(body)
        return signatureInstant.verify(decodeBase64Url(signature))
    }

    companion object {
        @JvmStatic
        fun create(algorithm: JwtAlgorithm, key: ByteArray): JwtPublicKey {
            if (algorithm.algorithm != "PAIR") {
                throw JwtIllegalArgumentException("${algorithm.name} does not support jwt Pair-Key algorithm")
            }
            return JwtPublicKey(algorithm, getKeyFactory(algorithm).generatePublic(X509EncodedKeySpec(key)))
        }

        @JvmStatic
        fun create(algorithm: JwtAlgorithm, key: String): JwtPublicKey =
            create(algorithm, decodeBase64(normalizePem(key)))
    }
}
