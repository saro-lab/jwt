package me.saro.jwt.key

import me.saro.jwt.JwtAlgorithm
import me.saro.jwt.Jwt.Companion.encodeToBase64UrlWop
import me.saro.jwt.exception.JwtIllegalArgumentException
import java.security.Key
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

class JwtPairPrivateKey(
    override val algorithm: JwtAlgorithm,
    override val key: Key,
): JwtPairKey(algorithm, key), JwtSignatureKey {

    constructor(algorithm: JwtAlgorithm, key: ByteArray): this(algorithm, getKeyFactory(algorithm).generatePrivate(X509EncodedKeySpec(key)))

    init {
        if (algorithm.keyType != "PAIR") {
            throw JwtIllegalArgumentException("$algorithm does not jwt pair key algorithm")
        }
    }

    override fun createSignature(body: ByteArray): ByteArray {
        val signature: Signature = getSignature()
        signature.initSign(key as PrivateKey)
        signature.update(body)
        return encodeToBase64UrlWop(signature.sign())
    }
}
