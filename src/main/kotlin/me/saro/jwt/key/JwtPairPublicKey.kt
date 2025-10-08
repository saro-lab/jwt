package me.saro.jwt.key

import me.saro.jwt.JwtAlgorithm
import me.saro.jwt.Jwt.Companion.decodeBase64Url
import me.saro.jwt.exception.JwtIllegalArgumentException
import java.security.Key
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

class JwtPairPublicKey(
    override val algorithm: JwtAlgorithm,
    override val key: Key,
): JwtPairKey(algorithm, key), JwtVerifyKey {

    constructor(algorithm: JwtAlgorithm, key: ByteArray): this(algorithm, getKeyFactory(algorithm).generatePublic(X509EncodedKeySpec(key)))

    init {
        if (algorithm.keyType != "PAIR") {
            throw JwtIllegalArgumentException("$algorithm does not jwt pair key algorithm")
        }
    }

    override fun verify(body: ByteArray, signature: ByteArray): Boolean {
        val signatureInstant: Signature = getSignature()
        signatureInstant.initVerify(key as PublicKey)
        signatureInstant.update(body)
        return signatureInstant.verify(decodeBase64Url(signature))
    }
}
