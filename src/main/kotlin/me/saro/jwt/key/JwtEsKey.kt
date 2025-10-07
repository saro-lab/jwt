package me.saro.jwt.key

import me.saro.jwt.JwtAlgorithm
import me.saro.jwt.exception.JwtIllegalArgumentException
import java.security.Key
import java.security.KeyFactory
import java.security.Signature

abstract class JwtEsKey(
    override val algorithm: JwtAlgorithm,
    override val key: Key,
): JwtKey {

    override fun toBytes(): ByteArray = key.encoded

    fun getSignature(): Signature =
        when (algorithm.algorithm) {
            "ES" -> Signature.getInstance("SHA${algorithm.bit}withECDSAinP1363Format")
        }

    companion object {
        @JvmStatic
        fun getKeyFactory(algorithm: JwtAlgorithm): KeyFactory =
            when (algorithm.algorithm) {
                "ES" -> KeyFactory.getInstance("EC")
                "RS", "PS" -> KeyFactory.getInstance("RSA")
                else -> throw JwtIllegalArgumentException("$algorithm does not support key factory")
            }
    }
}