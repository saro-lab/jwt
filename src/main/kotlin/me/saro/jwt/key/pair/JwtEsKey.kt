package me.saro.jwt.key.pair

import me.saro.jwt.JwtAlgorithm
import me.saro.jwt.exception.JwtIllegalArgumentException
import me.saro.jwt.key.JwtKey
import me.saro.jwt.key.JwtPairKeySet
import java.security.Key
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec

abstract class JwtEsKey(
    override val algorithm: JwtAlgorithm,
    override val key: Key,
): JwtKey {

    override fun toBytes(): ByteArray = key.encoded

    fun getSignature(): Signature =
        when (algorithm.algorithm) {
            "ES" -> Signature.getInstance("SHA${algorithm.bit}withECDSAinP1363Format")
            "RS" -> Signature.getInstance("SHA${algorithm.bit}withRSA")
            "PS" -> {
                Signature.getInstance("RSASSA-PSS")
                    .apply {
                        when (this@JwtEsKey.algorithm) {
                            JwtAlgorithm.PS256 -> setParameter(
                                PSSParameterSpec(
                                    "SHA-256",
                                    "MGF1",
                                    MGF1ParameterSpec.SHA256,
                                    32,
                                    1
                                )
                            )
                            JwtAlgorithm.PS384 -> setParameter(
                                PSSParameterSpec(
                                    "SHA-384",
                                    "MGF1",
                                    MGF1ParameterSpec.SHA384,
                                    48,
                                    1
                                )
                            )
                            JwtAlgorithm.PS512 -> setParameter(
                                PSSParameterSpec(
                                    "SHA-512",
                                    "MGF1",
                                    MGF1ParameterSpec.SHA512,
                                    64,
                                    1
                                )
                            )
                            else -> throw JwtIllegalArgumentException("$algorithm does not support jwt algorithm")
                        }
                    }
            }
            else -> throw JwtIllegalArgumentException("$algorithm does not support jwt algorithm")
        }

    companion object {
        @JvmStatic
        fun getKeyFactory(algorithm: JwtAlgorithm): KeyFactory =
            when (algorithm.algorithm) {
                "ES" -> KeyFactory.getInstance("EC")
                "RS", "PS" -> KeyFactory.getInstance("RSA")
                else -> throw JwtIllegalArgumentException("$algorithm does not support key factory")
            }

        @JvmStatic
        fun genRandomKey(algorithm: JwtAlgorithm): JwtPairKeySet {

        }
    }
}