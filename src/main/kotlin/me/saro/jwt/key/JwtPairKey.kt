package me.saro.jwt.key

import me.saro.jwt.JwtAlgorithm
import me.saro.jwt.exception.JwtIllegalArgumentException
import me.saro.jwt.old.keyPair.JwtEsKey
import java.security.Key
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec

abstract class JwtPairKey(
    override val algorithm: JwtAlgorithm,
    override val key: Key,
): JwtKey {

    override fun toBytes(): ByteArray = key.encoded

    fun getSignature(): Signature =
        when (algorithm.algorithm) {
            "ES" -> Signature.getInstance("SHA${algorithm.bit}withECDSAinP1363Format")
            "RS" -> Signature.getInstance("SHA${algorithm.bit}withRSA")
            "PS" -> Signature.getInstance("RSASSA-PSS").apply { setParameter(getPSSParameterSpec(this@JwtPairKey.algorithm)) }
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
        fun getPSSParameterSpec(algorithm: JwtAlgorithm): PSSParameterSpec =
            when (algorithm) {
                JwtAlgorithm.PS256 -> PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)
                JwtAlgorithm.PS384 -> PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1)
                JwtAlgorithm.PS512 -> PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1)
                else -> throw JwtIllegalArgumentException("$algorithm does not support jwt PS algorithm")
            }

        @JvmStatic
        fun getECGenParameterSpec(algorithm: JwtAlgorithm): ECGenParameterSpec =
            when (algorithm) {
                JwtAlgorithm.ES256 -> ECGenParameterSpec("secp256r1")
                JwtAlgorithm.ES384 -> ECGenParameterSpec("secp384r1")
                JwtAlgorithm.ES512 -> ECGenParameterSpec("secp521r1")
                else -> throw JwtIllegalArgumentException("$algorithm does not support jwt PS algorithm")
            }

        @JvmStatic
        fun generateRsKeyPair(algorithm: JwtAlgorithm, bit: Int): JwtKeyPair {
            val kg: KeyPairGenerator = KeyPairGenerator.getInstance("RSA")
            kg.initialize(bit)
            return toJwtKeyPair(algorithm, kg.genKeyPair())
        }

        @JvmStatic
        fun generatePsKeyPair(algorithm: JwtAlgorithm, bit: Int): JwtKeyPair {
            val kg: KeyPairGenerator = KeyPairGenerator.getInstance("RSA")
            kg.initialize(bit)
            return toJwtKeyPair(algorithm, kg.genKeyPair())
        }

        @JvmStatic
        fun generateEsKeyPair(algorithm: JwtAlgorithm): JwtKeyPair {
            val kg: KeyPairGenerator = KeyPairGenerator.getInstance("EC")
            when (algorithm) {
                JwtAlgorithm.ES256 -> kg.initialize(ECGenParameterSpec("secp256r1"))
                JwtAlgorithm.ES384 -> kg.initialize(ECGenParameterSpec("secp384r1"))
                JwtAlgorithm.ES512 -> kg.initialize(ECGenParameterSpec("secp521r1"))
                else -> throw JwtIllegalArgumentException("$algorithm does not support jwt ES algorithm")
            }
            return toJwtKeyPair(algorithm, kg.genKeyPair())
        }

        @JvmStatic
        fun generateKeyPair(algorithm: JwtAlgorithm, bit: Int): JwtKeyPair {
            val kg1: KeyPairGenerator = when(algorithm.algorithm) {
                "ES" -> {
                    KeyPairGenerator.getInstance("EC")
                        .apply {  }
                }
                "RS", "PS" -> KeyPairGenerator.getInstance("RSA")
                else -> throw JwtIllegalArgumentException("$algorithm does not support key generator")
            }
            when (algorithm) {
                JwtAlgorithm.ES256 -> kg.initialize(ECGenParameterSpec("secp256r1"))
                JwtAlgorithm.ES384 -> kg.initialize(ECGenParameterSpec("secp384r1"))
                JwtAlgorithm.ES512 -> kg.initialize(ECGenParameterSpec("secp521r1"))
                else -> throw JwtIllegalArgumentException("$algorithm does not support jwt ES algorithm")
            }
            val pair: KeyPair = kg.genKeyPair()
            return JwtKeyPair(
                JwtPairPublicKey(algorithm, pair.public),
                JwtPairPrivateKey(algorithm, pair.private),
            )
        }

        private fun checkSecureKeySize(algorithm: JwtAlgorithm, bit: Int) {

        }

        private fun getKeyPairGenerator(algorithm: JwtAlgorithm): KeyPairGenerator = when(algorithm.algorithm) {
            "ES" -> KeyPairGenerator.getInstance("EC")
            "RS", "PS" -> KeyPairGenerator.getInstance("RSA")
            else -> throw JwtIllegalArgumentException("$algorithm does not support key generator")
        }
    }
}