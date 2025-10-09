package me.saro.jwt.key

import me.saro.jwt.exception.JwtIllegalArgumentException
import me.saro.jwt.key.JwtAlgorithm.*
import java.security.*
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
                PS256 -> PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)
                PS384 -> PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1)
                PS512 -> PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1)
                else -> throw JwtIllegalArgumentException("$algorithm does not support jwt PS algorithm")
            }

        @JvmStatic
        fun getECGenParameterSpec(algorithm: JwtAlgorithm): ECGenParameterSpec =
            when (algorithm) {
                ES256 -> ECGenParameterSpec("secp256r1")
                ES384 -> ECGenParameterSpec("secp384r1")
                ES512 -> ECGenParameterSpec("secp521r1")
                else -> throw JwtIllegalArgumentException("$algorithm does not support jwt PS algorithm")
            }

        @JvmStatic
        fun generateKeyPair(algorithm: JwtAlgorithm, bit: Int): JwtKeyPair {
            checkSecureKeySize(algorithm, bit)
            val kg: KeyPairGenerator = when(algorithm.algorithm) {
                "ES" -> KeyPairGenerator.getInstance("EC").apply { initialize(getECGenParameterSpec(algorithm)) }
                "RS", "PS" -> KeyPairGenerator.getInstance("RSA").apply { initialize(bit) }
                else -> throw JwtIllegalArgumentException("$algorithm does not support key generator")
            }
            val pair: KeyPair = kg.genKeyPair()
            return JwtKeyPair(JwtPairPublicKey(algorithm, pair.public), JwtPairPrivateKey(algorithm, pair.private))
        }

        @JvmStatic
        fun generateKeyPair(algorithm: JwtAlgorithm): JwtKeyPair {
            val bit = when (algorithm) {
                ES256, ES384, ES512 -> 0
                RS256, PS256 -> 2048
                RS384, PS384 -> 3072
                RS512, PS512 -> 4096
                else -> throw JwtIllegalArgumentException("$algorithm does not support key generator")
            }
            return generateKeyPair(algorithm, bit)
        }

        private fun checkSecureKeySize(algorithm: JwtAlgorithm, bit: Int) {
            when (algorithm.algorithm) {
                "ES" -> {
                    if (bit != 0) {
                        throw JwtIllegalArgumentException("$algorithm does not support bit, please set 0")
                    }
                }
                "RS", "PS" -> {
                    if (bit < 2048) {
                        throw JwtIllegalArgumentException("It is recommended to use a key size of at least 2048 bits.")
                    }
                }
            }
        }
    }
}