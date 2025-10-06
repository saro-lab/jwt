package me.saro.jwt.old.keyPair

import me.saro.jwt.old.JwtKey
import java.security.KeyPair
import java.security.Signature

class JwtRsAlgorithm(
    override val algorithmFullName: String
): JwtKeyPairAlgorithm<JwtRsKey> {
    override val algorithmName: String = "PS"
    override val keyAlgorithmName = "RSA"
    private val signatureAlgorithm: String = getSignatureAlgorithm(algorithmFullName)

    override fun getKeyPairSignature(): Signature =
        Signature.getInstance(signatureAlgorithm)

    override fun toKey(keyPair: KeyPair): JwtRsKey = JwtRsKey(this, keyPair)

    override fun newRandomKey(): JwtKey =
        newRandomJwtKey(arrayOf(2048, 3072, 4096).random())

    fun newRandomJwtKey(bit: Int): JwtRsKey =
        getKeyPairGenerator().let {
            it.initialize(bit)
            JwtRsKey(this, it.genKeyPair())
        }

    companion object {
        fun getSignatureAlgorithm(algorithmFullName: String): String = when (algorithmFullName) {
            "RS256" -> "SHA256withRSA"
            "RS384" -> "SHA384withRSA"
            "RS512" -> "SHA512withRSA"
            else -> throw IllegalArgumentException("unsupported algorithm: $algorithmFullName")
        }
    }
}
