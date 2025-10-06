package me.saro.jwt.old.keyPair

import me.saro.jwt.old.JwtKey
import java.security.KeyPair
import java.security.Signature
import java.security.spec.ECGenParameterSpec

class JwtEsAlgorithm(
    override val algorithmFullName: String
): JwtKeyPairAlgorithm<JwtEsKey> {
    override val algorithmName: String = "ES"
    override val keyAlgorithmName = "EC"
    private val signatureAlgorithm: String = getSignatureAlgorithm(algorithmFullName)
    private val genParameterSpec: ECGenParameterSpec = getGenParameterSpec(algorithmFullName)

    override fun getKeyPairSignature(): Signature = Signature.getInstance(signatureAlgorithm)

    override fun toKey(keyPair: KeyPair): JwtEsKey = JwtEsKey(this, keyPair)

    override fun newRandomKey(): JwtKey =
        getKeyPairGenerator().let {
            it.initialize(genParameterSpec)
            JwtEsKey(this, it.genKeyPair())
        }

    companion object {
        fun getSignatureAlgorithm(algorithmFullName: String): String = when (algorithmFullName) {
            "ES256" -> "SHA256withECDSAinP1363Format"
            "ES384" -> "SHA384withECDSAinP1363Format"
            "ES512" -> "SHA512withECDSAinP1363Format"
            else -> throw IllegalArgumentException("unsupported algorithm: $algorithmFullName")
        }
        fun getGenParameterSpec(algorithmFullName: String): ECGenParameterSpec = when (algorithmFullName) {
            "ES256" -> ECGenParameterSpec("secp256r1")
            "ES384" -> ECGenParameterSpec("secp384r1")
            "ES512" -> ECGenParameterSpec("secp521r1")
            else -> throw IllegalArgumentException("unsupported algorithm: $algorithmFullName")
        }
    }
}
