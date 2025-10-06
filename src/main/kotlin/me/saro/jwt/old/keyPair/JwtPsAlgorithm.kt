package me.saro.jwt.old.keyPair

import me.saro.jwt.old.JwtKey
import java.security.KeyPair
import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec

class JwtPsAlgorithm(
    override val algorithmFullName: String
): JwtKeyPairAlgorithm<JwtPsKey> {
    override val algorithmName: String = "PS"
    override val keyAlgorithmName = "RSA"
    private val pssParameterSpec: PSSParameterSpec = getPSSParameterSpec(algorithmFullName)

    override fun getKeyPairSignature(): Signature {
        val keyPairSignature = Signature.getInstance("RSASSA-PSS")
        keyPairSignature.setParameter(pssParameterSpec)
        return keyPairSignature
    }

    override fun toKey(keyPair: KeyPair): JwtPsKey = JwtPsKey(this, keyPair)

    override fun newRandomKey(): JwtKey =
        newRandomJwtKey(arrayOf(2048, 3072, 4096).random())

    fun newRandomJwtKey(bit: Int): JwtPsKey =
        getKeyPairGenerator().let {
            it.initialize(bit)
            JwtPsKey(this, it.genKeyPair())
        }

    companion object {
        fun getPSSParameterSpec(algorithmFullName: String): PSSParameterSpec = when (algorithmFullName) {
            "PS256" -> PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)
            "PS384" -> PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1)
            "PS512" -> PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1)
            else -> throw IllegalArgumentException("unsupported algorithm: $algorithmFullName")
        }
    }
}
