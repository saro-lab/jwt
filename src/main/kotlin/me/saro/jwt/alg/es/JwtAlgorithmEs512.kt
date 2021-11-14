package me.saro.jwt.alg.es

import java.security.Signature
import java.security.spec.ECGenParameterSpec

class JwtAlgorithmEs512: JwtAlgorithmEs() {
    companion object {
        private val ecGenParameterSpec = ECGenParameterSpec("secp521r1")
        private val signature = Signature.getInstance("SHA512withECDSAinP1363Format")
    }

    override fun algorithm(): String = "ES384"
    override fun getECGenParameterSpec(): ECGenParameterSpec = ecGenParameterSpec
    override fun getSignature(): Signature = signature
}