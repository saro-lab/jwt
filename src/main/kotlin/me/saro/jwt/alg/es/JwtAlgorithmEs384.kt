package me.saro.jwt.alg.es

import java.security.Signature
import java.security.spec.ECGenParameterSpec

class JwtAlgorithmEs384: JwtAlgorithmEs() {
    companion object {
        private val ecGenParameterSpec = ECGenParameterSpec("secp384r1")
        private val signature = Signature.getInstance("SHA384withECDSAinP1363Format")
    }

    override fun algorithm(): String = "ES384"
    override fun getECGenParameterSpec(): ECGenParameterSpec = ecGenParameterSpec
    override fun getSignature(): Signature = signature
}