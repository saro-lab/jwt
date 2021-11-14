package me.saro.jwt.alg.es

import me.saro.jwt.core.JwtKey
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec

class JwtAlgorithmEs256: JwtAlgorithmEs() {
    override fun getSignature(): Signature =
        Signature.getInstance("SHA256withECDSAinP1363Format")

    override fun algorithm(): String =
        "ES256"

    override fun randomJwtKey(): JwtKey =
        JwtKeyEs(
            KeyPairGenerator.getInstance("EC")
                .apply { initialize(ECGenParameterSpec("secp256r1")) }
                .genKeyPair()
        )
}