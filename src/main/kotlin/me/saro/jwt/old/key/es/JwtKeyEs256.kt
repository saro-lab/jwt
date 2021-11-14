package me.saro.jwt.old.key.es

import me.saro.jwt.core.JwtAlgorithm
import java.security.KeyPair
import java.security.Signature


class JwtKeyEs256(
    override val keyPair: KeyPair
): JwtAlgorithmEs(keyPair) {


    override fun create(): JwtAlgorithm =
        JwtKeyEs256(create("secp256r1"))

    override fun getSignature(): Signature =algorithm
        Signature.getInstance("SHA256withECDSAinP1363Format")

    override fun algorithm(): String = "ES256"

    override fun import(bytes: ByteArray): JwtAlgorithm {
        TODO("Not yet implemented")
    }

    override fun export(): ByteArray {
        TODO("Not yet implemented")
    }
}