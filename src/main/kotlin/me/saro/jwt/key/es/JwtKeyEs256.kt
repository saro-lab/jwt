package me.saro.jwt.key.es

import me.saro.jwt.key.JwtKey
import java.security.KeyPair
import java.security.Signature


class JwtKeyEs256(
    override val keyPair: KeyPair
): JwtKeyEs(keyPair) {


    override fun create(): JwtKey =
        JwtKeyEs256(create("secp256r1"))

    override fun getSignature(): Signature =algorithm
        Signature.getInstance("SHA256withECDSAinP1363Format")

    override fun algorithm(): String = "ES256"

    override fun import(bytes: ByteArray): JwtKey {
        TODO("Not yet implemented")
    }

    override fun export(): ByteArray {
        TODO("Not yet implemented")
    }
}