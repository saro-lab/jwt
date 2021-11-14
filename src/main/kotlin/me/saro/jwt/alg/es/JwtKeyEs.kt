package me.saro.jwt.alg.es

import me.saro.jwt.core.JwtKey
import java.security.KeyPair

class JwtKeyEs(
    val keyPair: KeyPair
): JwtKey {
    override fun toByte(): ByteArray {
        TODO("Not yet implemented")
    }
    override fun toJwtKey(bytes: ByteArray): JwtKey {
        TODO("Not yet implemented")
    }
}