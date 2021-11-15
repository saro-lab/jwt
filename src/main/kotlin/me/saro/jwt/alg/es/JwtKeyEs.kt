package me.saro.jwt.alg.es

import me.saro.jwt.core.JwtKey
import java.security.KeyFactory
import java.security.KeyPair
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.*


class JwtKeyEs(
    val keyPair: KeyPair
): JwtKey {
    companion object {
        private val EN_BASE64 = Base64.getEncoder()
    }

    override fun stringify(): String =
        StringBuilder(500)
            .append(EN_BASE64.encodeToString(keyPair.public.encoded))
            .append('\n')
            .append(EN_BASE64.encodeToString(keyPair.private.encoded))
            .toString()
}
