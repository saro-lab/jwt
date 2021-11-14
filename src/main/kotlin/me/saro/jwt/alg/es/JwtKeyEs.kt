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
        private val DE_BASE64 = Base64.getDecoder()

        @JvmStatic
        fun parse(text: String): JwtKey {
            val keyFactory = KeyFactory.getInstance("EC")
            val textKeyPair = text.split('\n')
            println(textKeyPair[0])
            println(textKeyPair[1])
            val publicKey = keyFactory.generatePublic(X509EncodedKeySpec(DE_BASE64.decode(textKeyPair[0])))
            val privateKey = keyFactory.generatePrivate(PKCS8EncodedKeySpec(DE_BASE64.decode(textKeyPair[1])))
            return JwtKeyEs(KeyPair(publicKey, privateKey))
        }
    }
    override fun stringify(): String =
        StringBuilder(500)
            .append(EN_BASE64.encodeToString(keyPair.public.encoded))
            .append('\n')
            .append(EN_BASE64.encodeToString(keyPair.private.encoded))
            .toString()
}
