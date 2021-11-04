package me.saro.jwt.key.es

import me.saro.jwt.key.JwtKey
import java.security.KeyPair
import java.security.Signature
import java.util.*

class JwtKeyEs(
    protected open val keyPair: KeyPair
): JwtKey {
    companion object {
        private val EN_BASE64 = Base64.getUrlEncoder().withoutPadding()
        private val DE_BASE64 = Base64.getUrlDecoder()
    }

    abstract fun getSignature(): Signature

    override fun signature(body: String): String {
        val signature = getSignature()
        signature.initSign(keyPair.private)
        signature.update(body.toByteArray())
        return EN_BASE64.encodeToString(signature.sign())
    }

    override fun verify(body: String, sign: String): Boolean {
        val signature = getSignature()
        signature.initVerify(keyPair.public)
        signature.update(body.toByteArray())
        return signature.verify(DE_BASE64.decode(sign))
    }
}