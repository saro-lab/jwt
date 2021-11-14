package me.saro.jwt.old.key.es

import me.saro.jwt.core.JwtAlgorithm
import java.security.KeyPair
import java.security.Signature
import java.util.*

abstract class JwtAlgorithmEs(
    protected open val keyPair: KeyPair
): JwtAlgorithm {
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