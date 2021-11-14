package me.saro.jwt.alg.es

import me.saro.jwt.core.JwtAlgorithm
import me.saro.jwt.core.JwtKey
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.*

abstract class JwtAlgorithmEs: JwtAlgorithm{
    companion object {
        private val EN_BASE64 = Base64.getUrlEncoder().withoutPadding()
        private val DE_BASE64 = Base64.getUrlDecoder()
    }

    abstract fun getECGenParameterSpec(): ECGenParameterSpec
    abstract fun getSignature(): Signature

    override fun signature(key: JwtKey, body: String): String {
        val signature = getSignature()
        signature.initSign((key as JwtKeyEs).keyPair.private)
        signature.update(body.toByteArray())
        return EN_BASE64.encodeToString(signature.sign())
    }

    override fun genJwtKey(): JwtKey =
        JwtKeyEs(
            KeyPairGenerator.getInstance("EC")
                .apply { initialize(getECGenParameterSpec()) }
                .genKeyPair()
        )

    override fun verify(key: JwtKey, jwt: String): Boolean {
        val signature = getSignature()
        val firstPoint = jwt.indexOf('.')
        val lastPoint = jwt.lastIndexOf('.')
        signature.initVerify((key as JwtKeyEs).keyPair.public)
        signature.update(jwt.substring(0, lastPoint).toByteArray())
        return signature.verify(DE_BASE64.decode(jwt.substring(lastPoint + 1)))
    }

    override fun toJwtKey(text: String): JwtKey =
        JwtKeyEs.parse(text)
}