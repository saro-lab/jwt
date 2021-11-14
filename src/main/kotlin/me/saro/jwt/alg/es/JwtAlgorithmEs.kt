package me.saro.jwt.alg.es

import me.saro.jwt.core.JwtAlgorithm
import me.saro.jwt.core.JwtKey
import me.saro.jwt.core.JwtObject
import me.saro.jwt.exception.JwtException
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

abstract class JwtAlgorithmEs: JwtAlgorithm{
    companion object {
        private val EN_BASE64_URL_WOP = Base64.getUrlEncoder().withoutPadding()
        private val DE_BASE64_URL = Base64.getUrlDecoder()
    }

    abstract fun getECGenParameterSpec(): ECGenParameterSpec
    abstract fun getSignature(): Signature

    override fun signature(key: JwtKey, body: String): String {
        val signature = getSignature()
        signature.initSign((key as JwtKeyEs).keyPair.private)
        signature.update(body.toByteArray())
        return EN_BASE64_URL_WOP.encodeToString(signature.sign())
    }

    override fun genJwtKey(): JwtKey =
        JwtKeyEs(
            KeyPairGenerator.getInstance("EC")
                .apply { initialize(getECGenParameterSpec()) }
                .genKeyPair()
        )

    override fun verify(key: JwtKey, jwt: String): JwtObject {
        val signature = getSignature()
        val firstPoint = jwt.indexOf('.')
        val lastPoint = jwt.lastIndexOf('.')
        if (firstPoint < lastPoint && firstPoint != -1) {
            signature.initVerify((key as JwtKeyEs).keyPair.public)
            signature.update(jwt.substring(0, lastPoint).toByteArray())
            if (signature.verify(DE_BASE64_URL.decode(jwt.substring(lastPoint + 1)))) {
                val jwtObject = JwtObject.parse(jwt)
                if (jwtObject.header("alg") != algorithm()) {
                    throw JwtException("algorithm does not matched jwt : $jwt")
                }
                return jwtObject
            }
        }
        throw JwtException("invalid jwt : $jwt")
    }

    override fun toJwtKey(text: String): JwtKey =
        JwtKeyEs.parse(text)
}