package me.saro.jwt.old.key.es

import me.saro.jwt.old.key.JwtAlgorithm
import me.saro.jwt.old.key.JwtKeyIo
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.*

abstract class JwtKeyIoEs: JwtKeyIo {

    companion object {
        private val EN_BASE64 = Base64.getUrlEncoder().withoutPadding()
        private val DE_BASE64 = Base64.getUrlDecoder()
    }

    protected abstract fun algorithm(): String
    protected abstract fun ecGenParameterSpec(): String
    protected abstract fun signatureAlgorithm(): Signature

    override fun generate(): JwtAlgorithm =
        JwtAlgorithmEs(
            KeyPairGenerator.getInstance("EC")
                .apply { initialize(ECGenParameterSpec(ecGenParameterSpec())) }
                .genKeyPair()
        )

//    override fun export(jwtKey: JwtKeyEs): String {
//        val publicKey = EN_BASE64.encodeToString(jwtKey.keyPair.public.encoded)
//        val privateKey = EN_BASE64.encodeToString(jwtKey.keyPair.private.encoded)
//        return "${algorithm()} $publicKey $privateKey"
//    }

    override fun import(keyData: String): JwtAlgorithm {
        TODO("Not yet implemented")
    }
}