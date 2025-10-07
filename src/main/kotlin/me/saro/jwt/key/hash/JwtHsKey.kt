package me.saro.jwt.key.hash

import me.saro.jwt.key.JwtSignatureKey
import me.saro.jwt.key.JwtVerifyKey
import javax.crypto.Mac

abstract class JwtHsKey(): JwtSignatureKey, JwtVerifyKey {
    override fun createSignature(body: ByteArray): ByteArray {
        val mac: Mac = Mac.getInstance(key.algorithm)
        mac.init(key)
        return mac.doFinal(body)
    }

    override fun verify(body: ByteArray, signature: ByteArray): Boolean =
        body.isNotEmpty() && signature.contentEquals(createSignature(body))
}