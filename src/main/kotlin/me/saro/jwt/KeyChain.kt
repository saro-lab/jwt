package me.saro.jwt

import io.jsonwebtoken.SignatureAlgorithm
import java.io.ByteArrayInputStream
import java.io.ObjectInputStream
import java.io.Serializable
import java.security.PrivateKey
import java.security.PublicKey

interface KeyChain: Serializable {

    companion object {
        @JvmStatic
        fun deserialize(serialize: ByteArray): KeyChain {
            val bois = ByteArrayInputStream(serialize)
            return bois.use { os -> ObjectInputStream(os).use { it.readObject() as KeyChain } }
        }
    }

    fun encrypt(data: String): String
    fun decrypt(enc: String): String
    fun serialize(): ByteArray

    val kid: String
    val signatureAlgorithm: SignatureAlgorithm
    val signaturePrivateKey: PrivateKey
    val signaturePublicKey: PublicKey
}
