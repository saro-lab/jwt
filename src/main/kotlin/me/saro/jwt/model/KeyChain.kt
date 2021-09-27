package me.saro.jwt.model

import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.security.Keys
import java.io.*
import java.security.KeyPair
import java.util.*
import javax.crypto.Cipher

data class KeyChain(
    val kid: String,
    val algorithm: SignatureAlgorithm,
    val keyPair: KeyPair
): Serializable {
    companion object {
        @JvmStatic
        fun deserialize(serialize: ByteArray): KeyChain {
            val bois = ByteArrayInputStream(serialize)
            return bois.use { os -> ObjectInputStream(os).use { it.readObject() as KeyChain } }
        }
        @JvmStatic
        fun create(kid: String, algorithm: SignatureAlgorithm) =
            KeyChain(kid, algorithm, Keys.keyPairFor(algorithm))

        @JvmStatic
        fun create(algorithm: SignatureAlgorithm) =
            create(UUID.randomUUID().toString(), algorithm)
    }

    fun encrypt(data: String): String =
        Cipher.getInstance("RSA")
            .apply { init(Cipher.ENCRYPT_MODE, keyPair.private) }
            .run { Base64.getEncoder().encodeToString(doFinal(data.toByteArray())) }

    fun decrypt(enc: String): String =
        Cipher.getInstance("RSA")
            .apply { init(Cipher.DECRYPT_MODE, keyPair.public) }
            .run { String(doFinal(Base64.getDecoder().decode(enc))) }

    fun serialize(): ByteArray {
        val baos = ByteArrayOutputStream()
        baos.use { os -> ObjectOutputStream(os).use { it.writeObject(this) } }
        return baos.toByteArray()
    }
}
