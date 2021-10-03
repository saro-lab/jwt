package me.saro.jwt.impl

import io.jsonwebtoken.SignatureAlgorithm
import io.jsonwebtoken.security.Keys
import me.saro.jwt.KeyChain
import java.io.ByteArrayOutputStream
import java.io.ObjectOutputStream
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.util.*
import javax.crypto.Cipher

data class DefaultKeyChain(
    override val kid: String,
    override val signatureAlgorithm: SignatureAlgorithm,
    private val keyPair: KeyPair
): KeyChain {
    companion object {
        @JvmStatic
        fun create(kid: String, algorithm: SignatureAlgorithm) =
            DefaultKeyChain(kid, algorithm, Keys.keyPairFor(algorithm))

        @JvmStatic
        fun create(algorithm: SignatureAlgorithm) =
            create(UUID.randomUUID().toString(), algorithm)
    }

    override fun encrypt(data: String): String =
        Cipher.getInstance("RSA")
            .apply { init(Cipher.ENCRYPT_MODE, keyPair.private) }
            .run { Base64.getEncoder().encodeToString(doFinal(data.toByteArray())) }

    override fun decrypt(enc: String): String =
        Cipher.getInstance("RSA")
            .apply { init(Cipher.DECRYPT_MODE, keyPair.public) }
            .run { String(doFinal(Base64.getDecoder().decode(enc))) }

    override fun serialize(): ByteArray {
        val baos = ByteArrayOutputStream()
        baos.use { os -> ObjectOutputStream(os).use { it.writeObject(this) } }
        return baos.toByteArray()
    }

    override val signaturePrivateKey: PrivateKey get() = keyPair.private
    override val signaturePublicKey: PublicKey get() = keyPair.public
}
