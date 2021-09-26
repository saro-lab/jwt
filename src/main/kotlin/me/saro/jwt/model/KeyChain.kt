package me.saro.jwt.model

import java.security.KeyPair
import java.util.*
import javax.crypto.Cipher

data class KeyChain(
    val kid: Long,
    val keyPair: KeyPair
) {
    fun encrypt(data: String) =
        Cipher.getInstance("RSA")
            .apply { init(Cipher.ENCRYPT_MODE, keyPair.private) }
            .run { Base64.getEncoder().encodeToString(doFinal(data.toByteArray())) }

    fun decrypt(enc: String) =
        Cipher.getInstance("RSA")
            .apply { init(Cipher.DECRYPT_MODE, keyPair.public) }
            .run { String(doFinal(Base64.getDecoder().decode(enc))) }
}
