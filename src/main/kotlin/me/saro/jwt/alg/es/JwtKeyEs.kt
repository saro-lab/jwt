package me.saro.jwt.alg.es

import me.saro.jwt.core.JwtKey
import java.security.KeyPair
import java.time.LocalDateTime
import java.util.*


class JwtKeyEs(
    val keyPair: KeyPair
): JwtKey {
    private val createDateTime = LocalDateTime.now()

    companion object {
        private val EN_BASE64 = Base64.getEncoder()
    }

    override fun stringify(): String =
        StringBuilder(500)
            .append(EN_BASE64.encodeToString(keyPair.public.encoded))
            .append(' ')
            .append(EN_BASE64.encodeToString(keyPair.private.encoded))
            .toString()

    override fun createDateTime(): LocalDateTime =
        createDateTime
}
