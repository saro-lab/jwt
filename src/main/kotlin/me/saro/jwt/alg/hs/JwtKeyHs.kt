package me.saro.jwt.alg.hs

import me.saro.jwt.core.JwtKey
import java.time.LocalDateTime
import javax.crypto.spec.SecretKeySpec


class JwtKeyHs(
    val key: SecretKeySpec
): JwtKey {
    private val createDateTime = LocalDateTime.now()

    override fun stringify(): String =
        key.algorithm + ":" + String(key.encoded, Charsets.UTF_8)

    override fun createDateTime(): LocalDateTime =
        createDateTime
}
