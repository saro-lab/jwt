package me.saro.jwt.alg.hs

import me.saro.jwt.core.JwtKey
import javax.crypto.spec.SecretKeySpec


class JwtKeyHs(
    val key: SecretKeySpec
): JwtKey {
    override fun stringify(): String =
        key.algorithm + ":" + String(key.encoded, Charsets.UTF_8)
}
