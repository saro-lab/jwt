package me.saro.jwt.key.hash

import me.saro.jwt.JwtAlgorithm
import me.saro.jwt.key.JwtSignatureKey
import me.saro.jwt.key.JwtVerifyKey
import javax.crypto.spec.SecretKeySpec

class JwtHs256Key private constructor(
    override val algorithm: JwtAlgorithm,
    override val key: SecretKeySpec,
): JwtHsKey(), JwtSignatureKey, JwtVerifyKey {
    constructor(key: ByteArray): this(JwtAlgorithm.HS256, SecretKeySpec(key, "HmacSHA256"))
}