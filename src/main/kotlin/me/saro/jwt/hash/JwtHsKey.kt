package me.saro.jwt.hash

import me.saro.jwt.JwtKey
import me.saro.jwt.JwtUtils
import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode
import javax.crypto.spec.SecretKeySpec

class JwtHsKey(
    override val algorithm: JwtHsAlgorithm,
    private val secret: SecretKeySpec,
): JwtKey() {
    private val secretBase64: String get() = JwtUtils.encodeBase64String(secret.encoded)

    override fun toMap(): Map<String, String> = toMap(
        "key" to secretBase64,
    )

    override fun signature(body: ByteArray): ByteArray = try {
        val mac = algorithm.getMac().apply { init(secret) }
        JwtUtils.encodeToBase64UrlWop(mac.doFinal(body))
    } catch (e: Exception) {
        throw JwtException(JwtExceptionCode.PARSE_ERROR)
    }

    override fun verifySignature(body: ByteArray, signature: ByteArray): Boolean = try {
        signature.contentEquals(signature(body))
    } catch (_: Exception) {
        false
    }

}
