package me.saro.jwt.node

import me.saro.jwt.key.JwtSignatureKey
import me.saro.jwt.node.JwtUtils.Companion.DOT_INT
import java.io.ByteArrayOutputStream
import java.time.OffsetDateTime
import java.time.ZonedDateTime
import java.util.*

class JwtBuilder(
    override val header: MutableMap<String, String> = mutableMapOf("typ" to "JWT"),
    override val payload: MutableMap<String, Any> = mutableMapOf(),
): JwtReaderSpec(header, payload) {
    fun header(key: String, value: String): JwtBuilder = this.apply { header[key] = value }
    fun kid(value: String): JwtBuilder = this.apply { header["kid"] = value }

    fun claim(key: String, value: Any): JwtBuilder = this.apply { payload[key] = value }
    fun claimTimestamp(key: String, value: Date): JwtBuilder = claim(key, value.time / 1000L)
    fun claimTimestamp(key: String, value: OffsetDateTime): JwtBuilder = claim(key, value.toEpochSecond())
    fun claimTimestamp(key: String, value: ZonedDateTime): JwtBuilder = claim(key, value.toEpochSecond())

    fun issuer(value: Any): JwtBuilder = claim("iss", value)

    fun subject(value: String): JwtBuilder = claim("sub", value)

    fun audience(value: String): JwtBuilder = claim("aud", value)

    fun id(value: String): JwtBuilder = claim("jti", value)

    fun notBefore(epochSecond: Long): JwtBuilder = claim("nbf", epochSecond)
    fun notBefore(date: Date): JwtBuilder = notBefore(date.time / 1000L)
    fun notBefore(date: OffsetDateTime): JwtBuilder = notBefore(date.toEpochSecond())
    fun notBefore(date: ZonedDateTime): JwtBuilder = notBefore(date.toEpochSecond())

    fun issuedAt(epochSecond: Long): JwtBuilder = claim("iat", epochSecond)
    fun issuedAt(date: Date): JwtBuilder = issuedAt(date.time / 1000L)
    fun issuedAt(date: OffsetDateTime): JwtBuilder = issuedAt(date.toEpochSecond())
    fun issuedAt(date: ZonedDateTime): JwtBuilder = issuedAt(date.toEpochSecond())

    fun expire(epochSecond: Long): JwtBuilder = claim("exp", epochSecond)
    fun expire(date: Date): JwtBuilder = expire(date.time / 1000L)
    fun expire(date: OffsetDateTime): JwtBuilder = expire(date.toEpochSecond())
    fun expire(date: ZonedDateTime): JwtBuilder = expire(date.toEpochSecond())

    fun build(key: JwtSignatureKey): String {
        header("alg", key.algorithm.name)

        val jwt = ByteArrayOutputStream(2000)
        jwt.write(JwtUtils.encodeToBase64UrlWop(JwtUtils.writeValueAsBytes(header)))
        jwt.write(DOT_INT)
        jwt.write(JwtUtils.encodeToBase64UrlWop(JwtUtils.writeValueAsBytes(payload)))

        val signature = key.createSignature(jwt.toByteArray())
        jwt.write(DOT_INT)
        jwt.write(signature)

        return String(jwt.toByteArray())
    }

    override fun toString(): String {
        return "$header.$payload"
    }
}
