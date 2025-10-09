package me.saro.jwt.node

import me.saro.jwt.key.JwtSignatureKey
import me.saro.jwt.node.JwtUtils.Companion.DOT_INT
import java.io.ByteArrayOutputStream
import java.time.OffsetDateTime
import java.time.ZonedDateTime
import java.util.*

class JwtNodeBuilder(
    override val header: MutableMap<String, String> = mutableMapOf("typ" to "JWT"),
    override val payload: MutableMap<String, Any> = mutableMapOf(),
): JwtNodeReader(header, payload) {
    fun header(key: String, value: String): JwtNodeBuilder = this.apply { header[key] = value }
    fun kid(value: String): JwtNodeBuilder = this.apply { header["kid"] = value }

    fun claim(key: String, value: Any): JwtNodeBuilder = this.apply { payload[key] = value }
    fun claimTimestamp(key: String, value: Date): JwtNodeBuilder = claim(key, value.time / 1000L)
    fun claimTimestamp(key: String, value: OffsetDateTime): JwtNodeBuilder = claim(key, value.toEpochSecond())
    fun claimTimestamp(key: String, value: ZonedDateTime): JwtNodeBuilder = claim(key, value.toEpochSecond())

    fun issuer(value: Any): JwtNodeBuilder = claim("iss", value)

    fun subject(value: String): JwtNodeBuilder = claim("sub", value)

    fun audience(value: String): JwtNodeBuilder = claim("aud", value)

    fun id(value: String): JwtNodeBuilder = claim("jti", value)

    fun notBefore(epochSecond: Long): JwtNodeBuilder = claim("nbf", epochSecond)
    fun notBefore(date: Date): JwtNodeBuilder = notBefore(date.time / 1000L)
    fun notBefore(date: OffsetDateTime): JwtNodeBuilder = notBefore(date.toEpochSecond())
    fun notBefore(date: ZonedDateTime): JwtNodeBuilder = notBefore(date.toEpochSecond())

    fun issuedAt(epochSecond: Long): JwtNodeBuilder = claim("iat", epochSecond)
    fun issuedAt(date: Date): JwtNodeBuilder = issuedAt(date.time / 1000L)
    fun issuedAt(date: OffsetDateTime): JwtNodeBuilder = issuedAt(date.toEpochSecond())
    fun issuedAt(date: ZonedDateTime): JwtNodeBuilder = issuedAt(date.toEpochSecond())

    fun expire(epochSecond: Long): JwtNodeBuilder = claim("exp", epochSecond)
    fun expire(date: Date): JwtNodeBuilder = expire(date.time / 1000L)
    fun expire(date: OffsetDateTime): JwtNodeBuilder = expire(date.toEpochSecond())
    fun expire(date: ZonedDateTime): JwtNodeBuilder = expire(date.toEpochSecond())

    fun build(key: JwtSignatureKey): String {
        val jwt = ByteArrayOutputStream(2000)
        jwt.write(JwtUtils.Companion.encodeToBase64UrlWop(JwtUtils.Companion.writeValueAsBytes(header)))
        jwt.write(DOT_INT)
        jwt.write(JwtUtils.Companion.encodeToBase64UrlWop(JwtUtils.Companion.writeValueAsBytes(payload)))

        val signature = key.createSignature(jwt.toByteArray())
        jwt.write(DOT_INT)
        jwt.write(signature)

        return String(jwt.toByteArray())
    }

    override fun toString(): String {
        return "$header.$payload"
    }
}
