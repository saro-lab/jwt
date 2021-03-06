package me.saro.jwt.core

import me.saro.jwt.exception.JwtException
import me.saro.jwt.exception.JwtExceptionCode
import java.time.OffsetDateTime
import java.util.*

class JwtClaims constructor(
    private val claims: MutableMap<String, Any>
) {
    companion object {
        @JvmStatic
        fun create(): JwtClaims {
            return JwtClaims(mutableMapOf())
        }
    }

    fun claim(key: String, value: Any): JwtClaims {
        claims[key] = value
        return this
    }
    fun claim(key: String): Any? = claims[key]
    fun claimLong(key: String): Long? {
        val v = claims[key]
            ?: return null
        return when (v) {
            is Int -> v.toLong()
            is Long -> v
            is String -> v.toLong()
            else -> v.toString().toLong()
        }
    }

    fun issuer() = claim("iss")
    fun issuer(value: Any) = claim("iss", value)

    fun subject() = claim("sub") as String?
    fun subject(value: String) = claim("sub", value)

    fun audience() = claim("aud") as String?
    fun audience(value: String) = claim("aud", value)

    fun id() = claim("jti") as String?
    fun id(value: String) = claim("jti", value)

    fun notBefore() = claimLong("nbf")?.let { Date(1000L * it) }
    fun notBefore(date: Date) = claim("nbf", date.time / 1000L)
    fun notBefore(date: OffsetDateTime) = claim("nbf", date.toEpochSecond())

    fun issuedAt() = claimLong("iat")?.let { Date(1000L * it) }
    fun issuedAt(date: Date) = claim("iat", date.time / 1000L)
    fun issuedAt(date: OffsetDateTime) = claim("iat", date.toEpochSecond())

    fun expire(): Date? = claimLong("exp")?.let { Date(1000L * it) }
    fun expire(date: Date) = claim("exp", date.time / 1000L)
    fun expire(date: OffsetDateTime) = claim("exp", date.toEpochSecond())

    override fun toString(): String = JwtUtils.toJsonString(claims)

    fun toMap(): Map<String, Any> = claims.toMutableMap()

    @Throws(JwtException::class)
    fun assertExpire() {
        if (expire() != null && expire()!!.before(Date())) {
            throw JwtException(JwtExceptionCode.DATE_EXPIRED)
        }
    }

    @Throws(JwtException::class)
    fun assertNotBefore() {
        if (notBefore() != null && notBefore()!!.after(Date())) {
            throw JwtException(JwtExceptionCode.DATE_EXPIRED)
        }
    }

    fun assert() {
        assertExpire()
        assertNotBefore()
    }
}
