package me.saro.jwt.node

import me.saro.jwt.exception.JwtIllegalArgumentException
import me.saro.jwt.node.JwtUtils.Companion.REGEX_FALSE
import me.saro.jwt.node.JwtUtils.Companion.REGEX_TRUE
import java.util.*

abstract class JwtNodeReader(
    open val header: Map<String, String>,
    open val payload: Map<String, Any>,
) {
    val kid: String? get() = header["kid"]

    @Suppress("UNCHECKED_CAST")
    fun <T> claim(key: String): T? = payload[key] as T?
    fun claimString(key: String): String? = payload[key]?.toString()
    fun claimBoolean(key: String): Boolean? = when (val v = payload[key]) {
        null -> null
        is Boolean -> v
        is Int -> v != 0
        is Long -> v != 0L
        else -> {
            val b: String = v.toString()
            if (b.matches(REGEX_TRUE)) {
                true
            } else if (b.matches(REGEX_FALSE)) {
                false
            } else {
                throw JwtIllegalArgumentException("claimBoolean only support ignoreCase(true|yes|y|on|1|o|false|no|n|not|off|0|x) : $b")
            }
        }
    }
    fun claimInt(key: String): Int? = when (val v = payload[key]) {
        null -> null
        is Int -> v
        is Long -> v.toInt()
        is String -> if (v.isNotBlank()) v.toInt() else null
        else -> v.toString().toInt()
    }
    fun claimLong(key: String): Long? = when (val v = payload[key]) {
        null -> null
        is Int -> v.toLong()
        is Long -> v
        is String -> if (v.isNotBlank()) v.toLong() else null
        else -> v.toString().toLong()
    }
    fun claimDateByTimestamp(key: String): Date? = when (val v = payload[key]) {
        null -> null
        is Date -> v
        else -> claimLong(key)?.let { Date(1000L * it) }
    }
    fun claimDateByEpochSecond(key: String): Long? = when (val v = payload[key]) {
        null -> null
        is Date -> v.time / 1000L
        else -> claimLong(key)
    }

    val issuer: Any? get() = claim("iss")
    val subject: String? get() = claim("sub")
    val audience: String? get() = claim("aud")
    val id: String? get() = claim("jti")
    val notBefore: Date? get() = claimDateByTimestamp("nbf")
    val notBeforeEpochSecond: Long? get() = claimDateByEpochSecond("nbf")
    val issuedAt: Date? get() = claimDateByTimestamp("iat")
    val issuedAtEpochSecond: Long? get() = claimDateByEpochSecond("iat")
    val expire: Date? get() = claimDateByTimestamp("exp")
    val expireEpochSecond: Long? get() = claimDateByEpochSecond("exp")
}
