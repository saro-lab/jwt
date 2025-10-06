package me.saro.jwt.old

import me.saro.jwt.JwtUtils
import me.saro.jwt.old.exception.JwtException
import me.saro.jwt.old.exception.JwtExceptionCode
import java.io.ByteArrayOutputStream
import java.time.OffsetDateTime
import java.time.ZonedDateTime
import java.util.*

open class JwtNode internal constructor(
    protected open val header: Map<String, String>,
    protected open val payload: Map<String, Any>,
) {
    fun header(key: String): String? = header[key]

    val kid: String? get() = header("kid")
    val type: String? get() = header("typ")
    val algorithm: String? get() = header("alg")

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
                throw JwtException(JwtExceptionCode.PARSE_ERROR, "claimBoolean only support ignoreCase(true|yes|y|on|1|o|false|no|n|not|off|0|x) : $b")
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

    fun cloneNewBuilder(key: JwtKey): Builder = Builder(key, header.toMutableMap(), payload.toMutableMap())

    override fun toString(): String {
        return "$header.$payload"
    }

    companion object {
        private const val DOT_BYTE: Byte = '.'.code.toByte()
        private const val DOT_INT: Int = '.'.code
        private val REGEX_TRUE: Regex = Regex("true|yes|y|on|1|o", RegexOption.IGNORE_CASE)
        private val REGEX_FALSE: Regex = Regex("false|no|n|not|off|0|x", RegexOption.IGNORE_CASE)

        fun parse(jwt: String?, getJwtKey: (jwtNode: JwtNode) -> JwtKey?): JwtNode {
            if (jwt.isNullOrBlank()) {
                throw JwtException(JwtExceptionCode.PARSE_ERROR, "jwt is null or blank")
            }
            val jwtByte = jwt.toByteArray()
            val firstDot = jwtByte.indexOf(DOT_BYTE)
            val lastDot = jwtByte.lastIndexOf(DOT_BYTE)
            if (firstDot == lastDot) {
                // 이 조건에 걸리는경우는 jwt가 header.payload.signature 형식이 아닌경우이다
                throw JwtException(JwtExceptionCode.PARSE_ERROR, "jwt must be header.payload.signature: $jwt")
            }
            val header: MutableMap<String, String> = try {
                JwtUtils.Companion.readTextMap(JwtUtils.Companion.decodeBase64Url(jwtByte.copyOfRange(0, firstDot)))
            } catch (e: Exception) {
                throw JwtException(JwtExceptionCode.PARSE_ERROR, "header parse error: $jwt")
            }
            val payload: MutableMap<String, Any> = try {
                JwtUtils.Companion.readMap(JwtUtils.Companion.decodeBase64Url(jwtByte.copyOfRange(firstDot + 1, lastDot)));
            } catch (e: Exception) {
                throw JwtException(JwtExceptionCode.PARSE_ERROR, "payload parse error: $jwt")
            }
            val jwtNode: JwtNode = JwtNode(header, payload)
            if (jwtNode.algorithm.isNullOrBlank()) {
                throw JwtException(JwtExceptionCode.PARSE_ERROR, "algorithm is null or blank: $jwt, $jwtNode")
            }
            jwtNode.expire?.also {
                if (it.time < System.currentTimeMillis()) {
                    throw JwtException(JwtExceptionCode.DATE_EXPIRED, "jwt is expired: $jwt, $jwtNode")
                }
            }
            jwtNode.notBefore?.also {
                if (it.time > System.currentTimeMillis()) {
                    throw JwtException(JwtExceptionCode.DATE_BEFORE, "jwt is not before: $jwt, $jwtNode")
                }
            }
            try {
                val body = jwtByte.copyOfRange(0, lastDot)
                val signature = jwtByte.copyOfRange(lastDot + 1, jwt.length)
                if (getJwtKey(jwtNode)?.verifySignature(body, signature) == true) {
                    return jwtNode
                }
            } catch (_: Exception) { }
            throw JwtException(JwtExceptionCode.INVALID_SIGNATURE, "signature verify error: $jwt, $jwtNode")
        }
    }

    class Builder(
        private val key: JwtKey,
        override val header: MutableMap<String, String> = mutableMapOf(),
        override val payload: MutableMap<String, Any> = mutableMapOf(),
    ): JwtNode(header, payload) {

        init {
            header["typ"] = "JWT"
            header["alg"] = key.algorithm.algorithmFullName
            header["kid"] = key.kid
        }

        fun header(key: String, value: String): Builder = this.apply { header[key] = value }
        fun kid(value: String): Builder = this.apply { header["kid"] = value }

        fun claim(key: String, value: Any): Builder = this.apply { payload[key] = value }
        fun claimTimestamp(key: String, value: Date): Builder = claim(key, value.time / 1000L)
        fun claimTimestamp(key: String, value: OffsetDateTime): Builder = claim(key, value.toEpochSecond())
        fun claimTimestamp(key: String, value: ZonedDateTime): Builder = claim(key, value.toEpochSecond())

        fun issuer(value: Any): Builder = claim("iss", value)

        fun subject(value: String): Builder = claim("sub", value)

        fun audience(value: String): Builder = claim("aud", value)

        fun id(value: String): Builder = claim("jti", value)

        fun notBefore(epochSecond: Long): Builder = claim("nbf", epochSecond)
        fun notBefore(date: Date): Builder = notBefore(date.time / 1000L)
        fun notBefore(date: OffsetDateTime): Builder = notBefore(date.toEpochSecond())
        fun notBefore(date: ZonedDateTime): Builder = notBefore(date.toEpochSecond())

        fun issuedAt(epochSecond: Long): Builder = claim("iat", epochSecond)
        fun issuedAt(date: Date): Builder = issuedAt(date.time / 1000L)
        fun issuedAt(date: OffsetDateTime): Builder = issuedAt(date.toEpochSecond())
        fun issuedAt(date: ZonedDateTime): Builder = issuedAt(date.toEpochSecond())

        fun expire(epochSecond: Long): Builder = claim("exp", epochSecond)
        fun expire(date: Date): Builder = expire(date.time / 1000L)
        fun expire(date: OffsetDateTime): Builder = expire(date.toEpochSecond())
        fun expire(date: ZonedDateTime): Builder = expire(date.toEpochSecond())

        fun build(): String {
            val jwt = ByteArrayOutputStream(2000)
            jwt.write(JwtUtils.Companion.encodeToBase64UrlWop(JwtUtils.Companion.writeValueAsBytes(header)))
            jwt.write(DOT_INT)
            jwt.write(JwtUtils.Companion.encodeToBase64UrlWop(JwtUtils.Companion.writeValueAsBytes(payload)))

            val signature = key.signature(jwt.toByteArray())
            jwt.write(DOT_INT)
            jwt.write(signature)

            return String(jwt.toByteArray())
        }

        override fun toString(): String {
            return "$header.$payload"
        }
    }

}
