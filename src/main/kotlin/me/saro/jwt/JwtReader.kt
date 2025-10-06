package me.saro.jwt

import me.saro.jwt.JwtUtils.Companion.decodeBase64Url
import me.saro.jwt.JwtUtils.Companion.readMap
import me.saro.jwt.JwtUtils.Companion.readTextMap
import me.saro.jwt.exception.JwtParseException
import me.saro.jwt.old.exception.JwtException
import me.saro.jwt.old.exception.JwtExceptionCode
import java.util.Date

open class JwtReader internal constructor(
    val algorithm: JwtAlgorithm,
    val header: Map<String, String>,
    val payload: Map<String, Any>,
    val jwtByte: ByteArray,
    firstDot: Int,
    lastDot: Int,
) {
    val kid: String? get() = header["kid"]

    val jwtBody: ByteArray = jwtByte.copyOfRange(0, lastDot)
    val jwtSignature: ByteArray = jwtByte.copyOfRange(lastDot + 1, jwtByte.size)

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

    companion object {
        private const val DOT_BYTE: Byte = '.'.code.toByte()
        private const val DOT_INT: Int = '.'.code
        private val REGEX_TRUE: Regex = Regex("true|yes|y|on|1|o", RegexOption.IGNORE_CASE)
        private val REGEX_FALSE: Regex = Regex("false|no|n|not|off|0|x", RegexOption.IGNORE_CASE)

        private fun parsePair(jwt: String): Pair<JwtReader?, String?> {
            val jwtByte: ByteArray = jwt.toByteArray()
            val firstDot: Int = jwtByte.indexOf(DOT_BYTE)
            val lastDot: Int = jwtByte.lastIndexOf(DOT_BYTE)

            // firstDot must be not -1
            // lastDot must be not -1 and firstDot must be less than lastDot
            if (firstDot == lastDot) {
                return Pair(null, null)
            }

            val header: Map<String, String> = try {
                readTextMap(decodeBase64Url(jwtByte.copyOfRange(0, firstDot)))
            } catch (e: Exception) {
                return Pair(null, "$jwt invalid jwt header")
            }

            val payload: Map<String, Any> = try {
                readMap(decodeBase64Url(jwtByte.copyOfRange(firstDot + 1, lastDot)));
            } catch (e: Exception) {
                return Pair(null, "$jwt invalid jwt payload")
            }

            val alg: String = header["alg"]
                ?: return Pair(null, "$jwt missing jwt algorithm")

            val algorithm: JwtAlgorithm = try {
                JwtAlgorithm.valueOf(alg)
            } catch (e: IllegalArgumentException) {
                return Pair(null, "$jwt not support $alg jwt algorithm")
            }

            return Pair(JwtReader(algorithm, header, payload, jwtByte, firstDot, lastDot), null)
        }

        @JvmStatic
        fun parseOrNull(jwt: String): JwtReader? = parsePair(jwt).first

        @JvmStatic
        fun parseOrThrow(jwt: String): JwtReader {
            val pair = parsePair(jwt)
            if (pair.first != null) {
                return pair.first!!
            } else {
                throw JwtParseException(pair.second?: "$jwt invalid jwt format")
            }
        }
    }
}