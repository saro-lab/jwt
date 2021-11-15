package me.saro.jwt.core

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import me.saro.jwt.exception.JwtException
import java.lang.StringBuilder
import java.util.*

class JwtIo private constructor(
    private val header: MutableMap<String, Any>,
    private val claim: MutableMap<String, Any>
) {
    companion object {
        private val OBJECT_MAPPER = ObjectMapper()
        private val DE_BASE64_URL = Base64.getUrlDecoder()
        private val EN_BASE64_URL_WOP = Base64.getUrlEncoder().withoutPadding()
        private val TYPE_MAP = object: TypeReference<MutableMap<String, Any>>() {}

        @JvmStatic
        fun create(alg: String): JwtIo {
            val header = mutableMapOf<String, Any>("typ" to "JWT", "alg" to alg)
            val claim = mutableMapOf<String, Any>("iat" to System.currentTimeMillis() / 1000L)
            return JwtIo(header, claim)
        }

        @JvmStatic
        fun parse(jwt: String): JwtIo {
            val jwtParts = jwt.split('.')
            val header = OBJECT_MAPPER.readValue(DE_BASE64_URL.decode(jwtParts[0]), TYPE_MAP)
            val claim = OBJECT_MAPPER.readValue(DE_BASE64_URL.decode(jwtParts[1]), TYPE_MAP)

            if (header["typ"] != "JWT") {
                throw JwtException("typ must be JWT : $jwt")
            }
            if (header["alg"] == null) {
                throw JwtException("alg is required : $jwt")
            }

            norDate(jwt, header, "nbf")
            norDate(jwt, header, "iat")
            norDate(jwt, header, "exp")

            val exp = header["exp"]
            if (exp != null && (System.currentTimeMillis() / 1000L) > (exp as Long)) {
                throw JwtException("expired jwt : $jwt")
            }
            return JwtIo(header, claim)
        }

        private fun norDate(jwt: String, header: MutableMap<String, Any>, key: String) {
            var date = header[key]
            if (date != null) {
                if (date is Int) {
                    date = date.toLong() ; header["nbf"] = date
                }
                if (date !is Long) {
                    throw JwtException("nbf format error : $jwt")
                }
            }
        }
    }

    fun header(key: String, value: Any): JwtIo {
        when (key) {
            "alg" -> throw JwtException("alg(algorithm) is readonly")
            "typ" -> throw JwtException("tpy(type) is readonly")
        }
        header[key] = value
        return this
    }
    fun header(key: String): Any? = header[key]

    fun claim(key: String, value: Any): JwtIo {
        claim[key] = value
        return this
    }
    fun claim(key: String): Any? = claim[key]

    fun kid() = header("kid")
    fun kid(value: Any) = header("kid", value)

    fun issuer() = claim("iat")
    fun issuer(value: Any) = claim("iat", value)

    fun subject() = claim("sub") as String?
    fun subject(value: String) = claim("sub", value)

    fun audience() = claim("aud") as String?
    fun audience(value: String) = claim("aud", value)

    fun id() = claim("jti") as String?
    fun id(value: String) = claim("jti", value)

    fun notBefore() = claim("nbf")?.let { Date(1000L * it as Long) }
    fun notBefore(value: Date) = claim("nbf", value.time / 1000L)

    fun issuedAt() = claim("iat")?.let { Date(1000L * it as Long) }
    fun issuedAt(value: Date) = claim("iat", value.time / 1000L)

    fun expire() = claim("exp")?.let { Date(1000L * it as Long) }
    fun expire(value: Date) = claim("exp", value.time / 1000L)

    override fun toString(): String {
        return OBJECT_MAPPER.writeValueAsString(header) + " " + OBJECT_MAPPER.writeValueAsString(claim)
    }

    fun toJwtBody(): String =
        StringBuilder(200)
            .append(EN_BASE64_URL_WOP.encodeToString(OBJECT_MAPPER.writeValueAsBytes(header)))
            .append('.')
            .append(EN_BASE64_URL_WOP.encodeToString(OBJECT_MAPPER.writeValueAsBytes(claim)))
            .toString()
}
