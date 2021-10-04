package me.saro.jwt.tbd

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import java.util.*

@Deprecated("this class is TBD")
class JwtObject private constructor(
    private val body: String,
    private val sign: String,
    private val header: Map<String, Object>,
    private val payload: Map<String, Object>,
) {
    companion object {
        private val base64Decoder = Base64.getDecoder()
        private val objectMapper = jacksonObjectMapper()

        fun parse(jwt: String) {
            val part = jwt.split(".")
            if (part.size != 3) {
                throw JwtException("there is not jwt format: $jwt")
            }

            var body = jwt.substring(0, jwt.lastIndexOf('.'))
            var sign = part[1]
            var header = JwtConverter.toMap(part[0])
            var payload = JwtConverter.toMap(part[1])

            println(body)
            println(sign)
            println(header)
            println(payload)
        }
    }

    fun <T> header(name: String): T? = header[name] as T?
    fun <T> claim(name: String): T? = payload[name] as T?

    val kid: String? get() = header("kid")
    val algorithm: String? get() = header("alg")
}
