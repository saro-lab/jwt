package me.saro.jwt.old.util

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import me.saro.jwt.old.tbd.Jwt
import me.saro.jwt.old.JwtException
import java.util.*

class DecodeJwt {
    companion object {
        private val base64Decoder = Base64.getUrlDecoder()
        private val objectMapper = jacksonObjectMapper()
        private val typeMap = object: TypeReference<Map<String, Any>>(){}

        fun decode(jwt: String): Jwt {
            val firstPoint = jwt.indexOf('.')
            val lastPoint = jwt.lastIndexOf('.')

            if (firstPoint == -1 || firstPoint == lastPoint) {
                throw JwtException("there is not jwt format: $jwt")
            }

            val body = jwt.substring(0, lastPoint)
            val sign = jwt.substring(lastPoint + 1)

            val headerString = try {
                String(base64Decoder.decode(body.substring(0, firstPoint)))
            } catch (e: Exception) { throw JwtException("jwt header base64 decoding error: $jwt") }
            val payloadString = try {
                String(base64Decoder.decode(body.substring(firstPoint + 1)))
            } catch (e: Exception) { throw JwtException("jwt body base64 decoding error: $jwt") }

            val header = try {
                objectMapper.readValue(headerString, typeMap)
            } catch (e: Exception) { throw JwtException("jwt header json parse error: $headerString\n$jwt") }
            val payload = try {
                objectMapper.readValue(payloadString, typeMap)
            } catch (e: Exception) { throw JwtException("jwt body json parse error: $payloadString\n$jwt") }

            return Jwt(body = body, sign = sign, header = header, payload = payload)
        }
    }
}