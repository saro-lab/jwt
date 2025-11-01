package me.saro.jwt.node

import me.saro.jwt.exception.JwtParseException
import me.saro.jwt.node.JwtUtils.Companion.orThrows

class Jwt {
    companion object {

        @JvmStatic
        fun builder() = JwtBuilder()

        @JvmStatic
        fun builderOrNull(bodyWithoutSignature: ByteArray?): JwtBuilder? =
            JwtBuilder.parsePair(bodyWithoutSignature).first

        @JvmStatic
        fun builderOrThrow(bodyWithoutSignature: ByteArray): JwtBuilder =
            JwtBuilder.parsePair(bodyWithoutSignature)
                .orThrows { JwtParseException(it ?: "$bodyWithoutSignature invalid jwt-body format") }

        @JvmStatic
        fun builderOrNull(headerToken: ByteArray?, bodyToken: ByteArray?): JwtBuilder? =
            JwtBuilder.parsePair(headerToken, bodyToken).first

        @JvmStatic
        fun builderOrThrow(headerToken: ByteArray?, bodyToken: ByteArray?): JwtBuilder =
            JwtBuilder.parsePair(headerToken, bodyToken)
                .orThrows { JwtParseException(it ?: "$headerToken $bodyToken invalid jwt-body format") }

        @JvmStatic
        fun parseOrNull(jwt: String): JwtNode? = JwtNode.parsePair(jwt).first
        
        @JvmStatic
        fun parseOrThrow(jwt: String): JwtNode =
            JwtNode.parsePair(jwt).orThrows { JwtParseException(it ?: "$jwt invalid jwt format") }
    }
}