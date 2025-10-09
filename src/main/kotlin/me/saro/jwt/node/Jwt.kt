package me.saro.jwt.node

import me.saro.jwt.exception.JwtParseException

class Jwt {
    companion object {

        @JvmStatic
        fun builder() = JwtBuilder()

        @JvmStatic
        fun parseOrNull(jwt: String): JwtNode? = JwtNode.parsePair(jwt).first
        
        @JvmStatic
        fun parseOrThrow(jwt: String): JwtNode {
            val pair = JwtNode.parsePair(jwt)
            if (pair.first != null) {
                return pair.first!!
            } else {
                throw JwtParseException(pair.second ?: "$jwt invalid jwt format")
            }
        }
    }
}