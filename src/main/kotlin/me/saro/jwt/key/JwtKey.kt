package me.saro.jwt.key

import me.saro.jwt.JwtException

interface JwtKey {
    fun algorithm(): String
    fun signature(body: String): String
    @Throws(JwtException::class)
    fun verify(body: String, sign: String): Boolean
}