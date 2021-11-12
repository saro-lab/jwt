package me.saro.jwt.old.key

import me.saro.jwt.old.JwtException

interface JwtAlgorithm {
    fun algorithm(): String
    fun signature(body: String): String
    @Throws(JwtException::class)
    fun verify(body: String, sign: String): Boolean
}
