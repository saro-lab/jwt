package me.saro.jwt.core

interface JwtAlgorithm {
    fun algorithm(): String
    fun genJwtKey(): JwtKey
    fun signature(key: JwtKey, body: String): String
    fun verify(key: JwtKey, jwt: String): Boolean
    fun toJwtKey(text: String): JwtKey
}
