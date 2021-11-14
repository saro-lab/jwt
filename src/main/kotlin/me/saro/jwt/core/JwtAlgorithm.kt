package me.saro.jwt.core

interface JwtAlgorithm {
    fun algorithm(): String
    fun randomJwtKey(): JwtKey
    fun signature(key: JwtKey, body: String): String
    fun verify(key: JwtKey, jwt: String): Boolean
}
