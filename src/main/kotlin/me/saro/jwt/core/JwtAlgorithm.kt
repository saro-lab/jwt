package me.saro.jwt.core

interface JwtAlgorithm {
    fun algorithm(): String
    fun genJwtKey(): JwtKey
    fun signature(key: JwtKey, body: String): String
    fun verify(key: JwtKey, jwt: String, jwtIo: JwtIo): JwtIo
    fun toJwtKey(text: String): JwtKey

    fun verify(key: JwtKey, jwt: String): JwtIo =
        verify(key, jwt, JwtIo.parse(jwt))
}
