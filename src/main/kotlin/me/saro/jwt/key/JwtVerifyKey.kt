package me.saro.jwt.key

interface JwtVerifyKey: JwtKey {
    fun verify(body: ByteArray, signature: ByteArray): Boolean
}