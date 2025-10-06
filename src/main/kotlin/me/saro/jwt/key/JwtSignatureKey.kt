package me.saro.jwt.key

interface JwtSignatureKey: JwtKey {
    fun createSignature(body: ByteArray): ByteArray
}