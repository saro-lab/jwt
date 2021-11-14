package me.saro.jwt

class JwtException(override val message: String): SecurityException(message)