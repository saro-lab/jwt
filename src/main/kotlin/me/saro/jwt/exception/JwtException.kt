package me.saro.jwt.exception

class JwtException(override val message: String): SecurityException(message)