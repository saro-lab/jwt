package me.saro.jwt.old.exception

class JwtException(val code: JwtExceptionCode, override val message: String? = code.toString()): RuntimeException(message)
