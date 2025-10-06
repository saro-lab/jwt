package me.saro.jwt.exception

class JwtIllegalArgumentException(
    override val message: String,
): IllegalArgumentException(message), JwtException {
}