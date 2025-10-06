package me.saro.jwt.exception

class JwtParseException(
    override val message: String,
): IllegalArgumentException(message), JwtException {
}