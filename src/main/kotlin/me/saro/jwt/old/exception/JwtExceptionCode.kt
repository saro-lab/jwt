package me.saro.jwt.old.exception

enum class JwtExceptionCode {
    // PARSER
    PARSE_ERROR,

    // KEY
    INVALID_SIGNATURE,
    NOT_FOUND_KEY,

    // CLAIMS
    DATE_EXPIRED,
    DATE_BEFORE,

    KEY_STORE_EXCEPTION,
}
