package me.saro.jwt.model

enum class ClaimName(val value: String) {
    issuer("iss"),
    subject("sub"),
    audience("aud"),
    id("jti")
}
