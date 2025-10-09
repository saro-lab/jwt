package me.saro.jwt.key

enum class JwtAlgorithm(
    val algorithm: String,
    val bit: Int,
    val keyType: String,
) {
    HS256("HS", 256, "HASH"),
    HS384("HS", 384, "HASH"),
    HS512("HS", 512, "HASH"),
    ES256("ES", 256, "PAIR"),
    ES384("ES", 384, "PAIR"),
    ES512("ES", 512, "PAIR"),
    RS256("RS", 256, "PAIR"),
    RS384("RS", 384, "PAIR"),
    RS512("RS", 512, "PAIR"),
    PS256("PS", 256, "PAIR"),
    PS384("PS", 384, "PAIR"),
    PS512("PS", 512, "PAIR"),
}