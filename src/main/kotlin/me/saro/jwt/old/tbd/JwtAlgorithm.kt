package me.saro.jwt.old.tbd

import me.saro.jwt.old.JwtException

enum class JwtAlgorithm {
    HS256,
    HS384,
    HS512,
    PS256,
    PS384,
    PS512,
    RS256,
    RS384,
    RS512,
    ES256,
    ES256K,
    ES384,
    ES512,
    EdDSA;

    companion object {
        @JvmStatic
        fun parse(algorithm: String?): JwtAlgorithm =
            try {
                if (algorithm == null) {
                    throw JwtException("algorithm is not exists")
                }
                valueOf(algorithm.uppercase())
            } catch (e: IllegalArgumentException) {
                throw JwtException("Does not support $algorithm algorithm")
            }
    }
}
