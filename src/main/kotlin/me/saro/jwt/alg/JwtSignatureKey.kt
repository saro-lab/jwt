package me.saro.jwt.alg

class JwtSignatureKey private constructor(
    val algorithm: JwtSignatureAlgorithm,
) {
    companion object {
        @JvmStatic
        fun parse(base64: String) {

        }
        @JvmStatic
        fun parse(bytes: ByteArray) {

        }
        fun create(jwtSignatureAlgorithm: JwtSignatureAlgorithm): JwtSignatureKey {
            //jwtAlgorithm.name.substring(0, 2)

            return JwtSignatureKey(
                algorithm = jwtSignatureAlgorithm
            )
        }
    }
    override fun toString(): String {
        return ""
    }
}