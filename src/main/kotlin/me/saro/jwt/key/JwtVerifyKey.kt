package me.saro.jwt.key

interface JwtVerifyKey: JwtKey {
    fun verify(body: ByteArray, signature: ByteArray): Boolean

    fun verify(jwt: String): Boolean {
        val tokens: List<String> = jwt.split(".")
        return tokens.size == 3 && verify((tokens[0] + '.' + tokens[1]).toByteArray(), tokens[2].toByteArray())
    }
}
